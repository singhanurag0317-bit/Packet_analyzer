"""
Track C — Dashboard Backend
FastAPI server that:
  - Bridges to the C++ DPI engine via a localhost TCP socket (JSON events).
  - Serves REST endpoints for stats, connections, blocked list, events.
  - Pushes live updates to the browser over WebSocket /ws.
  - Exports HTML and PDF reports via /api/report.
"""

from __future__ import annotations

import asyncio
import collections
import html
import json
import random
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_HTML_PATH = STATIC_DIR / "index.html"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Port the C++ engine will stream JSON events to (§4 integration contract).
ENGINE_HOST = "127.0.0.1"
ENGINE_PORT = 9000          # Dashboard listens here to accept engine pushes

# How often (seconds) to push stats to WebSocket clients.
WS_PUSH_INTERVAL = 1.0

# Ring-buffer sizes
MAX_CONNECTIONS = 200
MAX_EVENTS = 100

# Default packet size (bytes) fallback when contract-compliant app_classified events omit wire length
DEFAULT_PACKET_BYTES = 512

# Maximum frame/buffer size (64 KB) to protect against memory exhaustion from un-delimited streams
MAX_IPC_FRAME_SIZE = 64 * 1024


# ---------------------------------------------------------------------------
# In-memory state (updated by IPC bridge)
# ---------------------------------------------------------------------------

class DashboardState:
    """Thread-safe-ish state store updated by the IPC bridge coroutine."""

    def __init__(self) -> None:
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.throughput_bps: float = 0.0
        self._last_bytes: int = 0
        self._last_ts: float = time.time()
        self._event_counter: int = 0

        # app_name -> packet count
        self.app_breakdown: dict[str, int] = {}

        self.blocked_total: int = 0
        self.blocked_reasons: dict[str, int] = {}

        self.scan_alerts: int = 0
        self.syn_flood_alerts: int = 0
        self.dns_tunnel_alerts: int = 0

        # Ring buffers
        self.connections: collections.deque[dict] = collections.deque(
            maxlen=MAX_CONNECTIONS
        )
        self.events: collections.deque[dict] = collections.deque(maxlen=MAX_EVENTS)

    # ------------------------------------------------------------------
    # Ingest an event from the C++ engine (§4.2 schema) or mock generator
    # ------------------------------------------------------------------

    def ingest(self, event: Any) -> None:
        # Require dictionary before processing so malformed JSON does not raise AttributeError
        if not isinstance(event, dict):
            return

        kind = event.get("event")

        # Consume engine's aggregate byte statistics if provided (§4.3)
        if kind == "stats" or ("total_packets" in event and "total_bytes" in event):
            if "total_packets" in event:
                self.total_packets = int(event["total_packets"])
            if "total_bytes" in event:
                self.total_bytes = int(event["total_bytes"])
            if "throughput_bps" in event:
                self.throughput_bps = float(event["throughput_bps"])
            if "app_breakdown" in event and isinstance(event["app_breakdown"], dict):
                self.app_breakdown.update(event["app_breakdown"])
            if "blocked_total" in event:
                self.blocked_total = int(event["blocked_total"])
            if "blocked_reasons" in event and isinstance(event["blocked_reasons"], dict):
                self.blocked_reasons.update(event["blocked_reasons"])
            if "scan_alerts" in event:
                self.scan_alerts = int(event["scan_alerts"])
            if "syn_flood_alerts" in event:
                self.syn_flood_alerts = int(event["syn_flood_alerts"])
            if "dns_tunnel_alerts" in event:
                self.dns_tunnel_alerts = int(event["dns_tunnel_alerts"])
            return

        if kind == "app_classified":
            self.total_packets += 1
            pkt_bytes = (
                event.get("bytes")
                or event.get("length")
                or event.get("packet_len")
                or event.get("size")
            )
            if pkt_bytes is None:
                pkt_bytes = DEFAULT_PACKET_BYTES
            self.total_bytes += int(pkt_bytes)

            app = str(event.get("app") or "Unknown")
            self.app_breakdown[app] = self.app_breakdown.get(app, 0) + 1

            if event.get("blocked"):
                self.blocked_total += 1
                reason = str(event.get("reason") or "OTHER")
                self.blocked_reasons[reason] = (
                    self.blocked_reasons.get(reason, 0) + 1
                )

            self.connections.appendleft(event)

        elif kind == "anomaly":
            self._event_counter += 1
            if "id" not in event:
                event["id"] = self._event_counter

            atype = str(event.get("type", ""))
            self.events.appendleft(event)
            if atype == "PORT_SCAN":
                self.scan_alerts += 1
            elif atype == "SYN_FLOOD":
                self.syn_flood_alerts += 1
            elif atype == "DNS_TUNNEL":
                self.dns_tunnel_alerts += 1

    def stats_snapshot(self) -> dict:
        """Calculates throughput against current wall-clock time so rate drops to 0
        when traffic ceases, and returns the aggregated metrics.
        """
        now = time.time()
        elapsed = now - self._last_ts
        if elapsed >= 1.0:
            self.throughput_bps = (self.total_bytes - self._last_bytes) * 8 / elapsed
            self._last_bytes = self.total_bytes
            self._last_ts = now

        return {
            "ts": int(now),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "throughput_bps": round(self.throughput_bps, 2),
            "app_breakdown": dict(self.app_breakdown),
            "blocked_total": self.blocked_total,
            "blocked_reasons": dict(self.blocked_reasons),
            "scan_alerts": self.scan_alerts,
            "syn_flood_alerts": self.syn_flood_alerts,
            "dns_tunnel_alerts": self.dns_tunnel_alerts,
        }


state = DashboardState()


# ---------------------------------------------------------------------------
# Mock data generator (used only when C++ engine is NOT connected)
# ---------------------------------------------------------------------------

_APPS = ["Google", "YouTube", "DNS", "Netflix", "Facebook", "Unknown",
         "GitHub", "Zoom", "Cloudflare", "Spotify"]
_REASONS = ["DOMAIN", "IP", "APP", "MALICIOUS", "VPN_DETECTED"]
_ANOMALIES = ["PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"]


def _mock_event() -> dict:
    app = random.choice(_APPS)
    blocked = random.random() < 0.15
    reason = random.choice(_REASONS) if blocked else None
    return {
        "event": "app_classified",
        "ts": time.time(),
        "five_tuple": {
            "src_ip": f"10.0.0.{random.randint(1, 254)}",
            "src_port": random.randint(1024, 65535),
            "dst_ip": f"142.250.{random.randint(0, 255)}.{random.randint(0, 255)}",
            "dst_port": 443,
            "proto": "TCP",
        },
        "app": app,
        "blocked": blocked,
        "reason": reason,
        "bytes": random.randint(64, 8192),
    }


def _maybe_anomaly_event() -> dict | None:
    if random.random() < 0.05:   # 5 % chance per tick
        atype = random.choice(_ANOMALIES)
        return {
            "event": "anomaly",
            "ts": time.time(),
            "type": atype,
            "detail": {
                "src_ip": f"10.0.0.{random.randint(1, 254)}",
                "info": "simulated",
            },
        }
    return None


# ---------------------------------------------------------------------------
# IPC bridge (Dashboard accepts connections from C++ engine; falls back to mock)
# ---------------------------------------------------------------------------

_active_engine_conns: set[asyncio.StreamWriter] = set()


async def handle_engine_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handles an incoming connection from the C++ DPI engine."""
    peer = writer.get_extra_info("peername")
    print(f"[ipc] C++ engine connected from {peer}")
    _active_engine_conns.add(writer)
    buf = b""
    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_IPC_FRAME_SIZE:
                print(
                    f"[ipc] Warning: frame size limit exceeded ({len(buf)} > "
                    f"{MAX_IPC_FRAME_SIZE} bytes) from {peer}; closing connection."
                )
                break
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if line:
                    try:
                        event = json.loads(line)
                        if isinstance(event, dict):
                            state.ingest(event)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
    except (OSError, asyncio.IncompleteReadError):
        pass
    finally:
        _active_engine_conns.discard(writer)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print(f"[ipc] C++ engine disconnected from {peer}.")


async def ipc_bridge() -> None:
    """Dashboard-side TCP listener to accept engine connections (§4 topology).
    If port 9000 is occupied by an engine server, retries connecting as a client with backoff.
    """
    try:
        server = await asyncio.start_server(
            handle_engine_connection, ENGINE_HOST, ENGINE_PORT
        )
        print(f"[ipc] Dashboard listening for C++ engine on {ENGINE_HOST}:{ENGINE_PORT}")
        async with server:
            await server.serve_forever()
    except OSError:
        # Fallback if an engine is already running as a server on ENGINE_PORT
        print(f"[ipc] Port {ENGINE_PORT} in use; attempting outbound client connection...")
        while True:
            try:
                reader, writer = await asyncio.open_connection(ENGINE_HOST, ENGINE_PORT)
                await handle_engine_connection(reader, writer)
            except OSError:
                await asyncio.sleep(2.0)


async def mock_feeder() -> None:
    """Generates mock data only while disconnected from live engines (Violation 4)."""
    while True:
        await asyncio.sleep(1.0)
        if not _active_engine_conns:
            for _ in range(10):
                state.ingest(_mock_event())
            anomaly = _maybe_anomaly_event()
            if anomaly:
                state.ingest(anomaly)


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        # Idempotent removal prevents ValueError on concurrent disconnect
        self._clients.discard(ws)

    async def broadcast(self, data: dict) -> None:
        # Iterate over a snapshot list to allow safe concurrent removal
        for ws in list(self._clients):
            try:
                await ws.send_json(data)
            except Exception:
                self._clients.discard(ws)


manager = ConnectionManager()


async def ws_broadcaster() -> None:
    """Push aggregated stats to all connected WebSocket clients every second."""
    while True:
        await asyncio.sleep(WS_PUSH_INTERVAL)
        if manager._clients:
            await manager.broadcast(state.stats_snapshot())


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start background tasks
    bridge_task = asyncio.create_task(ipc_bridge())
    mock_task = asyncio.create_task(mock_feeder())
    broadcast_task = asyncio.create_task(ws_broadcaster())
    yield
    bridge_task.cancel()
    mock_task.cancel()
    broadcast_task.cancel()


app = FastAPI(title="Packet Analyzer Dashboard", lifespan=lifespan)

# Serve frontend static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/api/stats")
async def get_stats() -> dict:
    """Aggregated stats snapshot (§4.3 schema)."""
    return state.stats_snapshot()


@app.get("/api/connections")
async def get_connections() -> list[dict[str, Any]]:
    """Most recent classified connections (ring buffer)."""
    return list(state.connections)


@app.get("/api/blocked")
async def get_blocked() -> list[dict[str, Any]]:
    """Only the blocked connections."""
    return [c for c in state.connections if c.get("blocked")]


@app.get("/api/events")
async def get_events() -> list[dict[str, Any]]:
    """Recent anomaly/security events."""
    return list(state.events)


# ---------------------------------------------------------------------------
# WebSocket live endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await manager.connect(ws)
    try:
        # Send an immediate snapshot so the client doesn't wait 1 s
        await ws.send_json(state.stats_snapshot())
        while True:
            # Keep the socket alive; broadcaster handles pushes
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------

def _render_html_report() -> str:
    snap = state.stats_snapshot()
    rows = "".join(
        f"<tr><td>{html.escape(str(app))}</td><td>{count}</td></tr>"
        for app, count in sorted(
            snap["app_breakdown"].items(), key=lambda x: -x[1]
        )
    )
    blocked_rows = "".join(
        f"<tr><td>{html.escape(str(reason))}</td><td>{count}</td></tr>"
        for reason, count in snap["blocked_reasons"].items()
    )
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DPI Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; color: #222; }}
    h1 {{ color: #1a56db; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 24px; }}
    th, td {{ border: 1px solid #ccc; padding: 8px 12px; text-align: left; }}
    th {{ background: #f0f4ff; }}
    .stat {{ display: inline-block; margin: 8px 16px 8px 0;
             padding: 12px 20px; background: #f9fafb;
             border-radius: 8px; border: 1px solid #e5e7eb; }}
    .stat h3 {{ margin: 0 0 4px; font-size: 0.85rem; color: #6b7280; }}
    .stat p  {{ margin: 0; font-size: 1.5rem; font-weight: bold; color: #111; }}
  </style>
</head>
<body>
  <h1>📡 Packet Analyzer — DPI Report</h1>
  <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>

  <h2>Summary</h2>
  <div>
    <div class="stat"><h3>Total Packets</h3><p>{snap['total_packets']:,}</p></div>
    <div class="stat"><h3>Total Bytes</h3><p>{snap['total_bytes']:,}</p></div>
    <div class="stat"><h3>Throughput</h3><p>{snap['throughput_bps']:,.0f} bps</p></div>
    <div class="stat"><h3>Blocked</h3><p>{snap['blocked_total']:,}</p></div>
    <div class="stat"><h3>Port Scan Alerts</h3><p>{snap['scan_alerts']}</p></div>
    <div class="stat"><h3>SYN Flood Alerts</h3><p>{snap['syn_flood_alerts']}</p></div>
    <div class="stat"><h3>DNS Tunnel Alerts</h3><p>{snap['dns_tunnel_alerts']}</p></div>
  </div>

  <h2>Application Breakdown</h2>
  <table>
    <tr><th>Application</th><th>Packets</th></tr>
    {rows}
  </table>

  <h2>Blocked Traffic by Reason</h2>
  <table>
    <tr><th>Reason</th><th>Count</th></tr>
    {blocked_rows if blocked_rows else '<tr><td colspan="2">None</td></tr>'}
  </table>
</body>
</html>"""


@app.get("/api/report")
async def export_report(format: str = "html"):
    """
    Export a snapshot report.
    ?format=html  → HTML file download
    ?format=pdf   → PDF file download (requires reportlab)
    """
    html_content = _render_html_report()

    if format == "pdf":
        try:
            from io import BytesIO

            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

            snap = state.stats_snapshot()
            buf = BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            story.append(Paragraph("Packet Analyzer — DPI Report", styles["Title"]))
            story.append(
                Paragraph(
                    f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]
                )
            )
            story.append(Spacer(1, 12))

            story.append(Paragraph("Summary", styles["Heading2"]))
            for label, val in [
                ("Total Packets", f"{snap['total_packets']:,}"),
                ("Total Bytes", f"{snap['total_bytes']:,}"),
                ("Throughput (bps)", f"{snap['throughput_bps']:,.0f}"),
                ("Blocked Total", f"{snap['blocked_total']:,}"),
                ("Port Scan Alerts", snap["scan_alerts"]),
                ("SYN Flood Alerts", snap["syn_flood_alerts"]),
                ("DNS Tunnel Alerts", snap["dns_tunnel_alerts"]),
            ]:
                story.append(Paragraph(f"<b>{label}:</b> {val}", styles["Normal"]))

            story.append(Spacer(1, 12))
            story.append(Paragraph("Application Breakdown", styles["Heading2"]))
            for app_name, count in sorted(
                snap["app_breakdown"].items(), key=lambda x: -x[1]
            ):
                safe_app = xml_escape(str(app_name))
                story.append(
                    Paragraph(f"{safe_app}: {count} packets", styles["Normal"])
                )

            story.append(Spacer(1, 12))
            story.append(Paragraph("Blocked Traffic by Reason", styles["Heading2"]))
            for reason, count in snap["blocked_reasons"].items():
                safe_reason = xml_escape(str(reason))
                story.append(Paragraph(f"{safe_reason}: {count}", styles["Normal"]))

            doc.build(story)
            pdf_bytes = buf.getvalue()

            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": "attachment; filename=dpi_report.pdf"
                },
            )

        except ImportError:
            return Response(
                content="reportlab not installed. Run: pip install reportlab",
                status_code=500,
            )

    # Default: HTML
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=dpi_report.html"},
    )


# ---------------------------------------------------------------------------
# Root — serve the dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def root():
    with open(INDEX_HTML_PATH, encoding="utf-8") as f:
        return f.read()
