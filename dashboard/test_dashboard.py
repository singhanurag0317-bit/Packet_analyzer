"""
Track C — Dashboard Pytest Suite
Functional and unit tests for DashboardState, REST API endpoints, HTML/PDF report export,
IPC engine connection handling, and WebSocket push.
"""

from __future__ import annotations

import os
import sys
import pytest
import asyncio
import json

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient

from dashboard.server import (
    app,
    state,
    DashboardState,
    handle_engine_connection,
    MAX_CONNECTIONS,
    MAX_EVENTS,
    MAX_IPC_FRAME_SIZE,
)


@pytest.fixture(autouse=True)
def reset_state():
    """Reset global dashboard state before each test."""
    state.total_packets = 0
    state.total_bytes = 0
    state.throughput_bps = 0.0
    state._last_bytes = 0
    state._event_counter = 0
    state.app_breakdown.clear()
    state.blocked_total = 0
    state.blocked_reasons.clear()
    state.scan_alerts = 0
    state.syn_flood_alerts = 0
    state.dns_tunnel_alerts = 0
    state.connections.clear()
    state.events.clear()


# ============================================================================
# 1. Unit Tests for DashboardState
# ============================================================================

def test_dashboard_state_app_classified_ingest():
    s = DashboardState()
    event = {
        "event": "app_classified",
        "ts": 1710000000.0,
        "five_tuple": {
            "src_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_ip": "1.1.1.1",
            "dst_port": 443,
            "proto": "TCP",
        },
        "app": "Google",
        "bytes": 1024,
        "blocked": False,
        "reason": None,
    }

    s.ingest(event)
    assert s.total_packets == 1
    assert s.total_bytes == 1024
    assert s.app_breakdown.get("Google") == 1
    assert len(s.connections) == 1
    assert s.blocked_total == 0


def test_dashboard_state_blocked_event_ingest():
    s = DashboardState()
    event = {
        "event": "app_classified",
        "ts": 1710000000.0,
        "five_tuple": {
            "src_ip": "10.0.0.2",
            "src_port": 54321,
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "proto": "UDP",
        },
        "app": "DNS",
        "bytes": 512,
        "blocked": True,
        "reason": "DOMAIN",
    }

    s.ingest(event)
    assert s.total_packets == 1
    assert s.total_bytes == 512
    assert s.blocked_total == 1
    assert s.blocked_reasons.get("DOMAIN") == 1


def test_dashboard_state_anomaly_ingest():
    s = DashboardState()
    for anomaly in ["PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"]:
        event = {
            "event": "anomaly",
            "ts": 1710000000.0,
            "type": anomaly,
            "detail": {"src_ip": "10.0.0.66", "target": "10.0.0.1"},
        }
        s.ingest(event)

    assert s.scan_alerts == 1
    assert s.syn_flood_alerts == 1
    assert s.dns_tunnel_alerts == 1
    assert len(s.events) == 3


def test_dashboard_state_aggregate_stats_ingest():
    s = DashboardState()
    stats_payload = {
        "event": "stats",
        "total_packets": 5000,
        "total_bytes": 2000000,
        "throughput_bps": 150000.0,
        "app_breakdown": {"YouTube": 3000, "Google": 2000},
        "blocked_total": 450,
        "blocked_reasons": {"APP": 250, "DOMAIN": 200},
        "scan_alerts": 5,
        "syn_flood_alerts": 2,
        "dns_tunnel_alerts": 1,
    }

    s.ingest(stats_payload)
    assert s.total_packets == 5000
    assert s.total_bytes == 2000000
    assert s.throughput_bps == 150000.0
    assert s.app_breakdown["YouTube"] == 3000
    assert s.blocked_total == 450
    assert s.scan_alerts == 5


def test_dashboard_state_ring_buffer_limits():
    s = DashboardState()
    for i in range(MAX_CONNECTIONS + 50):
        s.ingest({
            "event": "app_classified",
            "app": f"App_{i}",
            "blocked": False,
        })
    assert len(s.connections) == MAX_CONNECTIONS

    for i in range(MAX_EVENTS + 20):
        s.ingest({
            "event": "anomaly",
            "type": "PORT_SCAN",
            "detail": {"idx": i},
        })
    assert len(s.events) == MAX_EVENTS


def test_dashboard_state_malformed_input():
    s = DashboardState()
    # Malformed / non-dict inputs should not crash
    s.ingest(None)
    s.ingest("not a dict")
    s.ingest([1, 2, 3])
    s.ingest({"event": "unknown_event_type"})
    assert s.total_packets == 0


# ============================================================================
# 2. REST API Endpoints Tests
# ============================================================================

def test_api_stats():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "Google",
        "bytes": 2048,
        "blocked": False,
    })

    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["total_packets"] == 1
    assert data["total_bytes"] == 2048
    assert "Google" in data["app_breakdown"]


def test_api_connections():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "YouTube",
        "bytes": 500,
        "blocked": False,
    })

    res = client.get("/api/connections")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["app"] == "YouTube"


def test_api_blocked():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "YouTube",
        "bytes": 500,
        "blocked": True,
        "reason": "APP",
    })

    res = client.get("/api/blocked")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["blocked"] is True


def test_api_events():
    client = TestClient(app)
    state.ingest({
        "event": "anomaly",
        "type": "SYN_FLOOD",
        "detail": {"src_ip": "10.0.0.99"},
    })

    res = client.get("/api/events")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["type"] == "SYN_FLOOD"


def test_root_endpoint():
    client = TestClient(app)
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")
    assert "PACKET ANALYZER" in res.text


# ============================================================================
# 3. Report Generation Tests (HTML and PDF)
# ============================================================================

def test_api_report_html():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "Google",
        "bytes": 1000,
        "blocked": False,
    })

    res = client.get("/api/report?format=html")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    assert "DPI Report" in res.text
    assert "Google" in res.text


def test_api_report_pdf():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "Google",
        "bytes": 1000,
        "blocked": True,
        "reason": "DOMAIN",
    })

    res = client.get("/api/report?format=pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF")


# ============================================================================
# 4. IPC Frame Stream Handling Test
# ============================================================================

def test_handle_engine_connection_stream():
    async def run_stream():
        events = [
            {"event": "app_classified", "app": "Google", "bytes": 128, "blocked": False},
            {"event": "anomaly", "type": "PORT_SCAN", "detail": {"src_ip": "1.2.3.4"}},
        ]
        raw_payload = "\n".join(json.dumps(e) for e in events).encode("utf-8") + b"\n"

        reader = asyncio.StreamReader()
        reader.feed_data(raw_payload)
        reader.feed_eof()

        class MockWriter:
            def get_extra_info(self, name):
                return ("127.0.0.1", 9000)
            def close(self):
                pass
            async def wait_closed(self):
                pass

        writer = MockWriter()
        await handle_engine_connection(reader, writer)

    asyncio.run(run_stream())
    assert state.total_packets == 1
    assert state.total_bytes == 128
    assert state.scan_alerts == 1


# ============================================================================
# 5. WebSocket Test
# ============================================================================

def test_websocket_endpoint():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "DNS",
        "bytes": 64,
        "blocked": False,
    })

    with client.websocket_connect("/ws") as websocket:
        data = websocket.receive_json()
        assert "total_packets" in data
        assert "total_bytes" in data
        assert data["total_packets"] == 1


# ============================================================================
# 6. Simulator Feed Generator Unit Tests
# ============================================================================

def test_simulate_feed_generators():
    from dashboard.simulate_feed import generate_packet_event, generate_anomaly_event

    pkt = generate_packet_event()
    assert pkt["event"] == "app_classified"
    assert "five_tuple" in pkt
    assert "src_ip" in pkt["five_tuple"]
    assert "dst_ip" in pkt["five_tuple"]
    assert "app" in pkt
    assert isinstance(pkt["bytes"], int)
    assert isinstance(pkt["blocked"], bool)

    anomaly = generate_anomaly_event()
    assert anomaly["event"] == "anomaly"
    assert anomaly["type"] in ["PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"]
    assert "detail" in anomaly
    assert "src_ip" in anomaly["detail"]

