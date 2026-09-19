# Packet_analyzer — Real-Time DPI System Project Plan

**Status:** v1.2 — Track A (M0 + M1) & Track C (M4) delivered, dashboard + IPC verified
**Lead:** Naman Singh (namann5)

## Contributors

| Role | Contributor |
|---|---|
| **Lead** | Naman Singh ([@namann5](https://github.com/namann5)) |
| Track A — Capture + Rules | Naman Singh ([@namann5](https://github.com/namann5)) — delivered, see §5 |
| Track B — Security | _TBD_ |
| Track C — Dashboard | Delivered, see §7 |
**Target platform:** Cross-platform (Windows native + Linux / WSL)
**Build system:** Meson
**Baseline:** Existing C++17 DPI engine (~4,600 LOC) — PCAP replay, SNI/Host extraction, thread-safe rule engine, multi-threaded fast-path. No external deps.

---

## 1. Vision / End State

Transform the existing offline, file-replay DPI engine into a **real-time deep packet inspection system** that:

1. Captures live traffic via libpcap (no dependency on saved PCAP files)
2. Maintains a **persistent (JSON/SQLite) rules engine** with a dedicated CLI
3. Detects **security anomalies** — port scans, SYN floods, DNS tunneling
4. Matches traffic against a **public malicious-domain blocklist** (URLhaus)
5. Streams live stats to a **Web dashboard** (FastAPI + WebSocket + Chart.js) with PDF/HTML report export
6. **[Bonus]** Flags VPN/tunneled traffic via **protocol fingerprinting** + known VPN IP ranges

Reads as: **"real-time DPI system with security detection and a live monitoring dashboard."**

---

## 2. Role Assignment (decide before starting)

The plan is split so each block is independently demoable and can be handed to one person. **Track A is now delivered** (by the lead).

| Track | Owner (TBD) | Scope | Independent demo |
|---|---|---|---|
| **A — Capture + Rules** | ✅ delivered (§5) | libpcap live capture, PCAP↔live abstraction, persistent JSON rules, rules CLI, Meson build | `dpi_engine -i eth0` classes real packets; CRUD rules; survive restart |
| **B — Security** | _TBD_ | Port scan, SYN flood, DNS tunneling detectors; URLhaus blocklist; VPN fingerprinting | Feed malicious pcap → detected & blocked; VPN traffic flagged `VPN_DETECTED` |
| **C — Dashboard** | ✅ delivered (§7) | FastAPI + WebSocket + Chart.js, REST API, PDF/HTML reports, IPC bridge to C++ | Live-updating charts of blocked traffic, app breakdown, throughput; export report |

> Cross-cutting integration contract (below) must be agreed FIRST so tracks can proceed in parallel.

---

## 3. Current-State Assessment (verified)

- **Language:** C++17 (core), Python (only `generate_test_pcap.py`, `dashboard/` future)
- **Build:** Meson (`meson.build` + `meson_options.txt`) is the build system; `CMakeLists.txt` is STALE and removed from consideration
- **Reading:** `capture_source.h` abstraction — `FileCapture` (existing `pcap_reader`) + **`LiveCapture` (libpcap, Linux; Windows builds without it)**
- **Rules:** `RuleManager` — IP / App / Domain / Port, thread-safe. **Now `std::mutex`-based** (winpthreads' `shared_mutex` rwlock caused an intermittent `__builtin_abort` in release builds under concurrent readers). New **persistent JSON `RulesStore` + `dpi_cli`** CRUD lives in `rules_store.*` / `dpi_cli.cpp`
- **Concurrency:** LB → FP fast-path threads, connection tracking, thread-safe queues
- **Engine impl:** modular `include/` + `src/` (`main_dpi.cpp`) is the build target; legacy `src/main_working.cpp`, `src/main_simple.cpp`, `src/main.cpp`, `src/dpi_mt.cpp` remain as historical/desktop-only variants (not built by Meson)
- **Tests:** Meson `test()` harness — `engine_smoke` (replay 77-pkt `test_dpi.pcap` with `--block-app YouTube`) + `rules_cli_persistence`. CI runs these on **Linux, macOS, Windows (MSVC+GCC)**, plus a **Linux live-capture** job and a Python syntax-check job — all green
- **Known bugs fixed:** LoadBalancer init-order OOB (`per_fp_counts_` sized from moved-from vector); meson `disabler()` silently dropping target+tests; engine_smoke relied on CWD so it failed under `meson test`

---

## 4. Integration Contract (do this FIRST — parallel tracks depend on it)

Read as the "API" the three tracks agree on.

### 4.1 Technology stack decisions
- **Build:** Meson, `meson_options.txt` for platform toggles (Linux libpcap vs Windows Npcap)
- **IPC:** C++ engine → Python dashboard over a **localhost WebSocket/JSON socket** (simple, cross-platform, no shared-memory quirks). Fallback: named pipe.
- **JSON rules:** `nlohmann/json` (single-header, easy vendoring) or stdlib-light hand-rolled writer. Recommend **nlohmann/json**.
- **SQLite:** `sqlite3` C API (bundle sqlite3.c amalgamation — zero-install, cross-platform).
- **Dashboard deps:** FastAPI + `uvicorn` + `websockets`, frontend Chart.js (CDN), report via `reportlab` (PDF) + plain HTML.

### 4.2 Event / stats JSON schema (shared)
Every packet → classification → emits zero or more events; aggregated counters feed the dashboard.

```jsonc
// Per-connection classified event (pushed to dashboard IP socket)
{
  "event": "app_classified",
  "ts": 1710000000.123,
  "five_tuple": {"src_ip":"10.0.0.5","src_port":53124,
                  "dst_ip":"142.250.72.14","dst_port":443,"proto":"TCP"},
  "app": "Google",
  "blocked": false,
  "reason": null            // or "IP"/"PORT"/"APP"/"DOMAIN"/"MALICIOUS"/"VPN_DETECTED"
}

// Security detector trigger
{
  "event": "anomaly",
  "ts": 1710000000.200,
  "type": "PORT_SCAN" | "SYN_FLOOD" | "DNS_TUNNEL",
  "detail": {"src_ip":"10.0.0.66","target":"10.0.0.1","ports_seen":42}
}
```

### 4.3 Aggregated stats schema (dashboard poll / push)
```jsonc
{
  "ts": 1710000000,
  "total_packets": 123456,
  "total_bytes": 88239921,
  "throughput_bps": 88412,
  "app_breakdown": {"Google": 40, "YouTube": 25, "DNS": 10, "Unknown": 25},
  "blocked_total": 332,
  "blocked_reasons": {"DOMAIN": 200, "MALICIOUS": 100, "VPN_DETECTED": 32},
  "scan_alerts": 4, "syn_flood_alerts": 1, "dns_tunnel_alerts": 2
}
```

### 4.4 Interface boundaries (who owns what)
- **A owns:** `pcap_reader.*` → `live_capture.*`; `rule_manager.*` → `rules_store.*` (JSON+SQLite); `dpi_cli.*`; `meson.build`
- **B owns:** `anomaly_detector.*`, `blocklist.*`, `vpn_detector.*` (hooks inserted into FP classification path)
- **C owns:** everything under `dashboard/` (Python + static frontend), the IPC server, report export
- **Shared:** `events.h` (schema constants), `stats.h` (aggregator)

---

## 5. Track A — Live Capture + Persistent Rules Engine

**Status: ✅ DELIVERED (M1 gate met)** — live capture classifies real packets; rules CRUD persists across restarts; CI green.

### 5.1 Live capture (libpcap) ✅
- `include/capture_source.h` + `src/capture_source.cpp`
- Abstraction: `CaptureSource` interface with two impls — `FileCapture` (existing reader) and `LiveCapture` (libpcap)
- `LiveCapture::open(interface, snaplen=65535, promisc, timeout_ms)`; `-l` lists interfaces
- Callback style: the SAME per-packet extract path handles file and live packets (`CapturePacket` mirrors `RawPacket`)
- **Platform:** Linux → `pcap_open_live`+`pcap_next_ex`; Windows → optional Npcap link. Meson toggles via `live_capture` option + `HAVE_LIBPCAP`
- CLI: `dpi_engine -i eth0 [-o live.pcap] [--rules rules.json]`; Ctrl+C graceful stop

### 5.2 Persistent rules (JSON) ✅ — SQLite deferred to backlog
- Upgrade `RuleManager` backend:
  - Implemented: **JSON store** (`rules_store.*`) — portable, zero-install, survives restart
  - Backlog: **SQLite** table `rules(id, type, value, enabled, created_at, note)` (was §5.2 primary; JSON chosen first for zero-dependency portability)
- **CLI** `dpi_cli` (`src/dpi_cli.cpp`), commands all implemented:
  - `dpi_cli add-rule --type ip|app|domain|port --value 1.2.3.4 [--note "..." ] [--disabled]`
  - `dpi_cli del-rule <id>`
  - `dpi_cli list-rules [--type domain]`
  - `dpi_cli import rules.json` / `export out.json`
  - `dpi_cli enable <id>` / `disable <id>` / `clear`
  - `--store <file>` for all (default `rules.json`)
- Engine loads `--rules rules.json` at startup; `RulesStore::applyTo(RuleManager&)` maps AppType names → enum

### 5.3 Deliverables / demo — ✅ VERIFIED
- `meson setup build && meson compile -C build`
- `dpi_engine -i <interface> --rules rules.json` → live classification
- CLI rule CRUD that survives a restart (persistence proven by `rules_cli_persistence` test)

---

## 6. Track B — Anomaly Detection + Blocklist + VPN

### 6.1 Port scan detector (`anomaly_detector.*`)
- Sliding time window (e.g., 5 s); per `src_ip` count **unique destination ports**
- Threshold breach (e.g., > 15 distinct ports to one target in window) → `PORT_SCAN` event
- Lightweight map, LRU eviction; runs inside or beside fast-path

### 6.2 SYN flood detector
- Per `dst_ip` count **SYN-only** packets (no ACK, no payload) in window
- Rate above threshold (e.g., > 500 SYN/s) → `SYN_FLOOD` event

### 6.3 DNS tunneling heuristics
- For each DNS query (`DNSExtractor` output): compute
  - subdomain depth (labels − 1)
  - total query name length and per-label length
  - Shannon entropy of the leftmost label
- Heuristic: depth ≥ 4 AND (long label ~> 20 chars OR entropy ~> 4.0) → `DNS_TUNNEL`
- Track per `(src_ip, query pattern)` to suppress noise, report unique tunnel domains

### 6.4 Malicious domain blocklist (URLhaus)
- Download `https://urlhaus.abuse.ch/downloads/text/` (URLhaus online blocklist) on-demand
- Parse into an in-memory **trie / set** of domains; optional refresh interval
- Match against extracted DNS queries and TLS SNIs
- On match → block, reason = `MALICIOUS`, emit event (feeds dashboard "blocked by blocklist")
- Fallback offline: ship a small bundled sample list if no network

### 6.5 [Bonus] VPN / tunneled traffic detection (`vpn_detector.*`)
Protocol fingerprinting:
- **WireGuard:** UDP src/dst port 51820 + 32-byte initial packet pattern (type 1 message, fixed reserved bytes)
- **OpenVPN:** TCP or UDP port 1194 + characteristic packet opcodes (`P_CONTROL_HARD_RESET_CLIENT_V1` = 0x38, tls-auth HMAC)
- **IPSec:** IP protocol 50 (ESP) / 51 (AH) in `packet_parser`
- **Known VPN IP ranges:** static config/CIDR list (`vpn_ranges.json`), match `src_ip`/`dst_ip`
Match → label connection `VPN_DETECTED`; optionally blockable; surfaced in dashboard

### 6.6 Deliverables / demo
- Crafted / malicious pcap → detectors fire + auto-block; `dpi_engine` console shows alerts
- Live with URLhaus fetched → known-bad domain blocked & shown

---

## 7. Track C — Web Dashboard + Reports

**Status: ✅ DELIVERED (M4 gate met)** — WebSocket streaming, live charts, live connection inspector, REST API, and PDF/HTML report export verified.

### 7.1 Backend (FastAPI) — `dashboard/`
- `dashboard/server.py` — FastAPI app
- **IPC bridge:** connects to C++ engine socket, receives event/stats JSON (contract §4)
- **REST endpoints:**
  - `GET /api/stats` → aggregated stats
  - `GET /api/connections` → recent classified connections (ring buffer)
  - `GET /api/blocked` → blocked list w/ reasons
  - `GET /api/events` → recent anomaly/alerts
- **WebSocket:** `WS /ws` → pushes live updates (app breakdown, blocked, throughput)

### 7.2 Frontend — `dashboard/static/`
- `index.html` + `app.js` + Chart.js (CDN)
- Panels: live throughput line, app-donut, blocked-by-reason bar, alert feed, top talkers
- Updates via WebSocket; small sparkline for trend

### 7.3 Reports — export
- **HTML:** server-rendered snapshot of current stats/table (fast, offline)
- **PDF:** `reportlab` — same content paginated
- Trigger: `GET /api/report?format=pdf|html`

### 7.4 Deliverables / demo
- Standalone demo with C++ engine run in `--export-stats` mode (no live nic) feeding fake/recorded stream
- Live: charts update in real time → export HTML/PDF report

---

## 8. Shared Timeline / Milestones

| # | Milestone | Tracks | Gate |
|---|---|---|---|
| M0 | Integration contract + Meson skeleton + build green | A, B, C | ✅ Done — `meson compile` succeeds; baseline engine still runs; 3-OS CI + live-capture job green |
| M1 | Live capture + JSON/SQLite rules + CLI | A | ✅ Done — live capture classifies; rules survive restart (JSON store; SQLite backlog) |
| M2 | Anomaly detectors + VPN fingerprint (offline data) | B | Crafted pcap triggers all 3 + VPN flag |
| M3 | URLhaus blocklist + auto-block | B | Known-bad domain blocked on live/fake stream |
| M4 | Dashboard backend + WS streaming (fake feed) | C | ✅ Done — Charts move, live connection inspector, REST & PDF/HTML reports verified |
| M5 | End-to-end: live capture → security → dashboard → report | A+B+C | Full demo |

---

## 9. Risks / Decisions to Lock

1. **Decide the engine implementation to build on** — modular (`include/`+`src/`) recommended; `dpi_mt.cpp` is self-contained and harder to extend into. **Must resolve before Track B hooks in.**
2. **libpcap on Windows** requires **Npcap** runtime; CI must install it. Linux is trivial.
3. **IPSec (protocol 50/51)** — TCP/UDP fast-path has no stream for ESP/AH payload inspection; only header flagging possible (that's enough for `VPN_DETECTED`).
4. **SQLite/JSON dependency** — bundle `sqlite3.c` + nlohmann single headers to keep zero-install ambition; flag if you prefer system packages.
5. **Dashboard wiring for demos without root/nic** — always support `--export-stats`/replay feed so a nic is not mandatory.
6. **Blocklist refresh** — offline fallback list must ship; guard against stale/too-aggressive matching.

---

## 10. Getting Started (leader checklist)

- [x] Stand up Meson skeleton (M0) — build + CI green (all OS + live capture)
- [x] Resolve engine baseline: modular `include/`+`src/` (§9.1)
- [x] Approve integration contract (§4) — schema + IPC + tech stack
- [x] Track A delivered — live capture + JSON rules CLI (M1)
- [ ] Assign B / C owners (§2)
- [ ] Unblock Track B with its demo criteria (§6.6)
- [x] Unblock Track C with its demo criteria (§7.4)
- [ ] Decide SQLite backend for rules (backlog, §5.2)
