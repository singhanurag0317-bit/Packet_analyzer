#!/usr/bin/env python3
"""
Track C — Standalone Traffic & Security Anomaly Simulator
Streams contract-compliant JSON events (§4.2 & §4.3) over TCP to the Dashboard IPC server (127.0.0.1:9000).
Enables full live UI demonstrations, testing, and verification without requiring live NIC capture or C++ builds.
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import sys
import time


APPS = [
    ("Google", 443, "TCP", 0.25),
    ("YouTube", 443, "TCP", 0.20),
    ("Netflix", 443, "TCP", 0.15),
    ("GitHub", 443, "TCP", 0.10),
    ("Spotify", 443, "TCP", 0.08),
    ("Zoom", 8801, "UDP", 0.07),
    ("DNS", 53, "UDP", 0.08),
    ("Cloudflare", 443, "TCP", 0.04),
    ("Unknown", 8080, "TCP", 0.03),
]

BLOCK_REASONS = ["DOMAIN", "APP", "IP", "MALICIOUS", "VPN_DETECTED"]
ANOMALY_TYPES = ["PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"]


def generate_packet_event() -> dict:
    # Pick app based on weight
    r = random.random()
    cumulative = 0.0
    chosen_app, dst_port, proto, _ = APPS[0]
    for app_name, port, protocol, weight in APPS:
        cumulative += weight
        if r <= cumulative:
            chosen_app = app_name
            dst_port = port
            proto = protocol
            break

    blocked = random.random() < 0.12  # ~12% blocked rate
    reason = random.choice(BLOCK_REASONS) if blocked else None

    src_host = random.randint(2, 254)
    dst_a, dst_b = random.randint(1, 200), random.randint(1, 254)
    pkt_len = random.randint(64, 1514)

    return {
        "event": "app_classified",
        "ts": round(time.time(), 3),
        "five_tuple": {
            "src_ip": f"192.168.1.{src_host}",
            "src_port": random.randint(1024, 65535),
            "dst_ip": f"{dst_a}.{dst_b}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "dst_port": dst_port,
            "proto": proto,
        },
        "app": chosen_app,
        "bytes": pkt_len,
        "blocked": blocked,
        "reason": reason,
    }


def generate_anomaly_event() -> dict:
    atype = random.choice(ANOMALY_TYPES)
    src_ip = f"192.168.1.{random.randint(50, 150)}"
    target_ip = f"10.0.0.{random.randint(1, 20)}"

    detail: dict = {"src_ip": src_ip, "target": target_ip}
    if atype == "PORT_SCAN":
        detail["ports_seen"] = random.randint(18, 120)
        detail["window_sec"] = 5
    elif atype == "SYN_FLOOD":
        detail["syn_rate_pps"] = random.randint(600, 2500)
        detail["action"] = "ALERT_EMITTED"
    elif atype == "DNS_TUNNEL":
        detail["domain"] = f"x{random.randint(100000, 999999)}.sub.tunnel-exfil.xyz"
        detail["entropy"] = round(random.uniform(4.2, 5.8), 2)

    return {
        "event": "anomaly",
        "ts": round(time.time(), 3),
        "type": atype,
        "detail": detail,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Packet Analyzer — Live Traffic & Security Feed Simulator"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard IPC host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Dashboard IPC port (default: 9000)")
    parser.add_argument("--rate", type=float, default=25.0, help="Packets per second (default: 25)")
    parser.add_argument("--anomalies", type=float, default=0.08, help="Anomaly trigger chance per sec (default: 0.08)")
    parser.add_argument("--duration", type=int, default=0, help="Duration in seconds (0 = infinite)")

    args = parser.parse_args()

    print("=" * 65)
    print("📡  PACKET ANALYZER — TRACK C FEED SIMULATOR")
    print(f"    Target Server: {args.host}:{args.port}")
    print(f"    Packet Rate:   {args.rate} pkts/sec")
    print(f"    Anomaly Rate:  {args.anomalies * 100:.1f}% per sec")
    print(f"    Duration:      {'Infinite' if args.duration == 0 else f'{args.duration}s'}")
    print("=" * 65)

    delay = 1.0 / max(1.0, args.rate)
    start_time = time.time()
    total_sent = 0
    anomalies_sent = 0

    while True:
        try:
            print(f"[+] Connecting to dashboard at {args.host}:{args.port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((args.host, args.port))
            print(f"[✓] Connected successfully! Streaming events...\n")
            break
        except ConnectionRefusedError:
            print("[-] Connection refused. Ensure dashboard server is running (uvicorn dashboard.server:app).")
            print("    Retrying in 2 seconds (Ctrl+C to abort)...")
            time.sleep(2.0)
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(0)

    try:
        last_stat_time = time.time()
        while True:
            now = time.time()
            if args.duration > 0 and (now - start_time) >= args.duration:
                print(f"\n[✓] Finished simulation duration of {args.duration}s.")
                break

            # 1. Send packet event
            pkt = generate_packet_event()
            raw_pkt = (json.dumps(pkt) + "\n").encode("utf-8")
            sock.sendall(raw_pkt)
            total_sent += 1

            # 2. Maybe send anomaly event
            if random.random() < (args.anomalies * delay):
                anomaly = generate_anomaly_event()
                raw_anomaly = (json.dumps(anomaly) + "\n").encode("utf-8")
                sock.sendall(raw_anomaly)
                anomalies_sent += 1
                print(f" [!] Injected Security Anomaly: {anomaly['type']} from {anomaly['detail'].get('src_ip')}")

            # Status heartbeat in terminal
            if now - last_stat_time >= 2.0:
                elapsed = now - start_time
                pps = total_sent / max(1.0, elapsed)
                print(f" -> Sent {total_sent:,} packets ({pps:.1f} pps) | {anomalies_sent} anomalies", end="\r")
                last_stat_time = now

            time.sleep(delay)

    except KeyboardInterrupt:
        print(f"\n\n[!] Stopped by user.")
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        print(f"\n[-] Socket disconnected: {e}")
    finally:
        sock.close()
        elapsed = round(time.time() - start_time, 2)
        print(f"[✓] Summary: {total_sent:,} packet events and {anomalies_sent} anomalies sent in {elapsed}s.")


if __name__ == "__main__":
    main()
