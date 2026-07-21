#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def run(args: list[str], timeout: float = 2.0) -> tuple[int, str]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
        return completed.returncode, output
    except FileNotFoundError:
        return 127, f"{args[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, f"{args[0]} timeout"


def bgp_status(service: str, peer_ip: str, listen_port: int) -> dict[str, object]:
    service_code, service_output = run(["systemctl", "is-active", service]) if service else (1, "service not configured")
    listen_code, listen_output = run(["ss", "-lntp"])
    session_code, session_output = run(["ss", "-antp"])
    log_code, log_output = run(["journalctl", "-u", service, "-n", "120", "--no-pager"], timeout=3.0) if service else (1, "")

    listening = False
    if listen_code == 0:
        for line in listen_output.splitlines():
            if f":{listen_port}" in line:
                listening = True
                break

    established = False
    if session_code == 0:
        for line in session_output.splitlines():
            upper = line.upper()
            if "ESTAB" not in upper and "ESTABLISHED" not in upper:
                continue
            if peer_ip and peer_ip not in line:
                continue
            if f":{listen_port}" in line:
                established = True
                break

    return {
        "available": True,
        "service": {
            "name": service,
            "active": service_code == 0 and service_output.strip() == "active",
            "raw": service_output,
        },
        "listener": {"listening": listening, "expected_port": listen_port},
        "session": {"tcp_established": established, "peer_ip": peer_ip},
        # A TCP/179 socket proves transport only; it is not the BGP FSM and
        # must not be promoted to an established BGP/FlowSpec peer.
        "bgp_state": "not_verified",
        "flowspec_state": "not_verified",
        "logs_tail": log_output[-4000:] if log_code == 0 else "",
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/bgp/status":
            self.send_response(404)
            self.end_headers()
            return
        params = parse_qs(parsed.query)
        service = params.get("service", [""])[0]
        peer_ip = params.get("peer_ip", [""])[0]
        try:
            listen_port = int(params.get("listen_port", ["179"])[0])
        except ValueError:
            listen_port = 179
        payload = bgp_status(service, peer_ip, listen_port)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="GMJ-FLOW optional host status agent")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
