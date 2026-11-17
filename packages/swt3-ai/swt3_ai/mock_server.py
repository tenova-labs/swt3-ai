"""SWT3 Mock Server -- local HTTP endpoint for testing.

Returns SWT3-MOCK- prefixed anchors. MUST NOT share code paths
with the production witness endpoint.

Red team mitigations:
    #4  Mock server in prod:  All anchors carry SWT3-MOCK- prefix.
        Doctor check warns if mock endpoint detected in config.
        Banner printed every 100 requests.

Usage:
    swt3 mock-server                    # port 9999
    swt3 mock-server --port 8888        # custom port
    swt3 mock-server --verbose          # log each request

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional

VERSION = "8.2.0"
MOCK_PREFIX = "SWT3-MOCK-"
BANNER_INTERVAL = 100

# ANSI
_YELLOW = "\033[33m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_DIM = "\033[90m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_request_count = 0
_verbose = False
_last_request_time = 0.0


def _build_mock_receipt(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build a receipt with SWT3-MOCK- prefix."""
    fp = payload.get("anchor_fingerprint", "000000000000")
    proc = payload.get("procedure_id", "UNKNOWN")
    epoch = int(time.time())
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    anchor = f"{MOCK_PREFIX}{proc}-PASS-{epoch}-{fp}"
    return {
        "ok": True,
        "procedure_id": proc,
        "verdict": "PASS",
        "swt3_anchor": anchor,
        "canonical_hash": "",
        "clearing_level": payload.get("clearing_level", 1),
        "verification_url": "",
        "witnessed_at": ts,
        "mock": True,
    }


class MockWitnessHandler(BaseHTTPRequestHandler):
    """HTTP handler mimicking /api/v1/witness/batch and /ocsf."""

    def log_message(self, fmt: str, *args: Any) -> None:
        if _verbose:
            sys.stderr.write(f"  {_DIM}[mock] {fmt % args}{_RESET}\n")

    def do_GET(self) -> None:
        if self.path == "/healthz" or self.path == "/health":
            self._respond(200, {"ok": True, "mock": True, "version": VERSION})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        global _request_count, _last_request_time
        _request_count += 1
        _last_request_time = time.time()

        if _request_count % BANNER_INTERVAL == 0:
            sys.stderr.write(
                f"\n  {_RED}{_BOLD}THIS IS A MOCK SERVER. DO NOT USE IN PRODUCTION.{_RESET}\n"
                f"  {_DIM}{_request_count} requests served. All anchors carry {MOCK_PREFIX} prefix.{_RESET}\n\n"
            )

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._respond(400, {"error": "empty body"})
            return

        try:
            body = self.rfile.read(content_length)
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            self._respond(400, {"error": f"invalid JSON: {e}"})
            return

        # Support both batch format and OCSF format
        if self.path in ("/api/v1/witness/batch", "/api/v1/witness"):
            if isinstance(data, list):
                payloads = data
            else:
                payloads = data.get("payloads", data.get("events", []))
            receipts = [_build_mock_receipt(p) for p in payloads]
            self._respond(200, {
                "ok": True,
                "count": len(receipts),
                "receipts": receipts,
            })
        elif self.path == "/api/v1/witness/ocsf":
            if isinstance(data, list):
                events = data
            else:
                events = data.get("events", [])
            receipts = [_build_mock_receipt(e) for e in events]
            self._respond(200, {
                "ok": True,
                "count": len(receipts),
                "receipts": receipts,
            })
        else:
            # Accept any POST path gracefully for testing
            payloads = data if isinstance(data, list) else [data]
            receipts = [_build_mock_receipt(p) for p in payloads]
            self._respond(200, {
                "ok": True,
                "count": len(receipts),
                "receipts": receipts,
            })

    def _respond(self, code: int, body: Dict[str, Any]) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-SWT3-Mock", "true")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())


def run_mock_server(port: int = 9999, verbose: bool = False, idle_timeout: int = 1800) -> None:
    """Start the mock server.

    Args:
        idle_timeout: Seconds of inactivity before auto-shutdown. 0 = no timeout.
                      Default: 1800 (30 minutes). Red team #6: prevents stale processes.
    """
    global _verbose, _last_request_time
    _verbose = verbose
    _last_request_time = time.time()

    # Bind to localhost only -- NEVER expose mock server to the network.
    # Red team finding: 0.0.0.0 on a cloud VM = network-accessible mock endpoint.
    bind_addr = "127.0.0.1"
    server = HTTPServer((bind_addr, port), MockWitnessHandler)
    server.timeout = 1.0  # socket timeout for handle_request loop

    print(f"\n  {_BOLD}SWT3 Mock Server v{VERSION}{_RESET}")
    print(f"  {_RED}{_BOLD}FOR TESTING ONLY. DO NOT USE IN PRODUCTION.{_RESET}")
    print(f"  All anchors carry {_YELLOW}{MOCK_PREFIX}{_RESET} prefix.\n")
    print(f"  Listening on {_GREEN}http://{bind_addr}:{port}{_RESET}")
    print(f"    POST /api/v1/witness/batch  -- batch witness")
    print(f"    POST /api/v1/witness/ocsf   -- infrastructure witness")
    print(f"    GET  /healthz               -- health check")
    if idle_timeout > 0:
        print(f"\n  {_DIM}Auto-shutdown after {idle_timeout}s idle (--no-timeout to disable){_RESET}")
    print(f"  {_DIM}Usage: SWT3_ENDPOINT=http://localhost:{port}/api/v1/witness/batch swt3 test{_RESET}")
    print(f"  {_DIM}Press Ctrl+C to stop.{_RESET}\n")

    try:
        while True:
            server.handle_request()
            # Red team #6: Auto-shutdown on idle to prevent stale processes
            if idle_timeout > 0 and (time.time() - _last_request_time) > idle_timeout:
                sys.stderr.write(
                    f"\n  {_YELLOW}Mock server idle for {idle_timeout}s. Auto-shutting down.{_RESET}\n"
                    f"  {_DIM}{_request_count} requests served.{_RESET}\n"
                )
                break
    except KeyboardInterrupt:
        sys.stderr.write(f"\n  {_DIM}Mock server stopped. {_request_count} requests served.{_RESET}\n")
    finally:
        server.server_close()


def handle_mock_server(args: List[str]) -> None:
    """CLI handler for `swt3 mock-server`."""
    port = 9999
    idle_timeout = 1800
    verbose = "--verbose" in args or "-v" in args
    no_timeout = "--no-timeout" in args

    for i, arg in enumerate(args):
        if arg == "--port" and i + 1 < len(args):
            try:
                port = int(args[i + 1])
            except ValueError:
                print(f"Invalid port: {args[i + 1]}", file=sys.stderr)
                sys.exit(1)
        elif arg == "--timeout" and i + 1 < len(args):
            try:
                idle_timeout = int(args[i + 1])
            except ValueError:
                print(f"Invalid timeout: {args[i + 1]}", file=sys.stderr)
                sys.exit(1)

    if no_timeout:
        idle_timeout = 0

    run_mock_server(port=port, verbose=verbose, idle_timeout=idle_timeout)
