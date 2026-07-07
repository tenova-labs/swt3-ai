"""SWT3 AI Witness SDK: Sentinel Client.

Thin proxy that connects to the swt3-sentinel daemon over a Unix
domain socket. When the daemon is detected, witness operations
(attestation signing, WAL persistence, policy evaluation) are
delegated to the isolated process for tamper-proof evidence.
When the daemon is absent, the SDK operates standalone with
zero degradation.

Auto-detection adds less than 10ms to initialization and requires
zero code changes from the developer.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("swt3_ai")

# User-writable default: ~/.swt3/sentinel.sock. No root needed.
DEFAULT_SOCKET_PATH = str(Path.home() / ".swt3" / "sentinel.sock")
DEFAULT_TIMEOUT_S = 0.05  # 50ms
DETECT_TIMEOUT_S = 0.01  # 10ms


class SentinelViolation:
    """Violation returned by the sentinel daemon."""

    __slots__ = ("rule", "tool", "action", "reason", "timestamp", "context")

    def __init__(
        self,
        rule: str,
        tool: str,
        action: str,
        reason: str,
        timestamp: float,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.rule = rule
        self.tool = tool
        self.action = action
        self.reason = reason
        self.timestamp = timestamp
        self.context = context


class SentinelCheckResult:
    """Result of a chain enforcement check."""

    __slots__ = ("allowed", "violation")

    def __init__(self, allowed: bool, violation: Optional[SentinelViolation] = None) -> None:
        self.allowed = allowed
        self.violation = violation


class SentinelClient:
    """Unix domain socket client for the swt3-sentinel daemon.

    Usage::

        # Explicit connection
        client = SentinelClient.detect()
        if client:
            result = client.check("my_tool")

        # Or via Witness (automatic, zero code changes):
        witness = Witness.from_config()  # auto-detects daemon
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
        fail_secure: bool = False,
    ) -> None:
        self._socket_path = (
            socket_path
            or os.environ.get("SWT3_SENTINEL_SOCKET")
            or DEFAULT_SOCKET_PATH
        )
        self._timeout = timeout
        self._fail_secure = fail_secure
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._lock = threading.Lock()

    @classmethod
    def detect(cls, socket_path: Optional[str] = None) -> Optional["SentinelClient"]:
        """Non-blocking auto-detection with 10ms timeout.

        Returns a connected SentinelClient if the daemon is running,
        or None if no daemon is available.
        """
        path = (
            socket_path
            or os.environ.get("SWT3_SENTINEL_SOCKET")
            or DEFAULT_SOCKET_PATH
        )

        # Quick probe: can we connect to the socket?
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(DETECT_TIMEOUT_S)
        try:
            sock.connect(path)
            sock.close()
        except (OSError, socket.timeout):
            sock.close()
            return None

        # Socket exists and accepts connections -- create a real client
        client = cls(socket_path=path)
        try:
            client.connect()
            return client
        except Exception:
            return None

    def connect(self) -> None:
        """Connect to the sentinel daemon."""
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(self._timeout)
        self._sock.connect(self._socket_path)
        self._connected = True

    @property
    def connected(self) -> bool:
        return self._connected

    def check(self, tool: str) -> SentinelCheckResult:
        """Check a tool call against the shared enforcement engine."""
        resp = self._request({"op": "check", "tool": tool})
        violation = None
        if resp.get("violation"):
            v = resp["violation"]
            violation = SentinelViolation(
                rule=v.get("rule", ""),
                tool=v.get("tool", tool),
                action=v.get("action", "logged"),
                reason=v.get("reason", ""),
                timestamp=v.get("timestamp", 0),
                context=v.get("context"),
            )
        return SentinelCheckResult(
            allowed=resp.get("allowed", True),
            violation=violation,
        )

    def record(self, fingerprint: str, payload: str) -> Dict[str, Any]:
        """Record a witness entry in the protected WAL."""
        return self._request({"op": "record", "fingerprint": fingerprint, "payload": payload})

    def sign(self, data: str, agent_id: Optional[str] = None) -> str:
        """Sign a payload using the daemon's isolated key."""
        req: Dict[str, Any] = {"op": "sign", "payload": data}
        if agent_id is not None:
            req["agentId"] = agent_id
        resp = self._request(req)
        return resp.get("signature", "")

    def record_tokens(self, count: int) -> Dict[str, Any]:
        """Record token consumption in the shared budget."""
        return self._request({"op": "tokens", "count": count})

    def flush(self) -> Dict[str, Any]:
        """Flush the protected WAL."""
        return self._request({"op": "flush"})

    def status(self) -> Dict[str, Any]:
        """Get daemon status."""
        return self._request({"op": "status"})

    def destroy(self) -> None:
        """Disconnect from the daemon."""
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ── Internal ──────────────────────────────────────────────────────

    def _request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Send a request and wait for the correlated response."""
        if not self._sock or not self._connected:
            raise ConnectionError("Not connected to sentinel daemon")

        req_id = uuid.uuid4().hex[:8]
        req["id"] = req_id
        line = json.dumps(req) + "\n"

        with self._lock:
            try:
                self._sock.sendall(line.encode("utf-8"))
                # Read response (NDJSON: one line per response)
                data = self._recv_line()
                resp = json.loads(data)
                if not resp.get("ok"):
                    raise RuntimeError(resp.get("error", "Sentinel error"))
                return resp
            except (socket.timeout, OSError, json.JSONDecodeError) as exc:
                self._connected = False
                raise ConnectionError(f"Sentinel communication failed: {exc}") from exc

    def _recv_line(self) -> str:
        """Read until newline from the socket."""
        buf = b""
        while True:
            chunk = self._sock.recv(4096)  # type: ignore[union-attr]
            if not chunk:
                raise ConnectionError("Connection closed by sentinel")
            buf += chunk
            idx = buf.find(b"\n")
            if idx != -1:
                return buf[:idx].decode("utf-8")
