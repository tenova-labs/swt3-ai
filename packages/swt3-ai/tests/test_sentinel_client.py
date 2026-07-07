"""Tests for the SentinelClient.

Tests cover:
- Client API surface (check, record, sign, tokens, flush, status)
- Auto-detection returns None when no daemon
- NDJSON protocol round-trip with a mock server
- Cross-process shared enforcement via mock daemon
"""

import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from swt3_ai.sentinel_client import (
    SentinelClient,
    SentinelCheckResult,
    SentinelViolation,
    DEFAULT_SOCKET_PATH,
)


class MockSentinelDaemon:
    """Minimal mock daemon for testing the Python client."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(socket_path)
        self._server.listen(5)
        self._server.settimeout(2.0)
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._velocity_count = 0
        self._token_total = 0
        self._wal_seq = 0

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._server.close()
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass

    def _serve(self) -> None:
        while self._running:
            try:
                conn, _ = self._server.accept()
                handler = threading.Thread(
                    target=self._handle, args=(conn,), daemon=True
                )
                handler.start()
            except (OSError, socket.timeout):
                continue

    def _handle(self, conn: socket.socket) -> None:
        buf = b""
        conn.settimeout(2.0)
        while self._running:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    idx = buf.index(b"\n")
                    line = buf[:idx].decode("utf-8")
                    buf = buf[idx + 1:]
                    resp = self._dispatch(line)
                    conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            except (OSError, socket.timeout):
                break
        conn.close()

    def _dispatch(self, line: str) -> dict:
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            return {"id": "?", "ok": False, "error": "bad json", "code": "INVALID_REQUEST"}

        req_id = req.get("id", "?")
        op = req.get("op")

        if op == "status":
            return {
                "id": req_id, "ok": True, "uptime": 1000,
                "tokens": self._token_total, "violations": 0,
                "walSeq": self._wal_seq, "walCheckpoint": 0,
                "connections": 1, "protocolVersion": 1,
            }
        elif op == "check":
            self._velocity_count += 1
            tool = req.get("tool", "")
            if tool.startswith("blocked_"):
                return {
                    "id": req_id, "ok": True, "allowed": False,
                    "violation": {
                        "rule": "blocklist", "tool": tool,
                        "action": "blocked", "reason": f'Tool "{tool}" is on the blocklist',
                        "timestamp": int(time.time() * 1000),
                    },
                }
            return {"id": req_id, "ok": True, "allowed": True}
        elif op == "tokens":
            self._token_total += req.get("count", 0)
            return {"id": req_id, "ok": True, "total": self._token_total, "budget": 10000}
        elif op == "record":
            self._wal_seq += 1
            return {"id": req_id, "ok": True, "seq": self._wal_seq}
        elif op == "sign":
            # Return a fake but deterministic signature
            import hashlib
            payload = req.get("payload", "")
            agent_id = req.get("agentId")
            msg = f"{payload}:{agent_id}" if agent_id else payload
            sig = hashlib.sha256(msg.encode()).hexdigest()[:64]
            return {"id": req_id, "ok": True, "signature": sig}
        elif op == "flush":
            return {"id": req_id, "ok": True, "flushedSeq": self._wal_seq}
        else:
            return {"id": req_id, "ok": False, "error": f"unknown op: {op}", "code": "UNKNOWN_OP"}


class TestSentinelClientDetection(unittest.TestCase):
    """Test auto-detection behavior."""

    def test_detect_returns_none_when_no_daemon(self):
        """SentinelClient.detect() returns None when no daemon is running."""
        result = SentinelClient.detect("/tmp/nonexistent-swt3-sentinel.sock")
        self.assertIsNone(result)

    def test_default_socket_path_is_user_writable(self):
        """Default socket path should be in ~/.swt3/, not /var/run/."""
        self.assertIn(".swt3", DEFAULT_SOCKET_PATH)
        self.assertNotIn("/var/run/", DEFAULT_SOCKET_PATH)


class TestSentinelClientWithMockDaemon(unittest.TestCase):
    """Test client operations against a mock daemon."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmpdir = tempfile.mkdtemp(prefix="swt3-sentinel-py-test-")
        cls.socket_path = os.path.join(cls.tmpdir, "sentinel.sock")
        cls.daemon = MockSentinelDaemon(cls.socket_path)
        cls.daemon.start()
        time.sleep(0.05)  # Let server start

    @classmethod
    def tearDownClass(cls) -> None:
        cls.daemon.stop()
        try:
            os.rmdir(cls.tmpdir)
        except OSError:
            pass

    def _connect(self) -> SentinelClient:
        client = SentinelClient(socket_path=self.socket_path, timeout=2.0)
        client.connect()
        return client

    def test_detect_finds_running_daemon(self):
        client = SentinelClient.detect(self.socket_path)
        self.assertIsNotNone(client)
        self.assertTrue(client.connected)
        client.destroy()

    def test_status_round_trip(self):
        client = self._connect()
        resp = client.status()
        self.assertEqual(resp["protocolVersion"], 1)
        self.assertGreaterEqual(resp["uptime"], 0)
        client.destroy()

    def test_check_allowed(self):
        client = self._connect()
        result = client.check("safe_tool")
        self.assertTrue(result.allowed)
        self.assertIsNone(result.violation)
        client.destroy()

    def test_check_blocked(self):
        client = self._connect()
        result = client.check("blocked_tool")
        self.assertFalse(result.allowed)
        self.assertIsNotNone(result.violation)
        self.assertEqual(result.violation.rule, "blocklist")
        self.assertEqual(result.violation.action, "blocked")
        client.destroy()

    def test_record_returns_sequence(self):
        client = self._connect()
        resp = client.record("fp_abc", '{"model":"gpt-4"}')
        self.assertGreater(resp["seq"], 0)
        client.destroy()

    def test_sign_returns_signature(self):
        client = self._connect()
        sig = client.sign("test-fingerprint")
        self.assertEqual(len(sig), 64)
        client.destroy()

    def test_sign_with_agent_id_differs(self):
        client = self._connect()
        sig1 = client.sign("fp123")
        sig2 = client.sign("fp123", agent_id="agent-1")
        self.assertNotEqual(sig1, sig2)
        client.destroy()

    def test_sign_deterministic(self):
        client = self._connect()
        sig1 = client.sign("same-data")
        sig2 = client.sign("same-data")
        self.assertEqual(sig1, sig2)
        client.destroy()

    def test_tokens_accumulates(self):
        client = self._connect()
        r1 = client.record_tokens(100)
        total_after_first = r1["total"]
        r2 = client.record_tokens(200)
        self.assertEqual(r2["total"], total_after_first + 200)
        client.destroy()

    def test_flush_returns_seq(self):
        client = self._connect()
        client.record("fp_flush", "{}")
        resp = client.flush()
        self.assertGreater(resp["flushedSeq"], 0)
        client.destroy()

    def test_destroy_disconnects(self):
        client = self._connect()
        self.assertTrue(client.connected)
        client.destroy()
        self.assertFalse(client.connected)

    def test_cross_process_shared_velocity(self):
        """Two clients share state through the same daemon."""
        client_a = self._connect()
        client_b = self._connect()

        # Both check through the same daemon
        result_a = client_a.check("tool_from_a")
        result_b = client_b.check("tool_from_b")
        self.assertTrue(result_a.allowed)
        self.assertTrue(result_b.allowed)

        # Daemon's velocity counter incremented by both
        status = client_a.status()
        # We can't check exact velocity count from status, but tokens work
        r1 = client_a.record_tokens(500)
        r2 = client_b.record_tokens(700)
        # Client B sees the accumulated total from both
        self.assertGreater(r2["total"], r1["total"])

        client_a.destroy()
        client_b.destroy()

    def test_full_pipeline(self):
        """Complete witness cycle: check -> record -> sign -> tokens -> flush -> status."""
        client = self._connect()

        check = client.check("safe_tool")
        self.assertIsInstance(check, SentinelCheckResult)

        record = client.record("fp_pipeline", '{"procedure":"AI-INF.1"}')
        self.assertGreater(record["seq"], 0)

        sig = client.sign("fp_pipeline")
        self.assertEqual(len(sig), 64)

        tokens = client.record_tokens(150)
        self.assertGreater(tokens["total"], 0)

        flush = client.flush()
        self.assertGreater(flush["flushedSeq"], 0)

        status = client.status()
        self.assertEqual(status["protocolVersion"], 1)

        client.destroy()


class TestSentinelClientEdgeCases(unittest.TestCase):
    """Edge case and error handling tests."""

    def test_request_without_connection_raises(self):
        client = SentinelClient(socket_path="/tmp/no-such-socket")
        with self.assertRaises(ConnectionError):
            client.check("tool")

    def test_sentinel_violation_slots(self):
        """SentinelViolation uses __slots__ for memory efficiency."""
        v = SentinelViolation(
            rule="blocklist", tool="bad_tool", action="blocked",
            reason="test", timestamp=123,
        )
        self.assertEqual(v.rule, "blocklist")
        self.assertEqual(v.action, "blocked")
        with self.assertRaises(AttributeError):
            v.nonexistent = True  # type: ignore

    def test_check_result_slots(self):
        r = SentinelCheckResult(allowed=True)
        self.assertTrue(r.allowed)
        self.assertIsNone(r.violation)


if __name__ == "__main__":
    unittest.main()
