"""Tests for A2A (Agent-to-Agent) adapter."""

import unittest
from unittest.mock import MagicMock

from swt3_ai.adapters.a2a import wrap_a2a


class MockA2AAgent:
    """Mock A2A agent with send() method."""

    def __init__(self, response=None):
        self.name = "analyst-agent"
        self.model = "gemini-2.0"
        self._response = response or {"text": "Analysis complete."}
        self.send_count = 0

    def send(self, message, *args, **kwargs):
        self.send_count += 1
        return self._response

    def handle_message(self, message, *args, **kwargs):
        return self._response


class TestWrapA2A(unittest.TestCase):
    def _mock_witness(self):
        w = MagicMock()
        w.record = MagicMock()
        return w

    def test_wraps_send_and_records(self):
        agent = MockA2AAgent()
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        wrapped.send({"text": "Analyze this"})

        self.assertEqual(agent.send_count, 1)
        w.record.assert_called_once()

    def test_preserves_return_value(self):
        expected = {"text": "Result", "confidence": 0.95}
        agent = MockA2AAgent(response=expected)
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        result = wrapped.send({"text": "query"})

        self.assertEqual(result, expected)

    def test_wraps_handle_message(self):
        agent = MockA2AAgent()
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        wrapped.handle_message({"text": "incoming"})

        w.record.assert_called_once()
        record = w.record.call_args[0][0]
        self.assertEqual(record.provider, "a2a")

    def test_explicit_model_id(self):
        agent = MockA2AAgent()
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w, model_id="custom-a2a")

        wrapped.send("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "custom-a2a")

    def test_falls_back_to_agent_model(self):
        agent = MockA2AAgent()
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        wrapped.send("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "gemini-2.0")

    def test_falls_back_to_agent_name(self):
        agent = MockA2AAgent()
        agent.model = None
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        wrapped.send("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "a2a-analyst-agent")

    def test_default_model_id(self):
        agent = MockA2AAgent()
        agent.model = None
        agent.name = None
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        wrapped.send("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "a2a-agent")

    def test_provider_is_a2a(self):
        agent = MockA2AAgent()
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        wrapped.send("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.provider, "a2a")

    def test_measures_latency(self):
        agent = MockA2AAgent()
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        wrapped.send("test")

        record = w.record.call_args[0][0]
        self.assertGreaterEqual(record.latency_ms, 0)

    def test_hashes_message(self):
        agent = MockA2AAgent()
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        wrapped.send({"text": "important data", "metadata": {"src": "sensor"}})

        record = w.record.call_args[0][0]
        self.assertEqual(len(record.prompt_hash), 16)
        self.assertEqual(len(record.response_hash), 16)

    def test_passthrough_attributes(self):
        agent = MockA2AAgent()
        agent.custom = "hello"
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        self.assertEqual(wrapped.custom, "hello")

    def test_private_attrs_blocked(self):
        agent = MockA2AAgent()
        w = self._mock_witness()
        wrapped = wrap_a2a(agent, witness=w)

        with self.assertRaises(AttributeError):
            _ = wrapped._witness

    def test_noop_without_witness(self):
        agent = MockA2AAgent()
        result = wrap_a2a(agent)

        self.assertIs(result, agent)


if __name__ == "__main__":
    unittest.main()
