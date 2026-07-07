"""Tests for Microsoft Foundry adapter."""

import unittest
from unittest.mock import MagicMock

from swt3_ai.adapters.foundry import wrap_foundry


class MockFoundryAgent:
    """Mock Microsoft Foundry agent with execute() method."""

    def __init__(self, response=None):
        self.name = "document-agent"
        self.model = "gpt-4o"
        self._response = response or {"text": "Document summarized."}
        self.execute_count = 0

    def execute(self, prompt, *args, **kwargs):
        self.execute_count += 1
        return self._response

    def intercept_tool_call(self, tool_name, tool_input, *args, **kwargs):
        return {"tool": tool_name, "result": "ok"}


class TestWrapFoundry(unittest.TestCase):
    def _mock_witness(self):
        w = MagicMock()
        w.record = MagicMock()
        return w

    def test_wraps_execute_and_records(self):
        agent = MockFoundryAgent()
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w)

        wrapped.execute("Summarize this document")

        self.assertEqual(agent.execute_count, 1)
        w.record.assert_called_once()

    def test_preserves_return_value(self):
        expected = {"text": "Summary", "confidence": 0.98}
        agent = MockFoundryAgent(response=expected)
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w)

        result = wrapped.execute("Summarize Q4 earnings")

        self.assertEqual(result, expected)

    def test_wraps_intercept_tool_call(self):
        agent = MockFoundryAgent()
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w)

        wrapped.intercept_tool_call("search", {"query": "revenue"})

        w.record.assert_called_once()
        record = w.record.call_args[0][0]
        self.assertEqual(record.provider, "microsoft-foundry")

    def test_explicit_model_id(self):
        agent = MockFoundryAgent()
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w, model_id="mai-ds-1.0")

        wrapped.execute("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "mai-ds-1.0")

    def test_falls_back_to_agent_model(self):
        agent = MockFoundryAgent()
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w)

        wrapped.execute("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "gpt-4o")

    def test_falls_back_to_agent_name(self):
        agent = MockFoundryAgent()
        agent.model = None
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w)

        wrapped.execute("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "foundry-document-agent")

    def test_default_model_id(self):
        agent = MockFoundryAgent()
        agent.model = None
        agent.name = None
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w)

        wrapped.execute("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "foundry-agent")

    def test_provider_is_microsoft_foundry(self):
        agent = MockFoundryAgent()
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w)

        wrapped.execute("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.provider, "microsoft-foundry")

    def test_measures_latency(self):
        agent = MockFoundryAgent()
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w)

        wrapped.execute("test")

        record = w.record.call_args[0][0]
        self.assertGreaterEqual(record.latency_ms, 0)

    def test_hashes_prompt(self):
        agent = MockFoundryAgent()
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w)

        wrapped.execute({"text": "important data", "metadata": {"src": "scout"}})

        record = w.record.call_args[0][0]
        self.assertEqual(len(record.prompt_hash), 16)
        self.assertEqual(len(record.response_hash), 16)

    def test_passthrough_attributes(self):
        agent = MockFoundryAgent()
        agent.custom = "hello"
        w = self._mock_witness()
        wrapped = wrap_foundry(agent, witness=w)

        self.assertEqual(wrapped.custom, "hello")

    def test_noop_without_witness(self):
        agent = MockFoundryAgent()
        result = wrap_foundry(agent)

        self.assertIs(result, agent)


if __name__ == "__main__":
    unittest.main()
