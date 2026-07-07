"""Tests for Google ADK adapter."""

import unittest
from unittest.mock import MagicMock, patch

from swt3_ai.adapters.google_adk import wrap_google_adk


class MockAgent:
    """Mock Google ADK Agent with run() method."""

    def __init__(self, response="The weather is sunny."):
        self.model = "gemini-2.0-flash"
        self.name = "weather-agent"
        self._response = response
        self.run_count = 0

    def run(self, prompt, *args, **kwargs):
        self.run_count += 1
        return self._response


class TestWrapGoogleADK(unittest.TestCase):
    def _mock_witness(self):
        w = MagicMock()
        w.record = MagicMock()
        return w

    def test_wraps_run_and_records(self):
        agent = MockAgent()
        w = self._mock_witness()
        wrapped = wrap_google_adk(agent, witness=w)

        wrapped.run("What is the weather?")

        self.assertEqual(agent.run_count, 1)
        w.record.assert_called_once()

    def test_preserves_return_value(self):
        expected = {"text": "72F", "tools": ["weather_api"]}
        agent = MockAgent(response=expected)
        w = self._mock_witness()
        wrapped = wrap_google_adk(agent, witness=w)

        result = wrapped.run("temperature?")

        self.assertEqual(result, expected)

    def test_explicit_model_id(self):
        agent = MockAgent()
        w = self._mock_witness()
        wrapped = wrap_google_adk(agent, witness=w, model_id="custom-v2")

        wrapped.run("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "custom-v2")

    def test_falls_back_to_agent_model(self):
        agent = MockAgent()
        w = self._mock_witness()
        wrapped = wrap_google_adk(agent, witness=w)

        wrapped.run("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "gemini-2.0-flash")

    def test_falls_back_to_agent_name(self):
        agent = MockAgent()
        agent.model = None
        w = self._mock_witness()
        wrapped = wrap_google_adk(agent, witness=w)

        wrapped.run("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "google-adk-weather-agent")

    def test_default_model_id(self):
        agent = MockAgent()
        agent.model = None
        agent.name = None
        w = self._mock_witness()
        wrapped = wrap_google_adk(agent, witness=w)

        wrapped.run("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "google-adk-agent")

    def test_provider_is_google_adk(self):
        agent = MockAgent()
        w = self._mock_witness()
        wrapped = wrap_google_adk(agent, witness=w)

        wrapped.run("test")

        record = w.record.call_args[0][0]
        self.assertEqual(record.provider, "google-adk")

    def test_measures_latency(self):
        agent = MockAgent()
        w = self._mock_witness()
        wrapped = wrap_google_adk(agent, witness=w)

        wrapped.run("test")

        record = w.record.call_args[0][0]
        self.assertGreaterEqual(record.latency_ms, 0)

    def test_hashes_prompt_and_response(self):
        agent = MockAgent()
        w = self._mock_witness()
        wrapped = wrap_google_adk(agent, witness=w)

        wrapped.run("What is AI compliance?")

        record = w.record.call_args[0][0]
        self.assertEqual(len(record.prompt_hash), 16)
        self.assertEqual(len(record.response_hash), 16)

    def test_passthrough_attributes(self):
        agent = MockAgent()
        agent.custom_attr = "hello"
        w = self._mock_witness()
        wrapped = wrap_google_adk(agent, witness=w)

        self.assertEqual(wrapped.custom_attr, "hello")

    def test_noop_without_witness(self):
        agent = MockAgent()
        result = wrap_google_adk(agent)

        # Without env vars, should return original agent
        self.assertIs(result, agent)


if __name__ == "__main__":
    unittest.main()
