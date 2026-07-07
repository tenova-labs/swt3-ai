"""Tests for CrewAI adapter."""

import unittest
from unittest.mock import MagicMock

from swt3_ai.adapters.crewai import wrap_crew_ai


class MockCrew:
    """Mock CrewAI Crew with kickoff() method."""

    def __init__(self, output="Crew completed successfully."):
        self.name = "research-crew"
        self.agents = [{"name": "researcher"}, {"name": "writer"}]
        self.tasks = [{"desc": "research"}, {"desc": "write"}, {"desc": "review"}]
        self._output = output
        self.kickoff_count = 0

    def kickoff(self, inputs=None, **kwargs):
        self.kickoff_count += 1
        return self._output


class TestWrapCrewAI(unittest.TestCase):
    def _mock_witness(self):
        w = MagicMock()
        w.record = MagicMock()
        return w

    def test_wraps_kickoff_and_records(self):
        crew = MockCrew()
        w = self._mock_witness()
        wrapped = wrap_crew_ai(crew, witness=w)

        wrapped.kickoff()

        self.assertEqual(crew.kickoff_count, 1)
        w.record.assert_called_once()

    def test_preserves_return_value(self):
        expected = {"raw": "Report", "tasks_output": [1, 2, 3]}
        crew = MockCrew(output=expected)
        w = self._mock_witness()
        wrapped = wrap_crew_ai(crew, witness=w)

        result = wrapped.kickoff()

        self.assertEqual(result, expected)

    def test_passes_inputs(self):
        crew = MockCrew()
        w = self._mock_witness()
        wrapped = wrap_crew_ai(crew, witness=w)

        wrapped.kickoff(inputs={"topic": "AI compliance"})

        # Should have been called (kickoff_count tracks it)
        self.assertEqual(crew.kickoff_count, 1)

    def test_default_model_id_with_name(self):
        crew = MockCrew()
        w = self._mock_witness()
        wrapped = wrap_crew_ai(crew, witness=w)

        wrapped.kickoff()

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "crewai-research-crew")

    def test_default_model_id_without_name(self):
        crew = MockCrew()
        crew.name = None
        w = self._mock_witness()
        wrapped = wrap_crew_ai(crew, witness=w)

        wrapped.kickoff()

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "crewai-crew")

    def test_explicit_model_id(self):
        crew = MockCrew()
        w = self._mock_witness()
        wrapped = wrap_crew_ai(crew, witness=w, model_id="custom-crew-v2")

        wrapped.kickoff()

        record = w.record.call_args[0][0]
        self.assertEqual(record.model_id, "custom-crew-v2")

    def test_provider_is_crewai(self):
        crew = MockCrew()
        w = self._mock_witness()
        wrapped = wrap_crew_ai(crew, witness=w)

        wrapped.kickoff()

        record = w.record.call_args[0][0]
        self.assertEqual(record.provider, "crewai")

    def test_captures_agent_and_task_counts(self):
        crew = MockCrew()
        w = self._mock_witness()
        wrapped = wrap_crew_ai(crew, witness=w)

        wrapped.kickoff()

        record = w.record.call_args[0][0]
        self.assertEqual(record.input_tokens, 2)   # 2 agents
        self.assertEqual(record.output_tokens, 3)   # 3 tasks

    def test_measures_latency(self):
        crew = MockCrew()
        w = self._mock_witness()
        wrapped = wrap_crew_ai(crew, witness=w)

        wrapped.kickoff()

        record = w.record.call_args[0][0]
        self.assertGreaterEqual(record.latency_ms, 0)

    def test_passthrough_attributes(self):
        crew = MockCrew()
        crew.custom_attr = "hello"
        w = self._mock_witness()
        wrapped = wrap_crew_ai(crew, witness=w)

        self.assertEqual(wrapped.custom_attr, "hello")

    def test_noop_without_witness(self):
        crew = MockCrew()
        result = wrap_crew_ai(crew)

        self.assertIs(result, crew)


if __name__ == "__main__":
    unittest.main()
