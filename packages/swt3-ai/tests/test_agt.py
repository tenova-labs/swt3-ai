"""Tests for Microsoft AGT adapter."""

import pytest
from unittest.mock import MagicMock, patch
from swt3_ai.adapters.agt import wrap_agt, _extract_guardrails


class MockAGTEngine:
    """Mock AGT policy engine with evaluate() and assess()."""

    def __init__(self, name="test-policy", model="gpt-4o"):
        self.name = name
        self.model = model
        self._evaluate_result = {"verdict": "allow", "policies_evaluated": []}
        self._assess_result = {"score": 0.95}

    def evaluate(self, prompt, *args, **kwargs):
        return self._evaluate_result

    def assess(self, config, *args, **kwargs):
        return self._assess_result


class TestWrapAGT:
    def test_evaluate_witnesses(self):
        engine = MockAGTEngine()
        witness = MagicMock()
        wrapped = wrap_agt(engine, witness)

        result = wrapped.evaluate("Test prompt")

        assert result == {"verdict": "allow", "policies_evaluated": []}
        witness.record.assert_called_once()
        record = witness.record.call_args[0][0]
        assert record.provider == "microsoft-agt"
        assert record.model_id == "gpt-4o"

    def test_assess_witnesses(self):
        engine = MockAGTEngine()
        witness = MagicMock()
        wrapped = wrap_agt(engine, witness)

        result = wrapped.assess({"agent": "fraud-detector"})

        assert result == {"score": 0.95}
        witness.record.assert_called_once()
        record = witness.record.call_args[0][0]
        assert record.provider == "microsoft-agt"

    def test_assess_missing_raises(self):
        engine = MagicMock(spec=["evaluate"])
        engine.evaluate.return_value = {"verdict": "allow"}
        witness = MagicMock()
        wrapped = wrap_agt(engine, witness)

        with pytest.raises(AttributeError):
            wrapped.assess({"config": True})

    def test_passthrough_attributes(self):
        engine = MockAGTEngine()
        engine.custom_attr = "hello"
        witness = MagicMock()
        wrapped = wrap_agt(engine, witness)

        assert wrapped.custom_attr == "hello"
        assert wrapped.name == "test-policy"

    def test_model_id_from_engine(self):
        engine = MockAGTEngine(model="claude-opus-4-6")
        witness = MagicMock()
        wrapped = wrap_agt(engine, witness)
        wrapped.evaluate("test")

        record = witness.record.call_args[0][0]
        assert record.model_id == "claude-opus-4-6"

    def test_model_id_explicit_override(self):
        engine = MockAGTEngine()
        witness = MagicMock()
        wrapped = wrap_agt(engine, witness, model_id="custom-model")
        wrapped.evaluate("test")

        record = witness.record.call_args[0][0]
        assert record.model_id == "custom-model"

    def test_model_id_fallback(self):
        engine = MagicMock(spec=["evaluate"])
        engine.evaluate.return_value = {}
        del engine.model
        del engine.name
        witness = MagicMock()
        wrapped = wrap_agt(engine, witness)
        wrapped.evaluate("test")

        record = witness.record.call_args[0][0]
        assert record.model_id == "agt-policy-engine"

    def test_noop_without_witness(self):
        engine = MockAGTEngine()
        result = wrap_agt(engine, witness=None)
        assert result is engine

    def test_latency_recorded(self):
        engine = MockAGTEngine()
        witness = MagicMock()
        wrapped = wrap_agt(engine, witness)
        wrapped.evaluate("test")

        record = witness.record.call_args[0][0]
        assert record.latency_ms >= 0

    def test_response_untouched(self):
        expected = {"verdict": "deny", "reason": "PII detected"}
        engine = MockAGTEngine()
        engine._evaluate_result = expected
        witness = MagicMock()
        wrapped = wrap_agt(engine, witness)

        result = wrapped.evaluate("test with PII")
        assert result is expected


class TestExtractGuardrails:
    def test_empty_result(self):
        active, names, passed = _extract_guardrails({})
        assert active == 0
        assert names == []
        assert passed is True

    def test_policies_with_names(self):
        result = {
            "verdict": "allow",
            "policies_evaluated": [
                {"name": "pii-filter", "result": "pass"},
                {"name": "toxicity-check", "result": "pass"},
            ],
        }
        active, names, passed = _extract_guardrails(result)
        assert active == 2
        assert names == ["pii-filter", "toxicity-check"]
        assert passed is True

    def test_policy_failure(self):
        result = {
            "verdict": "deny",
            "policies_evaluated": [
                {"name": "pii-filter", "result": "fail"},
            ],
        }
        active, names, passed = _extract_guardrails(result)
        assert active == 1
        assert passed is False

    def test_guardrails_key(self):
        result = {
            "guardrails": [
                {"policy_name": "content-safety", "passed": True},
            ],
        }
        active, names, passed = _extract_guardrails(result)
        assert active == 1
        assert names == ["content-safety"]
        assert passed is True

    def test_string_policies(self):
        result = {"policies_evaluated": ["rule-a", "rule-b"]}
        active, names, passed = _extract_guardrails(result)
        assert active == 2
        assert names == ["rule-a", "rule-b"]

    def test_non_dict_result(self):
        active, names, passed = _extract_guardrails("just a string")
        assert active == 0
        assert passed is True

    def test_deny_verdict(self):
        result = {"verdict": "deny"}
        _, _, passed = _extract_guardrails(result)
        assert passed is False

    def test_block_verdict(self):
        result = {"decision": "block"}
        _, _, passed = _extract_guardrails(result)
        assert passed is False
