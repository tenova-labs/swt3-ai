"""Adapter parity tests for Mistral, Bedrock Guardrails, and Strands.

Cross-language parity: the expected hash values here MUST match the
TypeScript test file (test/new-adapters.test.ts). If a test fails here
but passes in TS (or vice versa), it means the adapters diverge.

No external SDK installs required -- uses MagicMock to simulate clients.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from swt3_ai.fingerprint import sha256_truncated
from swt3_ai.adapters.mistral import wrap_mistral, _extract_prompt_text, _extract_system_prompt, _extract_record
from swt3_ai.adapters.bedrock_guardrails import wrap_bedrock_guardrails, _extract_content_text
from swt3_ai.adapters.strands import wrap_strands, _get_model_id, _stringify_result


# ---------------------------------------------------------------------------
# Cross-language parity constants (computed from Python, verified in TS)
# ---------------------------------------------------------------------------

MISTRAL_PROMPT_TEXT = "You are a financial advisor.\nAnalyze this portfolio risk."
MISTRAL_SYSTEM_TEXT = "You are a financial advisor."
MISTRAL_RESPONSE_TEXT = "Based on the analysis, the portfolio has moderate risk."
MISTRAL_MODEL_ID = "mistral-large-2411"

EXPECTED_MISTRAL_PROMPT_HASH = "9e6c5530135bf590"
EXPECTED_MISTRAL_SYSTEM_HASH = "a933c605958009be"
EXPECTED_MISTRAL_RESPONSE_HASH = "de776ac3330266ab"
EXPECTED_MISTRAL_MODEL_HASH = "82cac7c231d55cb8"

BEDROCK_CONTENT_TEXT = "Evaluate this user message for policy violations"
BEDROCK_MODEL_ID = "guardrail:my-content-policy:1"

EXPECTED_BEDROCK_PROMPT_HASH = "778b0662d1d7997f"
EXPECTED_BEDROCK_MODEL_HASH = "8fed24ba506b00c3"
EXPECTED_BEDROCK_NONE_HASH = "59c83661ea2d62f2"

STRANDS_PROMPT = "What is 2+2?"
STRANDS_RESULT = "The answer is 4."
STRANDS_MODEL = "us.anthropic.claude-sonnet-4-20250514"

EXPECTED_STRANDS_PROMPT_HASH = "52cb6b5e4a038af1"
EXPECTED_STRANDS_RESPONSE_HASH = "ae758477f843049b"
EXPECTED_STRANDS_MODEL_HASH = "12087e2a951571ed"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _mock_witness():
    w = MagicMock()
    w._strict = False
    w.config = MagicMock(clearing_level=1)
    return w


# ---------------------------------------------------------------------------
# Hash parity: these must match TypeScript exactly
# ---------------------------------------------------------------------------

class TestHashParity:
    """Verify sha256_truncated produces identical output across languages."""

    def test_mistral_prompt_hash(self):
        assert sha256_truncated(MISTRAL_PROMPT_TEXT) == EXPECTED_MISTRAL_PROMPT_HASH

    def test_mistral_system_hash(self):
        assert sha256_truncated(MISTRAL_SYSTEM_TEXT) == EXPECTED_MISTRAL_SYSTEM_HASH

    def test_mistral_response_hash(self):
        assert sha256_truncated(MISTRAL_RESPONSE_TEXT) == EXPECTED_MISTRAL_RESPONSE_HASH

    def test_mistral_model_hash(self):
        assert sha256_truncated(MISTRAL_MODEL_ID) == EXPECTED_MISTRAL_MODEL_HASH

    def test_bedrock_prompt_hash(self):
        assert sha256_truncated(BEDROCK_CONTENT_TEXT) == EXPECTED_BEDROCK_PROMPT_HASH

    def test_bedrock_model_hash(self):
        assert sha256_truncated(BEDROCK_MODEL_ID) == EXPECTED_BEDROCK_MODEL_HASH

    def test_strands_prompt_hash(self):
        assert sha256_truncated(STRANDS_PROMPT) == EXPECTED_STRANDS_PROMPT_HASH

    def test_strands_response_hash(self):
        assert sha256_truncated(STRANDS_RESULT) == EXPECTED_STRANDS_RESPONSE_HASH

    def test_strands_model_hash(self):
        assert sha256_truncated(STRANDS_MODEL) == EXPECTED_STRANDS_MODEL_HASH


# ---------------------------------------------------------------------------
# Mistral adapter: extraction and proxy
# ---------------------------------------------------------------------------

class TestMistralExtraction:
    def test_extract_prompt_text_from_dicts(self):
        messages = [
            {"role": "system", "content": "You are a financial advisor."},
            {"role": "user", "content": "Analyze this portfolio risk."},
        ]
        text = _extract_prompt_text(messages)
        assert text == MISTRAL_PROMPT_TEXT

    def test_extract_system_prompt(self):
        messages = [
            {"role": "system", "content": "You are a financial advisor."},
            {"role": "user", "content": "Analyze this portfolio risk."},
        ]
        system = _extract_system_prompt(messages)
        assert system == MISTRAL_SYSTEM_TEXT

    def test_extract_system_prompt_none(self):
        messages = [{"role": "user", "content": "Hello"}]
        assert _extract_system_prompt(messages) is None

    def test_extract_record_from_response(self):
        response = MagicMock()
        response.choices = [MagicMock()]
        response.choices[0].message = MagicMock()
        response.choices[0].message.content = MISTRAL_RESPONSE_TEXT
        response.choices[0].finish_reason = "stop"
        response.usage = MagicMock(prompt_tokens=10, completion_tokens=5)
        response.model = MISTRAL_MODEL_ID

        record = _extract_record(
            response, "mistral-large-latest",
            EXPECTED_MISTRAL_PROMPT_HASH, 150,
            EXPECTED_MISTRAL_SYSTEM_HASH,
        )

        assert record.model_id == MISTRAL_MODEL_ID
        assert record.model_hash == EXPECTED_MISTRAL_MODEL_HASH
        assert record.response_hash == EXPECTED_MISTRAL_RESPONSE_HASH
        assert record.provider == "mistral"
        assert record.has_refusal is False
        assert record.input_tokens == 10
        assert record.output_tokens == 5
        assert record.system_prompt_hash == EXPECTED_MISTRAL_SYSTEM_HASH

    def test_refusal_detected(self):
        response = MagicMock()
        response.choices = [MagicMock()]
        response.choices[0].message = MagicMock(content="")
        response.choices[0].finish_reason = "error"
        response.usage = None
        response.model = "mistral-large-2411"

        record = _extract_record(response, "mistral-large-latest", "abc", 100)
        assert record.has_refusal is True

    def test_finish_reason_tool_calls_not_refusal(self):
        response = MagicMock()
        response.choices = [MagicMock()]
        response.choices[0].message = MagicMock(content="")
        response.choices[0].finish_reason = "tool_calls"
        response.usage = None
        response.model = "mistral-large-2411"

        record = _extract_record(response, "mistral-large-latest", "abc", 100)
        assert record.has_refusal is False


class TestMistralProxy:
    def test_two_level_proxy(self):
        """wrap_mistral -> proxy.chat.complete() triggers witnessing."""
        client = MagicMock()
        response = MagicMock()
        response.choices = [MagicMock()]
        response.choices[0].message = MagicMock(content="Hello!")
        response.choices[0].finish_reason = "stop"
        response.usage = MagicMock(prompt_tokens=5, completion_tokens=3)
        response.model = "mistral-large-2411"
        client.chat.complete = MagicMock(return_value=response)

        witness = _mock_witness()
        proxy = wrap_mistral(client, witness)

        result = proxy.chat.complete(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "hi"}],
        )

        assert result is response
        assert witness.record.called
        record = witness.record.call_args[0][0]
        assert record.provider == "mistral"
        assert record.model_id == "mistral-large-2411"

    def test_passthrough_non_chat(self):
        """Non-chat attributes pass through unchanged."""
        client = MagicMock()
        client.models = MagicMock()
        client.models.list = MagicMock(return_value=["model1"])

        witness = _mock_witness()
        proxy = wrap_mistral(client, witness)

        result = proxy.models.list()
        assert result == ["model1"]


# ---------------------------------------------------------------------------
# Bedrock Guardrails adapter: extraction and proxy
# ---------------------------------------------------------------------------

class TestBedrockGuardrailsExtraction:
    def test_extract_content_text(self):
        content = [{"text": {"text": "Evaluate this user message for policy violations"}}]
        text = _extract_content_text(content)
        assert text == BEDROCK_CONTENT_TEXT

    def test_extract_content_text_string_shorthand(self):
        content = [{"text": "plain text"}]
        text = _extract_content_text(content)
        assert text == "plain text"

    def test_extract_content_text_empty(self):
        assert _extract_content_text([]) == ""
        assert _extract_content_text(None) == ""


class TestBedrockGuardrailsProxy:
    def test_witnesses_apply_guardrail(self):
        client = MagicMock()
        client.apply_guardrail = MagicMock(return_value={
            "action": "NONE",
            "assessments": [],
            "outputs": [],
            "usage": {"topicPolicyUnits": 10, "contentPolicyUnits": 5},
        })

        witness = _mock_witness()
        proxy = wrap_bedrock_guardrails(client, witness)

        result = proxy.apply_guardrail(
            guardrailIdentifier="my-content-policy",
            guardrailVersion="1",
            source="INPUT",
            content=[{"text": {"text": BEDROCK_CONTENT_TEXT}}],
        )

        assert result["action"] == "NONE"
        assert witness.record.called

        record = witness.record.call_args[0][0]
        assert record.provider == "aws-bedrock-guardrails"
        assert record.model_id == BEDROCK_MODEL_ID
        assert record.model_hash == EXPECTED_BEDROCK_MODEL_HASH
        assert record.prompt_hash == EXPECTED_BEDROCK_PROMPT_HASH
        assert record.response_hash == EXPECTED_BEDROCK_NONE_HASH
        assert record.has_refusal is False
        assert record.guardrail_passed is True
        assert record.access_target == "INPUT"
        assert record.input_tokens == 15  # 10 + 5 policy units

    def test_witnesses_intervention(self):
        client = MagicMock()
        client.apply_guardrail = MagicMock(return_value={
            "action": "GUARDRAIL_INTERVENED",
            "assessments": [],
            "outputs": [],
            "usage": {},
        })

        witness = _mock_witness()
        proxy = wrap_bedrock_guardrails(client, witness)
        proxy.apply_guardrail(
            guardrailIdentifier="policy",
            guardrailVersion="1",
            source="OUTPUT",
            content=[{"text": {"text": "blocked content"}}],
        )

        record = witness.record.call_args[0][0]
        assert record.has_refusal is True
        assert record.guardrail_passed is False
        assert record.access_target == "OUTPUT"

    def test_passthrough_other_methods(self):
        client = MagicMock()
        client.invoke_model = MagicMock(return_value={"body": "response"})

        witness = _mock_witness()
        proxy = wrap_bedrock_guardrails(client, witness)

        result = proxy.invoke_model(modelId="test")
        assert result == {"body": "response"}
        assert not witness.record.called


# ---------------------------------------------------------------------------
# Strands adapter: extraction and proxy
# ---------------------------------------------------------------------------

class TestStrandsExtraction:
    def test_get_model_id_from_string(self):
        agent = MagicMock()
        agent.model = STRANDS_MODEL
        proxy = wrap_strands(agent, _mock_witness())
        assert _get_model_id(proxy) == STRANDS_MODEL

    def test_get_model_id_override(self):
        agent = MagicMock()
        agent.model = "ignored"
        proxy = wrap_strands(agent, _mock_witness(), model_id="custom-model")
        assert _get_model_id(proxy) == "custom-model"

    def test_get_model_id_fallback(self):
        agent = MagicMock(spec=[])
        proxy = wrap_strands(agent, _mock_witness())
        assert _get_model_id(proxy) == "strands-agent"

    def test_stringify_result_string(self):
        assert _stringify_result("hello") == "hello"

    def test_stringify_result_none(self):
        assert _stringify_result(None) == ""

    def test_stringify_result_object(self):
        result = MagicMock()
        result.__str__ = lambda self: "The answer is 4."
        assert _stringify_result(result) == "The answer is 4."


class TestStrandsProxy:
    def test_witnesses_call(self):
        agent = MagicMock()
        agent.model = STRANDS_MODEL
        agent.return_value = STRANDS_RESULT

        witness = _mock_witness()
        proxy = wrap_strands(agent, witness)

        result = proxy(STRANDS_PROMPT)

        assert result == STRANDS_RESULT
        assert witness.record.called

        record = witness.record.call_args[0][0]
        assert record.provider == "aws-strands"
        assert record.model_id == STRANDS_MODEL
        assert record.model_hash == EXPECTED_STRANDS_MODEL_HASH
        assert record.prompt_hash == EXPECTED_STRANDS_PROMPT_HASH
        assert record.response_hash == EXPECTED_STRANDS_RESPONSE_HASH
        assert record.has_refusal is False

    def test_passthrough_attributes(self):
        agent = MagicMock()
        agent.name = "test-agent"
        agent.tools = ["calculator"]

        witness = _mock_witness()
        proxy = wrap_strands(agent, witness)

        assert proxy.name == "test-agent"
        assert proxy.tools == ["calculator"]

    def test_repr(self):
        agent = MagicMock()
        witness = _mock_witness()
        proxy = wrap_strands(agent, witness)
        assert "WitnessProxy" in repr(proxy)
