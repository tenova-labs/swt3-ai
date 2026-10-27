"""Adapter parity tests for Groq, Together AI, DeepSeek, and Azure OpenAI.

Cross-language parity: the expected hash values here MUST match the
TypeScript test file (test/ecosystem-adapters.test.ts). If a test fails
here but passes in TS (or vice versa), it means the adapters diverge.

No external SDK installs required -- uses MagicMock to simulate clients.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from swt3_ai.fingerprint import sha256_truncated
from swt3_ai.adapters.groq import wrap_groq, is_groq_client, is_groq_url
from swt3_ai.adapters.together_ai import wrap_together, is_together_client, is_together_url
from swt3_ai.adapters.deepseek import wrap_deepseek, is_deepseek_client
from swt3_ai.adapters.azure_openai import wrap_azure_openai, is_azure_openai_client


# ---------------------------------------------------------------------------
# Cross-language parity constants (computed from Python, verified in TS)
# ---------------------------------------------------------------------------

GROQ_PROMPT = "Explain quantum computing briefly."
GROQ_RESPONSE = "Quantum computing uses qubits that can exist in superposition, enabling parallel computation for certain problems."
GROQ_MODEL = "llama-3.3-70b-versatile"
GROQ_SYSTEM = "You are a physics tutor."

EXPECTED_GROQ_PROMPT_HASH = "93dbeba4c831d02f"
EXPECTED_GROQ_RESPONSE_HASH = "02482cb21f3f0ff6"
EXPECTED_GROQ_MODEL_HASH = "3d066009f1527f27"
EXPECTED_GROQ_SYSTEM_HASH = "348cccd4bddf8d95"

TOGETHER_PROMPT = "Write a haiku about open-weight models."
TOGETHER_RESPONSE = "Weights freely given\nTransparency lights the path\nTrust through openness"
TOGETHER_MODEL = "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"

EXPECTED_TOGETHER_PROMPT_HASH = "c8a4a3842d54034f"
EXPECTED_TOGETHER_RESPONSE_HASH = "6e98a24614ab3a54"
EXPECTED_TOGETHER_MODEL_HASH = "0109d18002277f35"

DEEPSEEK_PROMPT = "Solve: 2x + 3 = 7"
DEEPSEEK_RESPONSE = "<think>Let me solve step by step.\n2x + 3 = 7\n2x = 4\nx = 2</think>\n\nThe solution is x = 2."
DEEPSEEK_MODEL = "deepseek-reasoner"

EXPECTED_DEEPSEEK_PROMPT_HASH = "0559ee0f82f2427a"
EXPECTED_DEEPSEEK_RESPONSE_HASH = "57fb4bbd3ebf6c37"
EXPECTED_DEEPSEEK_MODEL_HASH = "2524619d26e98571"

AZURE_PROMPT = "Summarize this quarterly report."
AZURE_RESPONSE = "Revenue increased 12% year-over-year driven by cloud services growth."
AZURE_MODEL = "my-gpt4o-deployment"
AZURE_SYSTEM = "You are a financial analyst."

EXPECTED_AZURE_PROMPT_HASH = "d3817bf5fea06df4"
EXPECTED_AZURE_RESPONSE_HASH = "f4fc2f4906791ccd"
EXPECTED_AZURE_MODEL_HASH = "08b365b7cd032f00"
EXPECTED_AZURE_SYSTEM_HASH = "3f85bf54e7d0287c"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _mock_witness():
    w = MagicMock()
    w._strict = False
    w.config = MagicMock(clearing_level=1)
    return w


def _mock_openai_response(model, content, input_tokens=10, output_tokens=5):
    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message = MagicMock(content=content, refusal=None)
    response.choices[0].finish_reason = "stop"
    response.usage = MagicMock(prompt_tokens=input_tokens, completion_tokens=output_tokens)
    response.model = model
    response.system_fingerprint = None
    return response


def _mock_oai_client(base_url="https://api.openai.com/v1", model="gpt-4o", content="Hello!"):
    """Create a mock OpenAI-compatible client."""
    client = MagicMock()
    client.base_url = base_url
    response = _mock_openai_response(model, content)
    client.chat.completions.create = MagicMock(return_value=response)
    return client, response


# ---------------------------------------------------------------------------
# Hash parity tests
# ---------------------------------------------------------------------------

class TestHashParity:
    """Verify sha256_truncated produces identical output across languages."""

    def test_groq_prompt_hash(self):
        assert sha256_truncated(GROQ_PROMPT) == EXPECTED_GROQ_PROMPT_HASH

    def test_groq_response_hash(self):
        assert sha256_truncated(GROQ_RESPONSE) == EXPECTED_GROQ_RESPONSE_HASH

    def test_groq_model_hash(self):
        assert sha256_truncated(GROQ_MODEL) == EXPECTED_GROQ_MODEL_HASH

    def test_groq_system_hash(self):
        assert sha256_truncated(GROQ_SYSTEM) == EXPECTED_GROQ_SYSTEM_HASH

    def test_together_prompt_hash(self):
        assert sha256_truncated(TOGETHER_PROMPT) == EXPECTED_TOGETHER_PROMPT_HASH

    def test_together_response_hash(self):
        assert sha256_truncated(TOGETHER_RESPONSE) == EXPECTED_TOGETHER_RESPONSE_HASH

    def test_together_model_hash(self):
        assert sha256_truncated(TOGETHER_MODEL) == EXPECTED_TOGETHER_MODEL_HASH

    def test_deepseek_prompt_hash(self):
        assert sha256_truncated(DEEPSEEK_PROMPT) == EXPECTED_DEEPSEEK_PROMPT_HASH

    def test_deepseek_response_hash(self):
        assert sha256_truncated(DEEPSEEK_RESPONSE) == EXPECTED_DEEPSEEK_RESPONSE_HASH

    def test_deepseek_model_hash(self):
        assert sha256_truncated(DEEPSEEK_MODEL) == EXPECTED_DEEPSEEK_MODEL_HASH

    def test_azure_prompt_hash(self):
        assert sha256_truncated(AZURE_PROMPT) == EXPECTED_AZURE_PROMPT_HASH

    def test_azure_response_hash(self):
        assert sha256_truncated(AZURE_RESPONSE) == EXPECTED_AZURE_RESPONSE_HASH

    def test_azure_model_hash(self):
        assert sha256_truncated(AZURE_MODEL) == EXPECTED_AZURE_MODEL_HASH

    def test_azure_system_hash(self):
        assert sha256_truncated(AZURE_SYSTEM) == EXPECTED_AZURE_SYSTEM_HASH


# ---------------------------------------------------------------------------
# Groq adapter tests
# ---------------------------------------------------------------------------

class TestGroqAdapter:

    def test_provider_tag(self):
        witness = _mock_witness()
        client, _ = _mock_oai_client(model=GROQ_MODEL, content=GROQ_RESPONSE)
        proxy = wrap_groq(client, witness)
        proxy.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": GROQ_PROMPT}],
        )
        assert witness.record.called
        record = witness.record.call_args[0][0]
        assert record.provider == "groq"

    def test_model_id(self):
        witness = _mock_witness()
        client, _ = _mock_oai_client(model=GROQ_MODEL, content=GROQ_RESPONSE)
        proxy = wrap_groq(client, witness)
        proxy.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": GROQ_PROMPT}],
        )
        record = witness.record.call_args[0][0]
        assert record.model_id == GROQ_MODEL

    def test_error_transparency(self):
        witness = _mock_witness()
        client = MagicMock()
        client.base_url = "https://api.groq.com/openai/v1"
        client.chat.completions.create = MagicMock(side_effect=RuntimeError("rate limited"))
        proxy = wrap_groq(client, witness)
        with pytest.raises(RuntimeError, match="rate limited"):
            proxy.chat.completions.create(model=GROQ_MODEL, messages=[])
        assert not witness.record.called


class TestGroqDetection:

    def test_is_groq_client_positive(self):
        client = MagicMock()
        client.__class__.__module__ = "groq._client"
        assert is_groq_client(client)

    def test_is_groq_client_negative(self):
        client = MagicMock()
        client.__class__.__module__ = "openai._client"
        assert not is_groq_client(client)

    def test_is_groq_url_positive(self):
        client = MagicMock()
        client.base_url = "https://api.groq.com/openai/v1"
        assert is_groq_url(client)

    def test_is_groq_url_negative(self):
        client = MagicMock()
        client.base_url = "https://api.openai.com/v1"
        assert not is_groq_url(client)


# ---------------------------------------------------------------------------
# Together AI adapter tests
# ---------------------------------------------------------------------------

class TestTogetherAdapter:

    def test_provider_tag(self):
        witness = _mock_witness()
        client, _ = _mock_oai_client(model=TOGETHER_MODEL, content=TOGETHER_RESPONSE)
        proxy = wrap_together(client, witness)
        proxy.chat.completions.create(
            model=TOGETHER_MODEL,
            messages=[{"role": "user", "content": TOGETHER_PROMPT}],
        )
        assert witness.record.called
        record = witness.record.call_args[0][0]
        assert record.provider == "together"

    def test_model_id(self):
        witness = _mock_witness()
        client, _ = _mock_oai_client(model=TOGETHER_MODEL, content=TOGETHER_RESPONSE)
        proxy = wrap_together(client, witness)
        proxy.chat.completions.create(
            model=TOGETHER_MODEL,
            messages=[{"role": "user", "content": TOGETHER_PROMPT}],
        )
        record = witness.record.call_args[0][0]
        assert record.model_id == TOGETHER_MODEL

    def test_error_transparency(self):
        witness = _mock_witness()
        client = MagicMock()
        client.base_url = "https://api.together.xyz/v1"
        client.chat.completions.create = MagicMock(side_effect=ConnectionError("timeout"))
        proxy = wrap_together(client, witness)
        with pytest.raises(ConnectionError, match="timeout"):
            proxy.chat.completions.create(model=TOGETHER_MODEL, messages=[])
        assert not witness.record.called


class TestTogetherDetection:

    def test_is_together_client_positive(self):
        client = MagicMock()
        client.__class__.__module__ = "together.client"
        assert is_together_client(client)

    def test_is_together_client_negative(self):
        client = MagicMock()
        client.__class__.__module__ = "openai._client"
        assert not is_together_client(client)

    def test_is_together_url_positive(self):
        client = MagicMock()
        client.base_url = "https://api.together.xyz/v1"
        assert is_together_url(client)

    def test_is_together_url_negative(self):
        client = MagicMock()
        client.base_url = "https://api.openai.com/v1"
        assert not is_together_url(client)


# ---------------------------------------------------------------------------
# DeepSeek adapter tests
# ---------------------------------------------------------------------------

class TestDeepSeekAdapter:

    def test_provider_tag(self):
        witness = _mock_witness()
        client, _ = _mock_oai_client(
            base_url="https://api.deepseek.com",
            model=DEEPSEEK_MODEL,
            content=DEEPSEEK_RESPONSE,
        )
        proxy = wrap_deepseek(client, witness)
        proxy.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=[{"role": "user", "content": DEEPSEEK_PROMPT}],
        )
        assert witness.record.called
        record = witness.record.call_args[0][0]
        assert record.provider == "deepseek"

    def test_r1_thinking_tokens_hashed(self):
        """DeepSeek R1 thinking tokens must be part of the response hash."""
        witness = _mock_witness()
        client, _ = _mock_oai_client(
            base_url="https://api.deepseek.com",
            model=DEEPSEEK_MODEL,
            content=DEEPSEEK_RESPONSE,
        )
        proxy = wrap_deepseek(client, witness)
        proxy.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=[{"role": "user", "content": DEEPSEEK_PROMPT}],
        )
        record = witness.record.call_args[0][0]
        assert record.response_hash == EXPECTED_DEEPSEEK_RESPONSE_HASH

    def test_error_transparency(self):
        witness = _mock_witness()
        client = MagicMock()
        client.base_url = "https://api.deepseek.com"
        client.chat.completions.create = MagicMock(side_effect=ValueError("invalid api key"))
        proxy = wrap_deepseek(client, witness)
        with pytest.raises(ValueError, match="invalid api key"):
            proxy.chat.completions.create(model=DEEPSEEK_MODEL, messages=[])
        assert not witness.record.called


class TestDeepSeekDetection:

    def test_is_deepseek_client_positive(self):
        client = MagicMock()
        client.base_url = "https://api.deepseek.com"
        assert is_deepseek_client(client)

    def test_is_deepseek_client_positive_with_path(self):
        client = MagicMock()
        client.base_url = "https://api.deepseek.com/v1"
        assert is_deepseek_client(client)

    def test_is_deepseek_client_negative(self):
        client = MagicMock()
        client.base_url = "https://api.openai.com/v1"
        assert not is_deepseek_client(client)

    def test_is_deepseek_client_no_base_url(self):
        client = MagicMock(spec=[])
        assert not is_deepseek_client(client)


# ---------------------------------------------------------------------------
# Azure OpenAI adapter tests
# ---------------------------------------------------------------------------

class TestAzureOpenAIAdapter:

    def test_provider_tag(self):
        witness = _mock_witness()
        client, _ = _mock_oai_client(
            base_url="https://myresource.openai.azure.com/openai/deployments/my-gpt4o-deployment",
            model=AZURE_MODEL,
            content=AZURE_RESPONSE,
        )
        proxy = wrap_azure_openai(client, witness)
        proxy.chat.completions.create(
            model=AZURE_MODEL,
            messages=[
                {"role": "system", "content": AZURE_SYSTEM},
                {"role": "user", "content": AZURE_PROMPT},
            ],
        )
        assert witness.record.called
        record = witness.record.call_args[0][0]
        assert record.provider == "azure-openai"

    def test_deployment_name_as_model_id(self):
        """Azure model param is deployment name -- must be preserved."""
        witness = _mock_witness()
        client, _ = _mock_oai_client(model=AZURE_MODEL, content=AZURE_RESPONSE)
        proxy = wrap_azure_openai(client, witness)
        proxy.chat.completions.create(
            model=AZURE_MODEL,
            messages=[{"role": "user", "content": AZURE_PROMPT}],
        )
        record = witness.record.call_args[0][0]
        assert record.model_id == AZURE_MODEL

    def test_content_filter_refusal(self):
        """Azure content_filter finish_reason should set has_refusal."""
        witness = _mock_witness()
        response = _mock_openai_response(AZURE_MODEL, "")
        response.choices[0].finish_reason = "content_filter"
        client = MagicMock()
        client.base_url = "https://myresource.openai.azure.com"
        client.chat.completions.create = MagicMock(return_value=response)
        proxy = wrap_azure_openai(client, witness)
        proxy.chat.completions.create(
            model=AZURE_MODEL,
            messages=[{"role": "user", "content": "bad content"}],
        )
        record = witness.record.call_args[0][0]
        assert record.has_refusal is True

    def test_error_transparency(self):
        witness = _mock_witness()
        client = MagicMock()
        client.base_url = "https://myresource.openai.azure.com"
        client.chat.completions.create = MagicMock(side_effect=PermissionError("auth failed"))
        proxy = wrap_azure_openai(client, witness)
        with pytest.raises(PermissionError, match="auth failed"):
            proxy.chat.completions.create(model=AZURE_MODEL, messages=[])
        assert not witness.record.called


class TestAzureDetection:

    def test_is_azure_by_class_name(self):
        client = MagicMock()
        client.__class__.__name__ = "AzureOpenAI"
        client.__class__.__module__ = "openai._client"
        assert is_azure_openai_client(client)

    def test_is_azure_async_by_class_name(self):
        client = MagicMock()
        client.__class__.__name__ = "AsyncAzureOpenAI"
        client.__class__.__module__ = "openai._client"
        assert is_azure_openai_client(client)

    def test_is_azure_by_url(self):
        client = MagicMock()
        client.__class__.__name__ = "OpenAI"
        client.base_url = "https://myresource.openai.azure.com/openai"
        assert is_azure_openai_client(client)

    def test_is_not_azure_plain_openai(self):
        client = MagicMock()
        client.__class__.__name__ = "OpenAI"
        client.base_url = "https://api.openai.com/v1"
        assert not is_azure_openai_client(client)


# ---------------------------------------------------------------------------
# Collision tests: OpenAI SDK pointed at alternative providers
# ---------------------------------------------------------------------------

class TestCollisionDetection:
    """Ensure correct provider detection when OpenAI SDK is pointed at various APIs."""

    def test_plain_openai_not_detected_as_others(self):
        client = MagicMock()
        client.base_url = "https://api.openai.com/v1"
        assert not is_deepseek_client(client)
        assert not is_azure_openai_client(client)
        assert not is_groq_url(client)
        assert not is_together_url(client)

    def test_openai_sdk_groq_url(self):
        client = MagicMock()
        client.base_url = "https://api.groq.com/openai/v1"
        assert is_groq_url(client)
        assert not is_deepseek_client(client)
        assert not is_together_url(client)

    def test_openai_sdk_together_url(self):
        client = MagicMock()
        client.base_url = "https://api.together.xyz/v1"
        assert is_together_url(client)
        assert not is_groq_url(client)
        assert not is_deepseek_client(client)

    def test_openai_sdk_deepseek_url(self):
        client = MagicMock()
        client.base_url = "https://api.deepseek.com/v1"
        assert is_deepseek_client(client)
        assert not is_groq_url(client)
        assert not is_together_url(client)

    def test_openai_sdk_azure_url(self):
        client = MagicMock()
        client.__class__.__name__ = "OpenAI"
        client.base_url = "https://myresource.openai.azure.com/openai"
        assert is_azure_openai_client(client)
        assert not is_deepseek_client(client)
        assert not is_groq_url(client)
