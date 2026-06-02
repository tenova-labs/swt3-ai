"""Unified adapter tests: Ollama, vLLM, LangChain.

Pure Python -- no external AI SDK installs required.
Uses MagicMock to simulate OpenAI clients and LangChain callbacks.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, PropertyMock

import pytest

from swt3_ai.adapters.ollama import wrap_ollama, is_ollama_client
from swt3_ai.adapters.vllm import wrap_vllm
from swt3_ai.adapters.langchain import SWT3CallbackHandler, _extract_model_name, _extract_chat_texts, _extract_llm_result
from swt3_ai.adapters.openai import _OpenAIProxy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _mock_witness():
    """Create a mock Witness with the minimum interface for adapters."""
    w = MagicMock()
    w._strict = False
    w.config = MagicMock(clearing_level=1)
    return w


def _mock_openai_client(base_url="https://api.openai.com/v1"):
    """Create a mock OpenAI client with chat.completions.create()."""
    client = MagicMock()
    client.base_url = base_url

    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message = MagicMock(content="Hello!", refusal=None)
    response.choices[0].finish_reason = "stop"
    response.usage = MagicMock(prompt_tokens=10, completion_tokens=5)
    response.model = "llama3.2"
    response.system_fingerprint = None

    client.chat.completions.create = MagicMock(return_value=response)
    return client, response


# ---------------------------------------------------------------------------
# Ollama: is_ollama_client detection
# ---------------------------------------------------------------------------

class TestIsOllamaClient:
    def test_standard_ollama_port(self):
        client = MagicMock()
        client.base_url = "http://localhost:11434/v1"
        assert is_ollama_client(client) is True

    def test_remote_ollama(self):
        client = MagicMock()
        client.base_url = "http://gpu-server.internal:11434/v1"
        assert is_ollama_client(client) is True

    def test_not_ollama(self):
        client = MagicMock()
        client.base_url = "https://api.openai.com/v1"
        assert is_ollama_client(client) is False

    def test_no_base_url(self):
        client = MagicMock(spec=[])
        assert is_ollama_client(client) is False

    def test_httpx_url_object(self):
        """base_url may be an httpx.URL object, not a string."""
        client = MagicMock()
        url = MagicMock()
        url.__str__ = lambda self: "http://localhost:11434/v1"
        client.base_url = url
        assert is_ollama_client(client) is True


# ---------------------------------------------------------------------------
# Ollama: wrap_ollama provider tagging
# ---------------------------------------------------------------------------

class TestWrapOllama:
    def test_returns_proxy(self):
        client, _ = _mock_openai_client("http://localhost:11434/v1")
        witness = _mock_witness()
        proxy = wrap_ollama(client, witness)
        assert isinstance(proxy, _OpenAIProxy)

    def test_provider_tag(self):
        client, response = _mock_openai_client("http://localhost:11434/v1")
        witness = _mock_witness()
        proxy = wrap_ollama(client, witness)

        # Trigger an inference through the proxy
        proxy.chat.completions.create(model="llama3.2", messages=[{"role": "user", "content": "hi"}])

        # Verify witness.record was called with provider="ollama"
        assert witness.record.called
        record = witness.record.call_args[0][0]
        assert record.provider == "ollama"
        assert record.model_id == "llama3.2"

    def test_repr(self):
        client, _ = _mock_openai_client("http://localhost:11434/v1")
        witness = _mock_witness()
        proxy = wrap_ollama(client, witness)
        assert "WitnessProxy" in repr(proxy)


# ---------------------------------------------------------------------------
# vLLM: wrap_vllm provider tagging
# ---------------------------------------------------------------------------

class TestWrapVllm:
    def test_returns_proxy(self):
        client, _ = _mock_openai_client("http://localhost:8000/v1")
        witness = _mock_witness()
        proxy = wrap_vllm(client, witness)
        assert isinstance(proxy, _OpenAIProxy)

    def test_provider_tag(self):
        client, response = _mock_openai_client("http://localhost:8000/v1")
        witness = _mock_witness()
        proxy = wrap_vllm(client, witness)

        proxy.chat.completions.create(model="mistral-7b", messages=[{"role": "user", "content": "hi"}])

        assert witness.record.called
        record = witness.record.call_args[0][0]
        assert record.provider == "vllm"
        # model_id comes from response.model (llama3.2 in mock), not request
        assert record.model_id == "llama3.2"

    def test_latency_recorded(self):
        client, _ = _mock_openai_client("http://localhost:8000/v1")
        witness = _mock_witness()
        proxy = wrap_vllm(client, witness)

        proxy.chat.completions.create(model="mistral-7b", messages=[{"role": "user", "content": "hi"}])

        record = witness.record.call_args[0][0]
        assert record.latency_ms >= 0

    def test_token_usage(self):
        client, _ = _mock_openai_client("http://localhost:8000/v1")
        witness = _mock_witness()
        proxy = wrap_vllm(client, witness)

        proxy.chat.completions.create(model="mistral-7b", messages=[{"role": "user", "content": "hi"}])

        record = witness.record.call_args[0][0]
        assert record.input_tokens == 10
        assert record.output_tokens == 5


# ---------------------------------------------------------------------------
# OpenAI adapter: default provider still "openai"
# ---------------------------------------------------------------------------

class TestOpenAIProviderDefault:
    def test_default_provider_unchanged(self):
        """Ensure the refactor didn't break existing OpenAI behavior."""
        from swt3_ai.adapters.openai import wrap_openai

        client, _ = _mock_openai_client("https://api.openai.com/v1")
        witness = _mock_witness()
        proxy = wrap_openai(client, witness)

        proxy.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])

        record = witness.record.call_args[0][0]
        assert record.provider == "openai"


# ---------------------------------------------------------------------------
# LangChain: SWT3CallbackHandler
# ---------------------------------------------------------------------------

class TestLangChainCallback:
    def test_llm_start_end_lifecycle(self):
        """on_llm_start + on_llm_end produces an InferenceRecord."""
        witness = _mock_witness()
        handler = SWT3CallbackHandler(witness)
        run_id = uuid.uuid4()

        # Simulate on_llm_start
        handler.on_llm_start(
            serialized={"id": ["langchain_openai", "OpenAI"]},
            prompts=["What is the capital of France?"],
            run_id=run_id,
        )

        # Simulate on_llm_end
        response = MagicMock()
        gen = MagicMock()
        gen.text = "Paris"
        gen.message = None
        response.generations = [[gen]]
        response.llm_output = {"token_usage": {"prompt_tokens": 8, "completion_tokens": 1}}

        handler.on_llm_end(response, run_id=run_id)

        assert witness.record.called
        record = witness.record.call_args[0][0]
        assert record.provider == "langchain"
        assert record.model_id == "OpenAI"
        assert record.input_tokens == 8
        assert record.output_tokens == 1
        assert record.latency_ms >= 0

    def test_chat_model_start_end_lifecycle(self):
        """on_chat_model_start + on_llm_end for chat models."""
        witness = _mock_witness()
        handler = SWT3CallbackHandler(witness)
        run_id = uuid.uuid4()

        system_msg = MagicMock()
        system_msg.type = "system"
        system_msg.content = "You are helpful."

        user_msg = MagicMock()
        user_msg.type = "human"
        user_msg.content = "Hello"

        handler.on_chat_model_start(
            serialized={"kwargs": {"model_name": "gpt-4o"}, "id": []},
            messages=[[system_msg, user_msg]],
            run_id=run_id,
        )

        response = MagicMock()
        chat_gen = MagicMock()
        chat_gen.message = MagicMock(content="Hi there!")
        response.generations = [[chat_gen]]
        response.llm_output = {}

        handler.on_llm_end(response, run_id=run_id)

        record = witness.record.call_args[0][0]
        assert record.provider == "langchain"
        assert record.model_id == "gpt-4o"
        assert record.system_prompt_hash is not None
        assert len(record.prompt_hash) == 16
        assert len(record.response_hash) == 16

    def test_error_cleans_up_state(self):
        """on_llm_error removes the run from tracking."""
        witness = _mock_witness()
        handler = SWT3CallbackHandler(witness)
        run_id = uuid.uuid4()

        handler.on_llm_start(
            serialized={"id": ["test"]},
            prompts=["test"],
            run_id=run_id,
        )
        assert str(run_id) in handler._runs

        handler.on_llm_error(RuntimeError("test"), run_id=run_id)
        assert str(run_id) not in handler._runs

    def test_end_without_start_is_noop(self):
        """on_llm_end without prior start does nothing."""
        witness = _mock_witness()
        handler = SWT3CallbackHandler(witness)

        handler.on_llm_end(MagicMock(), run_id=uuid.uuid4())
        assert not witness.record.called

    def test_concurrent_run_ids(self):
        """Multiple simultaneous runs are tracked independently."""
        witness = _mock_witness()
        handler = SWT3CallbackHandler(witness)

        run_a = uuid.uuid4()
        run_b = uuid.uuid4()

        handler.on_llm_start(
            serialized={"kwargs": {"model": "model-a"}, "id": []},
            prompts=["prompt a"],
            run_id=run_a,
        )
        handler.on_llm_start(
            serialized={"kwargs": {"model": "model-b"}, "id": []},
            prompts=["prompt b"],
            run_id=run_b,
        )

        assert len(handler._runs) == 2

        # End run_b first
        resp = MagicMock()
        gen = MagicMock()
        gen.text = "response b"
        gen.message = None
        resp.generations = [[gen]]
        resp.llm_output = {}
        handler.on_llm_end(resp, run_id=run_b)

        assert len(handler._runs) == 1
        record_b = witness.record.call_args[0][0]
        assert record_b.model_id == "model-b"

        # End run_a
        resp2 = MagicMock()
        gen2 = MagicMock()
        gen2.text = "response a"
        gen2.message = None
        resp2.generations = [[gen2]]
        resp2.llm_output = {}
        handler.on_llm_end(resp2, run_id=run_a)

        assert len(handler._runs) == 0

    def test_callback_properties(self):
        """Verify callback interface properties are set correctly."""
        handler = SWT3CallbackHandler(_mock_witness())
        assert handler.raise_on_llm_error is False
        assert handler.ignore_llm is False
        assert handler.ignore_chain is True
        assert handler.ignore_agent is True
        assert handler.ignore_retriever is False  # auto-witnesses RAG retrievals


# ---------------------------------------------------------------------------
# LangChain: extraction helpers
# ---------------------------------------------------------------------------

class TestLangChainExtraction:
    def test_model_name_from_invocation_params(self):
        name = _extract_model_name(
            {"id": []},
            {"invocation_params": {"model_name": "gpt-4o-mini"}},
        )
        assert name == "gpt-4o-mini"

    def test_model_name_from_serialized_kwargs(self):
        name = _extract_model_name(
            {"kwargs": {"model": "claude-3-opus"}, "id": []},
            {},
        )
        assert name == "claude-3-opus"

    def test_model_name_from_serialized_id(self):
        name = _extract_model_name(
            {"id": ["langchain_openai", "ChatOpenAI"]},
            {},
        )
        assert name == "ChatOpenAI"

    def test_model_name_fallback(self):
        name = _extract_model_name({}, {})
        assert name == "unknown"

    def test_chat_texts_extraction(self):
        msgs = [
            [
                {"type": "system", "content": "Be helpful"},
                {"type": "human", "content": "Hello"},
            ]
        ]
        prompt, system = _extract_chat_texts(msgs)
        assert "Hello" in prompt
        assert system is not None
        assert "Be helpful" in system

    def test_chat_texts_no_system(self):
        msgs = [[{"type": "human", "content": "Hello"}]]
        prompt, system = _extract_chat_texts(msgs)
        assert "Hello" in prompt
        assert system is None

    def test_llm_result_extraction(self):
        resp = MagicMock()
        gen = MagicMock()
        gen.message = MagicMock(content="Answer text")
        resp.generations = [[gen]]
        resp.llm_output = {"token_usage": {"prompt_tokens": 5, "completion_tokens": 3}}

        text, in_tok, out_tok = _extract_llm_result(resp)
        assert text == "Answer text"
        assert in_tok == 5
        assert out_tok == 3

    def test_llm_result_text_generation(self):
        """Generation with .text (not .message) -- old-style LLMs."""
        resp = MagicMock()
        gen = MagicMock()
        gen.message = None
        gen.text = "Plain text output"
        resp.generations = [[gen]]
        resp.llm_output = {}

        text, in_tok, out_tok = _extract_llm_result(resp)
        assert text == "Plain text output"
        assert in_tok is None

    def test_llm_result_empty(self):
        resp = MagicMock()
        resp.generations = []
        resp.llm_output = None
        text, in_tok, out_tok = _extract_llm_result(resp)
        assert text == ""


# ---------------------------------------------------------------------------
# Fingerprint parity: same prompt produces same hash across adapters
# ---------------------------------------------------------------------------

class TestFingerprintParity:
    def test_same_prompt_same_hash(self):
        """Ollama and vLLM produce identical prompt hashes for the same input."""
        witness = _mock_witness()
        messages = [{"role": "user", "content": "What is 2+2?"}]

        client_a, _ = _mock_openai_client("http://localhost:11434/v1")
        proxy_a = wrap_ollama(client_a, witness)
        proxy_a.chat.completions.create(model="llama3", messages=messages)
        hash_a = witness.record.call_args[0][0].prompt_hash

        witness.reset_mock()

        client_b, _ = _mock_openai_client("http://localhost:8000/v1")
        proxy_b = wrap_vllm(client_b, witness)
        proxy_b.chat.completions.create(model="llama3", messages=messages)
        hash_b = witness.record.call_args[0][0].prompt_hash

        assert hash_a == hash_b
        assert len(hash_a) == 16

    def test_langchain_same_hash(self):
        """LangChain callback produces the same prompt hash for the same text."""
        from swt3_ai.fingerprint import sha256_truncated

        prompt = "What is 2+2?"
        expected = sha256_truncated(prompt)

        witness = _mock_witness()
        handler = SWT3CallbackHandler(witness)
        run_id = uuid.uuid4()

        handler.on_llm_start(
            serialized={"id": ["test"]},
            prompts=[prompt],
            run_id=run_id,
        )

        resp = MagicMock()
        gen = MagicMock()
        gen.text = "4"
        gen.message = None
        resp.generations = [[gen]]
        resp.llm_output = {}
        handler.on_llm_end(resp, run_id=run_id)

        record = witness.record.call_args[0][0]
        assert record.prompt_hash == expected
