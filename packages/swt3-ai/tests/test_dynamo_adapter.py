"""Tests for SWT3 Dynamo Adapter (Layer 1).

Pure Python -- no GPU, no Dynamo install required.
Uses plain async generators as mock endpoints.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import MagicMock, patch

import pytest

from swt3_ai.adapters.dynamo import (
    _parse_dsn,
    _extract_request,
    _accumulate_chunks,
    _find_request,
    witness_endpoint,
)


# ---------------------------------------------------------------------------
# DSN Parsing
# ---------------------------------------------------------------------------

class TestParseDsn:
    def test_valid_dsn(self):
        endpoint, key, tenant = _parse_dsn(
            "https://axm_live_abc123@sovereign.tenova.io/MY_ENCLAVE"
        )
        assert endpoint == "https://sovereign.tenova.io"
        assert key == "axm_live_abc123"
        assert tenant == "MY_ENCLAVE"

    def test_dsn_with_port(self):
        endpoint, key, tenant = _parse_dsn(
            "https://axm_live_xyz@localhost:3000/TEST_TENANT"
        )
        assert endpoint == "https://localhost:3000"
        assert key == "axm_live_xyz"
        assert tenant == "TEST_TENANT"

    def test_dsn_missing_key(self):
        endpoint, key, tenant = _parse_dsn(
            "https://sovereign.tenova.io/MY_ENCLAVE"
        )
        assert key == ""

    def test_dsn_missing_tenant(self):
        endpoint, key, tenant = _parse_dsn(
            "https://axm_live_abc@sovereign.tenova.io/"
        )
        assert tenant == ""

    def test_dsn_empty(self):
        endpoint, key, tenant = _parse_dsn("")
        assert key == ""
        assert tenant == ""


# ---------------------------------------------------------------------------
# Request Extraction
# ---------------------------------------------------------------------------

class TestExtractRequest:
    def test_dict_request(self):
        request = {
            "model": "llama-3-70b",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello world"},
            ],
        }
        model_id, prompt_hash, sys_hash = _extract_request(request)
        assert model_id == "llama-3-70b"
        assert len(prompt_hash) == 16
        assert sys_hash is not None
        assert len(sys_hash) == 16

    def test_object_request(self):
        request = MagicMock()
        request.model = "gpt-4o"
        request.messages = [
            MagicMock(role="user", content="test prompt"),
        ]
        model_id, prompt_hash, sys_hash = _extract_request(request)
        assert model_id == "gpt-4o"
        assert len(prompt_hash) == 16
        assert sys_hash is None  # no system message

    def test_empty_request(self):
        model_id, prompt_hash, sys_hash = _extract_request({})
        assert model_id == "unknown"
        assert len(prompt_hash) == 16
        assert sys_hash is None

    def test_multimodal_content(self):
        request = {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Describe this image"},
                        {"type": "image_url", "url": "data:image/png;..."},
                    ],
                }
            ],
        }
        model_id, prompt_hash, _ = _extract_request(request)
        assert model_id == "gpt-4o"
        assert len(prompt_hash) == 16


# ---------------------------------------------------------------------------
# Chunk Accumulation
# ---------------------------------------------------------------------------

class TestAccumulateChunks:
    def test_dict_chunks(self):
        chunks = [
            {"choices": [{"delta": {"content": "Hello"}}]},
            {"choices": [{"delta": {"content": " world"}}]},
            {
                "choices": [{"delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2},
            },
        ]
        resp_hash, in_tok, out_tok, refusal = _accumulate_chunks(chunks)
        assert len(resp_hash) == 16
        assert in_tok == 10
        assert out_tok == 2
        assert refusal is False

    def test_content_filter_refusal(self):
        chunks = [
            {"choices": [{"delta": {"content": ""}, "finish_reason": "content_filter"}]},
        ]
        _, _, _, refusal = _accumulate_chunks(chunks)
        assert refusal is True

    def test_empty_chunks(self):
        resp_hash, in_tok, out_tok, refusal = _accumulate_chunks([])
        assert len(resp_hash) == 16  # hash of empty string
        assert in_tok is None
        assert out_tok is None
        assert refusal is False

    def test_object_chunks(self):
        chunk = MagicMock()
        choice = MagicMock()
        choice.delta = MagicMock(content="test")
        choice.finish_reason = "stop"
        chunk.choices = [choice]
        chunk.usage = MagicMock(prompt_tokens=5, completion_tokens=1)

        resp_hash, in_tok, out_tok, refusal = _accumulate_chunks([chunk])
        assert len(resp_hash) == 16
        assert in_tok == 5
        assert out_tok == 1


# ---------------------------------------------------------------------------
# Find Request
# ---------------------------------------------------------------------------

class TestFindRequest:
    def test_kwargs(self):
        req = {"model": "test"}
        result = _find_request((), {"request": req})
        assert result is req

    def test_positional_with_self(self):
        self_obj = object()
        req = {"model": "test", "messages": []}
        result = _find_request((self_obj, req), {})
        assert result is req

    def test_positional_direct(self):
        req = {"model": "test"}
        result = _find_request((req,), {})
        assert result is req

    def test_empty(self):
        result = _find_request((), {})
        assert result == {}


# ---------------------------------------------------------------------------
# Decorator Behavior
# ---------------------------------------------------------------------------

class TestWitnessEndpointDecorator:
    def test_noop_when_unconfigured(self):
        """Decorator passes through when no SWT3 config is set."""
        with patch.dict(os.environ, {}, clear=True):
            # Reset the module-level warning flag
            import swt3_ai.adapters.dynamo as mod
            mod._warned_unconfigured = False

            @witness_endpoint()
            async def generate(request):
                yield {"choices": [{"delta": {"content": "hello"}}]}

            async def run():
                chunks = []
                req = {"model": "test", "messages": []}
                async for chunk in generate(req):
                    chunks.append(chunk)
                return chunks

            result = asyncio.run(run())
            assert len(result) == 1
            assert result[0]["choices"][0]["delta"]["content"] == "hello"

    def test_chunks_pass_through_untouched(self):
        """All chunks arrive in order and unmodified."""
        with patch.dict(os.environ, {}, clear=True):
            import swt3_ai.adapters.dynamo as mod
            mod._warned_unconfigured = False

            @witness_endpoint()
            async def generate(request):
                for i in range(5):
                    yield {"id": i, "choices": [{"delta": {"content": str(i)}}]}

            async def run():
                chunks = []
                req = {"model": "test", "messages": []}
                async for chunk in generate(req):
                    chunks.append(chunk)
                return chunks

            result = asyncio.run(run())
            assert len(result) == 5
            for i, chunk in enumerate(result):
                assert chunk["id"] == i

    def test_explicit_witness_takes_precedence(self):
        """Explicit Witness instance overrides env vars."""
        mock_witness = MagicMock()
        mock_witness.config = MagicMock(clearing_level=2)

        @witness_endpoint(witness=mock_witness)
        async def generate(request):
            yield {"choices": [{"delta": {"content": "test"}}]}

        async def run():
            req = {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}
            async for _ in generate(req):
                pass

        asyncio.run(run())
        # Witness.record() should have been called
        assert mock_witness.record.called

    def test_record_called_with_correct_provider(self):
        """InferenceRecord has provider='nvidia-dynamo'."""
        mock_witness = MagicMock()
        mock_witness.config = MagicMock(clearing_level=1)

        @witness_endpoint(witness=mock_witness)
        async def generate(request):
            yield {"choices": [{"delta": {"content": "response"}}]}

        async def run():
            req = {"model": "llama-3", "messages": [{"role": "user", "content": "q"}]}
            async for _ in generate(req):
                pass

        asyncio.run(run())
        call_args = mock_witness.record.call_args
        record = call_args[0][0]
        assert record.provider == "nvidia-dynamo"
        assert record.model_id == "llama-3"
        assert record.latency_ms >= 0

    def test_decorator_order_agnostic(self):
        """Works when stacked with other decorators."""
        def other_decorator(fn):
            """Simulates @dynamo_endpoint()."""
            return fn

        with patch.dict(os.environ, {}, clear=True):
            import swt3_ai.adapters.dynamo as mod
            mod._warned_unconfigured = False

            # witness_endpoint below other decorator
            @other_decorator
            @witness_endpoint()
            async def generate_a(request):
                yield {"choices": [{"delta": {"content": "a"}}]}

            # witness_endpoint above other decorator
            @witness_endpoint()
            @other_decorator
            async def generate_b(request):
                yield {"choices": [{"delta": {"content": "b"}}]}

            async def run():
                req = {"model": "test", "messages": []}
                chunks_a = [c async for c in generate_a(req)]
                chunks_b = [c async for c in generate_b(req)]
                return chunks_a, chunks_b

            a, b = asyncio.run(run())
            assert len(a) == 1
            assert len(b) == 1

    def test_dsn_env_creates_witness(self):
        """SWT3_DSN env var triggers Witness creation."""
        env = {"SWT3_DSN": "https://axm_test_key@localhost:9999/TEST"}

        with patch.dict(os.environ, env, clear=True):
            import swt3_ai.adapters.dynamo as mod
            mod._warned_unconfigured = False

            # Patch Witness constructor to avoid network
            with patch("swt3_ai.adapters.dynamo._create_witness") as mock_create:
                mock_w = MagicMock()
                mock_w.config = MagicMock(clearing_level=1)
                mock_create.return_value = mock_w

                @witness_endpoint()
                async def generate(request):
                    yield {"choices": [{"delta": {"content": "ok"}}]}

                async def run():
                    req = {"model": "test", "messages": []}
                    async for _ in generate(req):
                        pass

                asyncio.run(run())
                mock_create.assert_called_once()

    def test_individual_env_vars_fallback(self):
        """Individual env vars work when SWT3_DSN is not set."""
        env = {
            "SWT3_ENDPOINT": "https://localhost:9999",
            "SWT3_API_KEY": "axm_test_key",
            "SWT3_TENANT_ID": "TEST",
        }

        with patch.dict(os.environ, env, clear=True):
            import swt3_ai.adapters.dynamo as mod
            mod._warned_unconfigured = False

            with patch("swt3_ai.adapters.dynamo._create_witness") as mock_create:
                mock_w = MagicMock()
                mock_w.config = MagicMock(clearing_level=1)
                mock_create.return_value = mock_w

                @witness_endpoint()
                async def generate(request):
                    yield {"choices": [{"delta": {"content": "ok"}}]}

                async def run():
                    req = {"model": "test", "messages": []}
                    async for _ in generate(req):
                        pass

                asyncio.run(run())
                mock_create.assert_called_once()


# ---------------------------------------------------------------------------
# Non-async-generator handling
# ---------------------------------------------------------------------------

class TestNonAsyncGenerator:
    def test_coroutine_passthrough(self):
        """Coroutine functions (not async generators) pass through."""
        @witness_endpoint()
        async def my_coroutine(request):
            return {"result": "ok"}

        async def run():
            return await my_coroutine({"model": "test"})

        result = asyncio.run(run())
        assert result == {"result": "ok"}

    def test_regular_function_passthrough(self):
        """Regular functions pass through unmodified."""
        @witness_endpoint()
        def my_func(x):
            return x * 2

        assert my_func(5) == 10
