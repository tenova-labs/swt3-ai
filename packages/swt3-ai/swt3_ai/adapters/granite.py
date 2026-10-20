"""SWT3 AI Witness SDK -- IBM Granite Adapter.

Wraps the ibm-watsonx-ai ModelInference class to witness inference calls.
Intercepts generate(), generate_text(), and generate_text_stream() methods,
minting anchors for each completion.

Usage:
    from swt3_ai.adapters.granite import wrap_granite

    witness = Witness(endpoint="...", api_key="...", tenant_id="...")
    model = ModelInference(model_id="ibm/granite-3-8b-instruct", ...)
    witnessed = wrap_granite(model, witness)

    response = witnessed.generate(prompt="Summarize this document.")

For Granite models served via Ollama or vLLM, use the existing OpenAI
or vLLM adapters instead -- they handle OpenAI-compatible endpoints.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, TYPE_CHECKING

from ..types import InferenceRecord
from ..fingerprint import sha256_truncated

if TYPE_CHECKING:
    from ..witness import Witness


def wrap_granite(client: Any, witness: "Witness") -> "_GraniteProxy":
    """Wrap an ibm-watsonx-ai ModelInference with transparent witnessing.

    Intercepts generate(), generate_text(), and generate_text_stream().
    """
    return _GraniteProxy(client, witness)


class _GraniteProxy:
    """Proxy for IBM watsonx ModelInference.

    The watsonx API is flat: model.generate(), model.generate_text(),
    model.generate_text_stream(). One level of proxy is sufficient.
    """

    __slots__ = ("_target", "_witness")

    def __init__(self, target: Any, witness: "Witness") -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")
        real_attr = getattr(target, name)

        if name == "generate":
            if asyncio.iscoroutinefunction(real_attr):
                return _make_async_generate_interceptor(real_attr, witness, target)
            return _make_generate_interceptor(real_attr, witness, target)

        if name == "generate_text":
            if asyncio.iscoroutinefunction(real_attr):
                return _make_async_generate_text_interceptor(real_attr, witness, target)
            return _make_generate_text_interceptor(real_attr, witness, target)

        if name == "generate_text_stream":
            if asyncio.iscoroutinefunction(real_attr):
                return _make_async_stream_interceptor(real_attr, witness, target)
            return _make_stream_interceptor(real_attr, witness, target)

        return real_attr

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"<WitnessProxy({type(target).__name__})>"


# -- generate() interceptors --


def _make_generate_interceptor(real_method: Any, witness: "Witness", target: Any) -> Any:
    """Intercept ModelInference.generate() (returns dict)."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        prompt = kwargs.get("prompt", args[0] if args else "")
        prompt_hash = sha256_truncated(prompt if isinstance(prompt, str) else str(prompt))

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(prompt, _get_model_id(target))

        start = time.monotonic()
        response = real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        record = _extract_record(response, _get_model_id(target), prompt_hash, elapsed_ms)
        witness.record(record, authorization_id=authorization_id)

        return response

    interceptor.__name__ = "generate"
    interceptor.__qualname__ = "ModelInference.generate"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _make_async_generate_interceptor(real_method: Any, witness: "Witness", target: Any) -> Any:
    """Intercept async ModelInference.generate()."""

    async def interceptor(*args: Any, **kwargs: Any) -> Any:
        prompt = kwargs.get("prompt", args[0] if args else "")
        prompt_hash = sha256_truncated(prompt if isinstance(prompt, str) else str(prompt))

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(prompt, _get_model_id(target))

        start = time.monotonic()
        response = await real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        record = _extract_record(response, _get_model_id(target), prompt_hash, elapsed_ms)
        witness.record(record, authorization_id=authorization_id)

        return response

    interceptor.__name__ = "generate"
    interceptor.__qualname__ = "ModelInference.generate"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


# -- generate_text() interceptors --


def _make_generate_text_interceptor(real_method: Any, witness: "Witness", target: Any) -> Any:
    """Intercept ModelInference.generate_text() (returns bare string)."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        prompt = kwargs.get("prompt", args[0] if args else "")
        prompt_hash = sha256_truncated(prompt if isinstance(prompt, str) else str(prompt))

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(prompt, _get_model_id(target))

        start = time.monotonic()
        response_text = real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        model_id = _get_model_id(target)
        record = InferenceRecord(
            model_id=model_id,
            model_hash=sha256_truncated(model_id),
            prompt_hash=prompt_hash,
            response_hash=sha256_truncated(response_text if isinstance(response_text, str) else ""),
            latency_ms=elapsed_ms,
            input_tokens=None,
            output_tokens=None,
            has_refusal=False,
            provider="ibm-watsonx",
        )
        witness.record(record, authorization_id=authorization_id)

        return response_text

    interceptor.__name__ = "generate_text"
    interceptor.__qualname__ = "ModelInference.generate_text"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _make_async_generate_text_interceptor(real_method: Any, witness: "Witness", target: Any) -> Any:
    """Intercept async ModelInference.generate_text()."""

    async def interceptor(*args: Any, **kwargs: Any) -> Any:
        prompt = kwargs.get("prompt", args[0] if args else "")
        prompt_hash = sha256_truncated(prompt if isinstance(prompt, str) else str(prompt))

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(prompt, _get_model_id(target))

        start = time.monotonic()
        response_text = await real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        model_id = _get_model_id(target)
        record = InferenceRecord(
            model_id=model_id,
            model_hash=sha256_truncated(model_id),
            prompt_hash=prompt_hash,
            response_hash=sha256_truncated(response_text if isinstance(response_text, str) else ""),
            latency_ms=elapsed_ms,
            input_tokens=None,
            output_tokens=None,
            has_refusal=False,
            provider="ibm-watsonx",
        )
        witness.record(record, authorization_id=authorization_id)

        return response_text

    interceptor.__name__ = "generate_text"
    interceptor.__qualname__ = "ModelInference.generate_text"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


# -- generate_text_stream() interceptors --


def _make_stream_interceptor(real_method: Any, witness: "Witness", target: Any) -> Any:
    """Intercept ModelInference.generate_text_stream() (returns generator)."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        prompt = kwargs.get("prompt", args[0] if args else "")
        prompt_hash = sha256_truncated(prompt if isinstance(prompt, str) else str(prompt))

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(prompt, _get_model_id(target))

        start = time.monotonic()
        stream = real_method(*args, **kwargs)

        return _StreamAccumulator(
            stream, witness, _get_model_id(target), prompt_hash, start,
            authorization_id,
        )

    interceptor.__name__ = "generate_text_stream"
    interceptor.__qualname__ = "ModelInference.generate_text_stream"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _make_async_stream_interceptor(real_method: Any, witness: "Witness", target: Any) -> Any:
    """Intercept async ModelInference.generate_text_stream()."""

    async def interceptor(*args: Any, **kwargs: Any) -> Any:
        prompt = kwargs.get("prompt", args[0] if args else "")
        prompt_hash = sha256_truncated(prompt if isinstance(prompt, str) else str(prompt))

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(prompt, _get_model_id(target))

        start = time.monotonic()
        stream = await real_method(*args, **kwargs)

        return _AsyncStreamAccumulator(
            stream, witness, _get_model_id(target), prompt_hash, start,
            authorization_id,
        )

    interceptor.__name__ = "generate_text_stream"
    interceptor.__qualname__ = "ModelInference.generate_text_stream"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


# -- Stream Accumulators --


class _StreamAccumulator:
    """Wraps a sync watsonx stream. Accumulates text and witnesses on completion.

    generate_text_stream() yields plain text strings (not structured events).
    """

    def __init__(
        self,
        stream: Any,
        witness: "Witness",
        model: str,
        prompt_hash: str,
        start_time: float,
        authorization_id: str | None,
    ) -> None:
        self._stream = stream
        self._witness = witness
        self._model = model
        self._prompt_hash = prompt_hash
        self._start_time = start_time
        self._authorization_id = authorization_id
        self._text_parts: list[str] = []
        self._witnessed = False

    def __iter__(self) -> "_StreamAccumulator":
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._stream)
            if isinstance(chunk, str):
                self._text_parts.append(chunk)
            return chunk
        except StopIteration:
            self._witness_completion()
            raise

    def __enter__(self) -> "_StreamAccumulator":
        if hasattr(self._stream, "__enter__"):
            self._stream.__enter__()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._witness_completion()
        if hasattr(self._stream, "__exit__"):
            self._stream.__exit__(*exc)

    def __del__(self) -> None:
        self._witness_completion()

    def _witness_completion(self) -> None:
        if self._witnessed:
            return
        self._witnessed = True

        elapsed_ms = int((time.monotonic() - self._start_time) * 1000)
        response_text = "".join(self._text_parts)

        record = InferenceRecord(
            model_id=self._model,
            model_hash=sha256_truncated(self._model),
            prompt_hash=self._prompt_hash,
            response_hash=sha256_truncated(response_text),
            latency_ms=elapsed_ms,
            input_tokens=None,
            output_tokens=None,
            has_refusal=False,
            provider="ibm-watsonx",
        )
        self._witness.record(record, authorization_id=self._authorization_id)


class _AsyncStreamAccumulator:
    """Wraps an async watsonx stream. Accumulates text and witnesses on completion."""

    def __init__(
        self,
        stream: Any,
        witness: "Witness",
        model: str,
        prompt_hash: str,
        start_time: float,
        authorization_id: str | None,
    ) -> None:
        self._stream = stream
        self._witness = witness
        self._model = model
        self._prompt_hash = prompt_hash
        self._start_time = start_time
        self._authorization_id = authorization_id
        self._text_parts: list[str] = []
        self._witnessed = False

    def __aiter__(self) -> "_AsyncStreamAccumulator":
        return self

    async def __anext__(self) -> Any:
        try:
            chunk = await self._stream.__anext__()
            if isinstance(chunk, str):
                self._text_parts.append(chunk)
            return chunk
        except StopAsyncIteration:
            self._witness_completion()
            raise

    async def __aenter__(self) -> "_AsyncStreamAccumulator":
        if hasattr(self._stream, "__aenter__"):
            await self._stream.__aenter__()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self._witness_completion()
        if hasattr(self._stream, "__aexit__"):
            await self._stream.__aexit__(*exc)

    def __del__(self) -> None:
        self._witness_completion()

    def _witness_completion(self) -> None:
        if self._witnessed:
            return
        self._witnessed = True

        elapsed_ms = int((time.monotonic() - self._start_time) * 1000)
        response_text = "".join(self._text_parts)

        record = InferenceRecord(
            model_id=self._model,
            model_hash=sha256_truncated(self._model),
            prompt_hash=self._prompt_hash,
            response_hash=sha256_truncated(response_text),
            latency_ms=elapsed_ms,
            input_tokens=None,
            output_tokens=None,
            has_refusal=False,
            provider="ibm-watsonx",
        )
        self._witness.record(record, authorization_id=self._authorization_id)


# -- Extraction helpers --


def _get_model_id(target: Any) -> str:
    """Extract model_id from a ModelInference instance."""
    model_id = getattr(target, "model_id", None)
    if model_id:
        return model_id
    model_id = getattr(target, "model", None)
    if model_id:
        return model_id
    return "unknown"


def _extract_record(
    response: Any,
    model: str,
    prompt_hash: str,
    elapsed_ms: int,
) -> InferenceRecord:
    """Extract an InferenceRecord from a watsonx generate() response.

    watsonx generate() returns a dict:
        {"model_id": "...", "results": [{"generated_text": "...",
         "generated_token_count": N, "input_token_count": N,
         "stop_reason": "eos_token|max_tokens|stop_sequence"}]}
    """
    response_text = ""
    input_tokens = None
    output_tokens = None
    has_refusal = False

    if isinstance(response, dict):
        actual_model = response.get("model_id", model) or model

        results = response.get("results", [])
        if results and isinstance(results, list):
            first = results[0]
            if isinstance(first, dict):
                response_text = first.get("generated_text", "")
                output_tokens = first.get("generated_token_count")
                input_tokens = first.get("input_token_count")
                stop_reason = first.get("stop_reason", "")
                if stop_reason not in ("eos_token", "max_tokens", "stop_sequence", "not_finished"):
                    has_refusal = True
    else:
        actual_model = model

    return InferenceRecord(
        model_id=actual_model,
        model_hash=sha256_truncated(actual_model),
        prompt_hash=prompt_hash,
        response_hash=sha256_truncated(response_text) if response_text else sha256_truncated(""),
        latency_ms=elapsed_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        has_refusal=has_refusal,
        provider="ibm-watsonx",
    )
