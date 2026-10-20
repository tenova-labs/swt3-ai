"""SWT3 AI Witness SDK -- Mistral Adapter.

Wraps the Mistral Python SDK to witness inference calls. Intercepts
chat.complete(), chat.stream(), and chat.complete_async() methods,
minting anchors for each completion.

Usage:
    from swt3_ai.adapters.mistral import wrap_mistral

    witness = Witness(endpoint="...", api_key="...", tenant_id="...")
    client = Mistral(api_key="...")
    witnessed = wrap_mistral(client, witness)

    response = witnessed.chat.complete(
        model="mistral-large-latest",
        messages=[{"role": "user", "content": "Hello"}],
    )

Works with both Mistral (sync) and async usage. Duck-typed -- zero
mistralai import at runtime.

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


def wrap_mistral(client: Any, witness: "Witness") -> "_MistralProxy":
    """Wrap a Mistral client with transparent witnessing.

    Intercepts client.chat.complete(), client.chat.stream(),
    and client.chat.complete_async() calls.
    """
    return _MistralProxy(client, witness)


class _MistralProxy:
    """Proxy for the Mistral client.

    Mistral's API is two levels deep: client.chat.complete()
    So we intercept .chat to return a _ChatProxy.
    """

    __slots__ = ("_target", "_witness")

    def __init__(self, target: Any, witness: "Witness") -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")
        real_attr = getattr(target, name)

        if name == "chat":
            return _ChatProxy(real_attr, witness)

        return real_attr

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"<WitnessProxy({type(target).__name__})>"


class _ChatProxy:
    """Proxy for client.chat -- intercepts complete, stream, complete_async."""

    __slots__ = ("_target", "_witness")

    def __init__(self, target: Any, witness: "Witness") -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")
        real_attr = getattr(target, name)

        if name == "complete":
            if asyncio.iscoroutinefunction(real_attr):
                return _make_async_complete_interceptor(real_attr, witness)
            return _make_complete_interceptor(real_attr, witness)

        if name == "complete_async":
            return _make_async_complete_interceptor(real_attr, witness)

        if name == "stream":
            if asyncio.iscoroutinefunction(real_attr):
                return _make_async_stream_interceptor(real_attr, witness)
            return _make_stream_interceptor(real_attr, witness)

        if name == "stream_async":
            return _make_async_stream_interceptor(real_attr, witness)

        return real_attr


# -- complete() interceptors --


def _make_complete_interceptor(real_method: Any, witness: "Witness") -> Any:
    """Create a sync interceptor for chat.complete()."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", args[0] if args else [])
        model = kwargs.get("model", "unknown")

        prompt_text = _extract_prompt_text(messages)
        prompt_hash = sha256_truncated(prompt_text)

        system_prompt_text = _extract_system_prompt(messages)
        system_prompt_hash = sha256_truncated(system_prompt_text) if system_prompt_text else None

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(messages, model)

        start = time.monotonic()
        response = real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        record = _extract_record(response, model, prompt_hash, elapsed_ms, system_prompt_hash)
        witness.record(record, authorization_id=authorization_id)

        return response

    interceptor.__name__ = "complete"
    interceptor.__qualname__ = "Chat.complete"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _make_async_complete_interceptor(real_method: Any, witness: "Witness") -> Any:
    """Create an async interceptor for chat.complete_async()."""

    async def interceptor(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", args[0] if args else [])
        model = kwargs.get("model", "unknown")

        prompt_text = _extract_prompt_text(messages)
        prompt_hash = sha256_truncated(prompt_text)

        system_prompt_text = _extract_system_prompt(messages)
        system_prompt_hash = sha256_truncated(system_prompt_text) if system_prompt_text else None

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(messages, model)

        start = time.monotonic()
        response = await real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        record = _extract_record(response, model, prompt_hash, elapsed_ms, system_prompt_hash)
        witness.record(record, authorization_id=authorization_id)

        return response

    interceptor.__name__ = "complete_async"
    interceptor.__qualname__ = "Chat.complete_async"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


# -- stream() interceptors --


def _make_stream_interceptor(real_method: Any, witness: "Witness") -> Any:
    """Create a sync interceptor for chat.stream()."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", args[0] if args else [])
        model = kwargs.get("model", "unknown")

        prompt_text = _extract_prompt_text(messages)
        prompt_hash = sha256_truncated(prompt_text)

        system_prompt_text = _extract_system_prompt(messages)
        system_prompt_hash = sha256_truncated(system_prompt_text) if system_prompt_text else None

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(messages, model)

        start = time.monotonic()
        stream = real_method(*args, **kwargs)

        return _StreamAccumulator(
            stream, witness, model, prompt_hash, start,
            system_prompt_hash, authorization_id,
        )

    interceptor.__name__ = "stream"
    interceptor.__qualname__ = "Chat.stream"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _make_async_stream_interceptor(real_method: Any, witness: "Witness") -> Any:
    """Create an async interceptor for chat.stream_async()."""

    async def interceptor(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", args[0] if args else [])
        model = kwargs.get("model", "unknown")

        prompt_text = _extract_prompt_text(messages)
        prompt_hash = sha256_truncated(prompt_text)

        system_prompt_text = _extract_system_prompt(messages)
        system_prompt_hash = sha256_truncated(system_prompt_text) if system_prompt_text else None

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(messages, model)

        start = time.monotonic()
        stream = await real_method(*args, **kwargs)

        return _AsyncStreamAccumulator(
            stream, witness, model, prompt_hash, start,
            system_prompt_hash, authorization_id,
        )

    interceptor.__name__ = "stream_async"
    interceptor.__qualname__ = "Chat.stream_async"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


# -- Stream Accumulators --


class _StreamAccumulator:
    """Wraps a sync Mistral stream. Accumulates text and witnesses on completion.

    Mistral chat.stream() yields CompletionChunk objects with:
        chunk.data.choices[0].delta.content  (text fragment)
    The .data wrapper may or may not exist depending on SDK version.
    """

    def __init__(
        self,
        stream: Any,
        witness: "Witness",
        model: str,
        prompt_hash: str,
        start_time: float,
        system_prompt_hash: str | None,
        authorization_id: str | None,
    ) -> None:
        self._stream = stream
        self._witness = witness
        self._model = model
        self._prompt_hash = prompt_hash
        self._start_time = start_time
        self._system_prompt_hash = system_prompt_hash
        self._authorization_id = authorization_id
        self._text_parts: list[str] = []
        self._actual_model = model
        self._input_tokens: int | None = None
        self._output_tokens: int | None = None
        self._finish_reason: str | None = None
        self._witnessed = False

    def __iter__(self) -> "_StreamAccumulator":
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._stream)
            self._accumulate(chunk)
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

    def _accumulate(self, chunk: Any) -> None:
        """Extract data from a Mistral stream chunk.

        Handles both wrapped (chunk.data.choices) and unwrapped
        (chunk.choices) formats across SDK versions.
        """
        data = getattr(chunk, "data", chunk)

        choices = getattr(data, "choices", None)
        if choices and len(choices) > 0:
            choice = choices[0]
            delta = getattr(choice, "delta", None)
            if delta is not None:
                content = getattr(delta, "content", None)
                if isinstance(content, str) and content:
                    self._text_parts.append(content)

            fr = getattr(choice, "finish_reason", None)
            if fr is not None:
                self._finish_reason = str(fr)

        model = getattr(data, "model", None)
        if model:
            self._actual_model = model

        usage = getattr(data, "usage", None)
        if usage is not None:
            pt = getattr(usage, "prompt_tokens", None)
            ct = getattr(usage, "completion_tokens", None)
            if pt is not None:
                self._input_tokens = pt
            if ct is not None:
                self._output_tokens = ct

    def _witness_completion(self) -> None:
        if self._witnessed:
            return
        self._witnessed = True

        elapsed_ms = int((time.monotonic() - self._start_time) * 1000)
        response_text = "".join(self._text_parts)

        has_refusal = self._finish_reason is not None and self._finish_reason not in (
            "stop", "length", "model_length", "tool_calls",
        )

        record = InferenceRecord(
            model_id=self._actual_model,
            model_hash=sha256_truncated(self._actual_model),
            prompt_hash=self._prompt_hash,
            response_hash=sha256_truncated(response_text),
            latency_ms=elapsed_ms,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            has_refusal=has_refusal,
            provider="mistral",
            system_prompt_hash=self._system_prompt_hash,
        )
        self._witness.record(record, authorization_id=self._authorization_id)


class _AsyncStreamAccumulator:
    """Wraps an async Mistral stream. Accumulates text and witnesses on completion."""

    def __init__(
        self,
        stream: Any,
        witness: "Witness",
        model: str,
        prompt_hash: str,
        start_time: float,
        system_prompt_hash: str | None,
        authorization_id: str | None,
    ) -> None:
        self._stream = stream
        self._witness = witness
        self._model = model
        self._prompt_hash = prompt_hash
        self._start_time = start_time
        self._system_prompt_hash = system_prompt_hash
        self._authorization_id = authorization_id
        self._text_parts: list[str] = []
        self._actual_model = model
        self._input_tokens: int | None = None
        self._output_tokens: int | None = None
        self._finish_reason: str | None = None
        self._witnessed = False

    def __aiter__(self) -> "_AsyncStreamAccumulator":
        return self

    async def __anext__(self) -> Any:
        try:
            chunk = await self._stream.__anext__()
            self._accumulate(chunk)
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

    def _accumulate(self, chunk: Any) -> None:
        """Extract data from a Mistral stream chunk (same logic as sync)."""
        data = getattr(chunk, "data", chunk)

        choices = getattr(data, "choices", None)
        if choices and len(choices) > 0:
            choice = choices[0]
            delta = getattr(choice, "delta", None)
            if delta is not None:
                content = getattr(delta, "content", None)
                if isinstance(content, str) and content:
                    self._text_parts.append(content)

            fr = getattr(choice, "finish_reason", None)
            if fr is not None:
                self._finish_reason = str(fr)

        model = getattr(data, "model", None)
        if model:
            self._actual_model = model

        usage = getattr(data, "usage", None)
        if usage is not None:
            pt = getattr(usage, "prompt_tokens", None)
            ct = getattr(usage, "completion_tokens", None)
            if pt is not None:
                self._input_tokens = pt
            if ct is not None:
                self._output_tokens = ct

    def _witness_completion(self) -> None:
        if self._witnessed:
            return
        self._witnessed = True

        elapsed_ms = int((time.monotonic() - self._start_time) * 1000)
        response_text = "".join(self._text_parts)

        has_refusal = self._finish_reason is not None and self._finish_reason not in (
            "stop", "length", "model_length", "tool_calls",
        )

        record = InferenceRecord(
            model_id=self._actual_model,
            model_hash=sha256_truncated(self._actual_model),
            prompt_hash=self._prompt_hash,
            response_hash=sha256_truncated(response_text),
            latency_ms=elapsed_ms,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            has_refusal=has_refusal,
            provider="mistral",
            system_prompt_hash=self._system_prompt_hash,
        )
        self._witness.record(record, authorization_id=self._authorization_id)


# -- Extraction helpers --


def _extract_prompt_text(messages: Any) -> str:
    """Extract hashable text from Mistral message format.

    Mistral uses OpenAI-style messages:
        [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]
    """
    parts: list[str] = []

    if isinstance(messages, (list, tuple)):
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict):
                            text = block.get("text", "")
                            if text:
                                parts.append(text)
            elif hasattr(msg, "content"):
                c = getattr(msg, "content", "")
                if isinstance(c, str):
                    parts.append(c)

    return "\n".join(parts)


def _extract_system_prompt(messages: Any) -> str | None:
    """Extract system prompt text from the messages list."""
    if isinstance(messages, (list, tuple)):
        for msg in messages:
            role = None
            content = ""
            if isinstance(msg, dict):
                role = msg.get("role", "")
                content = msg.get("content", "")
            elif hasattr(msg, "role"):
                role = getattr(msg, "role", "")
                content = getattr(msg, "content", "")

            if role == "system":
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    text_parts: list[str] = []
                    for block in content:
                        if isinstance(block, dict):
                            t = block.get("text", "")
                            if t:
                                text_parts.append(t)
                    return "\n".join(text_parts) if text_parts else None
    return None


def _extract_record(
    response: Any,
    model: str,
    prompt_hash: str,
    elapsed_ms: int,
    system_prompt_hash: str | None = None,
) -> InferenceRecord:
    """Extract an InferenceRecord from a Mistral chat response.

    Mistral response fields (Pydantic objects, not dicts):
        response.choices[0].message.content  -> response text
        response.model                       -> actual model name (resolved alias)
        response.usage.prompt_tokens
        response.usage.completion_tokens
        response.choices[0].finish_reason    -> "stop", "length", "model_length", "tool_calls"
    """
    response_text = ""
    has_refusal = False
    input_tokens = None
    output_tokens = None

    choices = getattr(response, "choices", None)
    if choices and len(choices) > 0:
        choice = choices[0]
        message = getattr(choice, "message", None)
        if message is not None:
            content = getattr(message, "content", None)
            if isinstance(content, str):
                response_text = content
            elif isinstance(content, list):
                text_parts: list[str] = []
                for block in content:
                    text = getattr(block, "text", None) if not isinstance(block, str) else block
                    if text:
                        text_parts.append(text)
                response_text = "\n".join(text_parts)

        finish_reason = getattr(choice, "finish_reason", None)
        if finish_reason is not None:
            fr_str = str(finish_reason)
            if fr_str not in ("stop", "length", "model_length", "tool_calls"):
                has_refusal = True

    usage = getattr(response, "usage", None)
    if usage is not None:
        input_tokens = getattr(usage, "prompt_tokens", None)
        output_tokens = getattr(usage, "completion_tokens", None)

    actual_model = getattr(response, "model", model) or model

    return InferenceRecord(
        model_id=actual_model,
        model_hash=sha256_truncated(actual_model),
        prompt_hash=prompt_hash,
        response_hash=sha256_truncated(response_text) if response_text else sha256_truncated(""),
        latency_ms=elapsed_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        has_refusal=has_refusal,
        provider="mistral",
        system_prompt_hash=system_prompt_hash,
    )
