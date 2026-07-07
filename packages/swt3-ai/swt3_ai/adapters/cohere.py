"""SWT3 AI Witness SDK -- Cohere Adapter.

Wraps the Cohere Python SDK to witness inference calls. Intercepts
chat() and chat_stream() methods, minting anchors for each completion.

Usage:
    from swt3_ai.adapters.cohere import wrap_cohere

    witness = Witness(endpoint="...", api_key="...", tenant_id="...")
    client = cohere.ClientV2(api_key="...")
    witnessed = wrap_cohere(client, witness)

    response = witnessed.chat(model="command-r-plus", messages=[...])

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


def wrap_cohere(client: Any, witness: "Witness") -> "_CohereProxy":
    """Wrap a Cohere client with transparent witnessing.

    Works with both cohere.ClientV2 and cohere.AsyncClientV2.
    Intercepts chat() and chat_stream() calls.
    """
    return _CohereProxy(client, witness)


class _CohereProxy:
    """Proxy for the Cohere client.

    Cohere's API is flat: client.chat() and client.chat_stream().
    Only one level of proxy is needed.
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
            if asyncio.iscoroutinefunction(real_attr):
                return _make_async_chat_interceptor(real_attr, witness)
            return _make_chat_interceptor(real_attr, witness)

        if name == "chat_stream":
            if asyncio.iscoroutinefunction(real_attr):
                return _make_async_stream_interceptor(real_attr, witness)
            return _make_stream_interceptor(real_attr, witness)

        # Everything else passes through
        return real_attr

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"<WitnessProxy({type(target).__name__})>"


# -- chat() interceptors --


def _make_chat_interceptor(real_method: Any, witness: "Witness") -> Any:
    """Create a sync interceptor for client.chat()."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        # -- Pre-call: capture prompt for hashing --
        messages = kwargs.get("messages", args[0] if args else [])
        model = kwargs.get("model", "unknown")

        prompt_text = _extract_prompt_text(messages)
        prompt_hash = sha256_truncated(prompt_text)

        # Hash system prompt separately (instruction drift detection)
        system_prompt_text = _extract_system_prompt(messages)
        system_prompt_hash = sha256_truncated(system_prompt_text) if system_prompt_text else None

        # Gatekeeper pre-call check (strict mode only)
        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(messages, model)

        # -- Call the real method and measure latency --
        start = time.monotonic()
        response = real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # -- Post-call: extract factors --
        record = _extract_record(response, model, prompt_hash, elapsed_ms, system_prompt_hash)
        witness.record(record, authorization_id=authorization_id)

        # -- Return UNTOUCHED response --
        return response

    interceptor.__name__ = "chat"
    interceptor.__qualname__ = "ClientV2.chat"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _make_async_chat_interceptor(real_method: Any, witness: "Witness") -> Any:
    """Create an async interceptor for AsyncClientV2.chat()."""

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

    interceptor.__name__ = "chat"
    interceptor.__qualname__ = "AsyncClientV2.chat"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


# -- chat_stream() interceptors --


def _make_stream_interceptor(real_method: Any, witness: "Witness") -> Any:
    """Create a sync interceptor for client.chat_stream().

    chat_stream() returns an iterator of streamed events. We accumulate
    text content and token usage, then witness on stream completion.
    """

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

    interceptor.__name__ = "chat_stream"
    interceptor.__qualname__ = "ClientV2.chat_stream"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _make_async_stream_interceptor(real_method: Any, witness: "Witness") -> Any:
    """Create an async interceptor for AsyncClientV2.chat_stream()."""

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

    interceptor.__name__ = "chat_stream"
    interceptor.__qualname__ = "AsyncClientV2.chat_stream"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


# -- Stream Accumulators --


class _StreamAccumulator:
    """Wraps a sync Cohere stream iterator. Accumulates text and witnesses on completion."""

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
        self._witnessed = False

    def __iter__(self) -> "_StreamAccumulator":
        return self

    def __next__(self) -> Any:
        try:
            event = next(self._stream)
            self._accumulate(event)
            return event
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

    def _accumulate(self, event: Any) -> None:
        """Extract data from a stream event."""
        event_type = getattr(event, "type", "")

        # Content delta events contain text fragments
        if event_type == "content-delta":
            delta = getattr(event, "delta", None)
            if delta is not None:
                message = getattr(delta, "message", None)
                if message is not None:
                    content = getattr(message, "content", None)
                    if content is not None:
                        text = getattr(content, "text", "")
                        if text:
                            self._text_parts.append(text)

        # Stream end event carries final metadata
        elif event_type == "message-end":
            delta = getattr(event, "delta", None)
            if delta is not None:
                # Token usage from finish message
                usage = getattr(delta, "usage", None)
                if usage is not None:
                    tokens = getattr(usage, "tokens", usage)
                    self._input_tokens = getattr(tokens, "input_tokens", None)
                    self._output_tokens = getattr(tokens, "output_tokens", None)

        # Message start can carry model info
        elif event_type == "message-start":
            delta = getattr(event, "delta", None)
            if delta is not None:
                message = getattr(delta, "message", None)
                if message is not None:
                    m = getattr(message, "model", None)
                    if m:
                        self._actual_model = m

    def _witness_completion(self) -> None:
        """Mint an anchor from the accumulated stream data."""
        if self._witnessed:
            return
        self._witnessed = True

        elapsed_ms = int((time.monotonic() - self._start_time) * 1000)
        response_text = "".join(self._text_parts)

        record = InferenceRecord(
            model_id=self._actual_model,
            model_hash=sha256_truncated(self._actual_model),
            prompt_hash=self._prompt_hash,
            response_hash=sha256_truncated(response_text),
            latency_ms=elapsed_ms,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            has_refusal=False,
            provider="cohere",
            system_prompt_hash=self._system_prompt_hash,
        )
        self._witness.record(record, authorization_id=self._authorization_id)


class _AsyncStreamAccumulator:
    """Wraps an async Cohere stream. Accumulates text and witnesses on completion."""

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
        self._witnessed = False

    def __aiter__(self) -> "_AsyncStreamAccumulator":
        return self

    async def __anext__(self) -> Any:
        try:
            event = await self._stream.__anext__()
            self._accumulate(event)
            return event
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

    def _accumulate(self, event: Any) -> None:
        """Extract data from a stream event (same logic as sync)."""
        event_type = getattr(event, "type", "")

        if event_type == "content-delta":
            delta = getattr(event, "delta", None)
            if delta is not None:
                message = getattr(delta, "message", None)
                if message is not None:
                    content = getattr(message, "content", None)
                    if content is not None:
                        text = getattr(content, "text", "")
                        if text:
                            self._text_parts.append(text)

        elif event_type == "message-end":
            delta = getattr(event, "delta", None)
            if delta is not None:
                usage = getattr(delta, "usage", None)
                if usage is not None:
                    tokens = getattr(usage, "tokens", usage)
                    self._input_tokens = getattr(tokens, "input_tokens", None)
                    self._output_tokens = getattr(tokens, "output_tokens", None)

        elif event_type == "message-start":
            delta = getattr(event, "delta", None)
            if delta is not None:
                message = getattr(delta, "message", None)
                if message is not None:
                    m = getattr(message, "model", None)
                    if m:
                        self._actual_model = m

    def _witness_completion(self) -> None:
        """Mint an anchor from the accumulated stream data."""
        if self._witnessed:
            return
        self._witnessed = True

        elapsed_ms = int((time.monotonic() - self._start_time) * 1000)
        response_text = "".join(self._text_parts)

        record = InferenceRecord(
            model_id=self._actual_model,
            model_hash=sha256_truncated(self._actual_model),
            prompt_hash=self._prompt_hash,
            response_hash=sha256_truncated(response_text),
            latency_ms=elapsed_ms,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            has_refusal=False,
            provider="cohere",
            system_prompt_hash=self._system_prompt_hash,
        )
        self._witness.record(record, authorization_id=self._authorization_id)


# -- Extraction helpers --


def _extract_prompt_text(messages: Any) -> str:
    """Extract hashable text from Cohere message format.

    Cohere V2 messages follow the OpenAI-style format:
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
    """Extract system prompt text from the messages list.

    Cohere V2 uses a system message in the messages array
    (role="system") rather than a separate parameter.
    """
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
    """Extract an InferenceRecord from a Cohere chat response.

    Cohere response fields:
        response.message.content[0].text  -> response text
        response.model                    -> actual model name
        response.usage.tokens.input_tokens
        response.usage.tokens.output_tokens
        response.finish_reason            -> "COMPLETE", "MAX_TOKENS", "ERROR"
    """
    # Response text
    response_text = ""
    has_refusal = False

    message = getattr(response, "message", None)
    if message is not None:
        content = getattr(message, "content", None)
        if isinstance(content, (list, tuple)) and len(content) > 0:
            text_parts: list[str] = []
            for block in content:
                text = getattr(block, "text", None)
                if text:
                    text_parts.append(text)
            response_text = "\n".join(text_parts)

    # Finish reason
    finish_reason = getattr(response, "finish_reason", "")
    if finish_reason not in ("COMPLETE", "MAX_TOKENS", "TOOL_CALL"):
        has_refusal = True

    # Token usage
    input_tokens = None
    output_tokens = None
    usage = getattr(response, "usage", None)
    if usage is not None:
        tokens = getattr(usage, "tokens", usage)
        input_tokens = getattr(tokens, "input_tokens", None)
        output_tokens = getattr(tokens, "output_tokens", None)

    # Actual model from response
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
        provider="cohere",
        system_prompt_hash=system_prompt_hash,
    )
