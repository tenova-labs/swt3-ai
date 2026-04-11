"""SWT3 AI Witness SDK — Anthropic Adapter (ChainProxy).

Wraps the Anthropic client so that `client.messages.create()` is
intercepted for witnessing. Only two levels deep (simpler than OpenAI).

Anthropic response structure:
    response.content      → List[ContentBlock] (text, tool_use, etc.)
    response.model        → str (actual model used)
    response.stop_reason  → str ("end_turn", "max_tokens", "stop_sequence")
    response.usage        → Usage(input_tokens, output_tokens)

Factor mapping:
    factor_a → SHA-256 of model identifier (model integrity)
    factor_b → latency in milliseconds (performance)
    factor_c → 0 if clean, 1 if refusal/stop detected (content safety)
"""

from __future__ import annotations

import time
from typing import Any, Set, TYPE_CHECKING

from ..types import InferenceRecord
from ..fingerprint import sha256_truncated

if TYPE_CHECKING:
    from ..witness import Witness


def wrap_anthropic(client: Any, witness: "Witness") -> "_AnthropicProxy":
    """Wrap an Anthropic client with transparent witnessing."""
    return _AnthropicProxy(client, witness)


class _AnthropicProxy:
    """Proxy for the Anthropic client.

    Anthropic's API is two levels deep: client.messages.create()
    So we only need one level of proxy before interception.
    """

    __slots__ = ("_target", "_witness")

    def __init__(self, target: Any, witness: "Witness") -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")
        real_attr = getattr(target, name)

        if name == "messages":
            return _MessagesProxy(real_attr, witness)

        # Everything else passes through
        return real_attr

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"<WitnessProxy({type(target).__name__})>"


class _MessagesProxy:
    """Proxy for client.messages — intercepts create()."""

    __slots__ = ("_target", "_witness")

    def __init__(self, target: Any, witness: "Witness") -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")
        real_attr = getattr(target, name)

        if name == "create":
            return _make_interceptor(real_attr, witness)

        return real_attr


def _make_interceptor(real_method: Any, witness: "Witness") -> Any:
    """Create an interceptor for messages.create()."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        # ── Pre-call: capture prompt for hashing ──
        messages = kwargs.get("messages", args[0] if args else [])
        system = kwargs.get("system", "")
        model = kwargs.get("model", "unknown")

        prompt_text = _extract_prompt_text(messages, system)
        prompt_hash = sha256_truncated(prompt_text)

        # ── Call the real method and measure latency ──
        start = time.monotonic()
        response = real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # ── Post-call: extract factors ──
        record = _extract_record(response, model, prompt_hash, elapsed_ms)
        witness.record(record)

        # ── Return UNTOUCHED response ──
        return response

    interceptor.__name__ = "create"
    interceptor.__qualname__ = "messages.create"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _extract_prompt_text(messages: Any, system: Any = "") -> str:
    """Extract hashable text from Anthropic message format.

    Handles:
        - system prompt (str or list of content blocks)
        - List[dict] with "content" (str or list of content blocks)
    """
    parts: list[str] = []

    # System prompt
    if isinstance(system, str) and system:
        parts.append(system)
    elif isinstance(system, list):
        for block in system:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))

    # Messages
    if isinstance(messages, (list, tuple)):
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            parts.append(block.get("text", ""))
            elif hasattr(msg, "content"):
                c = getattr(msg, "content", "")
                if isinstance(c, str):
                    parts.append(c)

    return "\n".join(parts)


def _extract_record(
    response: Any,
    model: str,
    prompt_hash: str,
    elapsed_ms: int,
) -> InferenceRecord:
    """Extract an InferenceRecord from an Anthropic Message response.

    Anthropic response fields:
        response.content     → List[ContentBlock]
        response.model       → str
        response.stop_reason → str
        response.usage       → Usage(input_tokens, output_tokens)
    """
    # Extract response text from content blocks
    response_text = ""
    has_refusal = False

    content_blocks = getattr(response, "content", [])
    if isinstance(content_blocks, list):
        text_parts: list[str] = []
        for block in content_blocks:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                text_parts.append(getattr(block, "text", ""))
        response_text = "\n".join(text_parts)

    # Check stop_reason for content safety indicators
    stop_reason = getattr(response, "stop_reason", "")
    # Anthropic uses "end_turn" for normal, "max_tokens" for truncation
    # A missing or unusual stop_reason could indicate filtering
    if stop_reason not in ("end_turn", "max_tokens", "stop_sequence", "tool_use"):
        has_refusal = True

    # Check for empty response with end_turn (possible soft refusal)
    if not response_text.strip() and stop_reason == "end_turn":
        # Empty response is suspicious but not necessarily a refusal
        pass

    # Token usage
    input_tokens = None
    output_tokens = None
    usage = getattr(response, "usage", None)
    if usage:
        input_tokens = getattr(usage, "input_tokens", None)
        output_tokens = getattr(usage, "output_tokens", None)

    # Model from response (may differ from request for aliases)
    actual_model = getattr(response, "model", model) or model

    # Model hash
    model_hash = sha256_truncated(actual_model)

    # Response hash
    response_hash = sha256_truncated(response_text) if response_text else sha256_truncated("")

    return InferenceRecord(
        model_id=actual_model,
        model_hash=model_hash,
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        latency_ms=elapsed_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        has_refusal=has_refusal,
        provider="anthropic",
    )
