"""SWT3 AI Witness SDK — OpenAI Adapter (ChainProxy).

Implements a recursive proxy that transparently wraps the OpenAI client
so that `client.chat.completions.create()` is intercepted for witnessing
while all other attributes pass through untouched.

The ChainProxy follows the attribute chain:
    client.chat         → ChainProxy (passthrough)
    client.chat.completions → ChainProxy (passthrough)
    client.chat.completions.create() → INTERCEPTED

On interception:
    1. Capture the prompt messages for hashing
    2. Start the latency timer
    3. Call the real create() method
    4. Extract factors from the response
    5. Build an InferenceRecord
    6. Hand to Witness.record() (non-blocking buffer)
    7. Return the original response to the developer UNTOUCHED

The developer's code sees zero difference from using the raw OpenAI client.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Set, TYPE_CHECKING

from ..types import InferenceRecord
from ..fingerprint import sha256_truncated

if TYPE_CHECKING:
    from ..witness import Witness


# Methods to intercept at the terminal level
INTERCEPTED_METHODS: Dict[str, Set[str]] = {
    # path → method names to intercept
    "chat.completions": {"create"},
    # Future: "embeddings": {"create"},
    # Future: "images": {"generate"},
}

# Map attribute chains to their dotted path
# e.g., client.chat.completions → "chat.completions"


def wrap_openai(client: Any, witness: "Witness") -> "_OpenAIProxy":
    """Wrap an OpenAI client with transparent witnessing."""
    return _OpenAIProxy(client, witness, path="")


class _OpenAIProxy:
    """Recursive proxy that follows the OpenAI client attribute chain.

    At each level, __getattr__ checks if the resolved path has interceptable
    methods. If the next attribute IS an interceptable method, it returns a
    wrapped callable. Otherwise, it returns another proxy for the next level.
    """

    __slots__ = ("_target", "_witness", "_path")

    def __init__(self, target: Any, witness: "Witness", path: str) -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)
        object.__setattr__(self, "_path", path)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")
        path = object.__getattribute__(self, "_path")

        # Resolve the real attribute from the target
        real_attr = getattr(target, name)

        # Build the dotted path for this level
        current_path = f"{path}.{name}" if path else name

        # Check if this attribute is an interceptable method
        parent_path = path  # e.g., "chat.completions"
        if parent_path in INTERCEPTED_METHODS and name in INTERCEPTED_METHODS[parent_path]:
            # This IS the method to intercept — wrap it
            return _make_interceptor(real_attr, witness, name, parent_path)

        # Check if this path could lead to interceptable methods
        # e.g., "chat" could lead to "chat.completions"
        has_children = any(p.startswith(current_path) for p in INTERCEPTED_METHODS)

        if has_children:
            # Keep proxying deeper
            return _OpenAIProxy(real_attr, witness, current_path)

        # No interception needed — return the real attribute directly
        return real_attr

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"<WitnessProxy({type(target).__name__})>"


def _make_interceptor(
    real_method: Callable[..., Any],
    witness: "Witness",
    method_name: str,
    path: str,
) -> Callable[..., Any]:
    """Create an interceptor that wraps an OpenAI API method."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        # ── Pre-call: capture prompt for hashing ──
        messages = kwargs.get("messages", args[0] if args else [])
        model = kwargs.get("model", "unknown")

        # Hash the prompt (all message contents concatenated)
        prompt_text = _extract_prompt_text(messages)
        prompt_hash = sha256_truncated(prompt_text)

        # ── Call the real method and measure latency ──
        start = time.monotonic()
        response = real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # ── Post-call: extract factors from response ──
        record = _extract_record(response, model, prompt_hash, elapsed_ms)

        # ── Hand to witness (non-blocking) ──
        witness.record(record)

        # ── Return UNTOUCHED response to developer ──
        return response

    # Preserve the original method's signature for IDE support
    interceptor.__name__ = method_name
    interceptor.__qualname__ = f"{path}.{method_name}"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)

    return interceptor


def _extract_prompt_text(messages: Any) -> str:
    """Extract hashable text from OpenAI message format.

    Handles:
        - List[dict] with "content" keys (standard chat format)
        - List[dict] with multimodal content (text parts only)
        - String input (simple prompt)
    """
    if isinstance(messages, str):
        return messages

    parts: list[str] = []
    if isinstance(messages, (list, tuple)):
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    # Multimodal: extract text parts only
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            parts.append(part.get("text", ""))
            elif hasattr(msg, "content"):
                # Pydantic model (openai types)
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
    """Extract an InferenceRecord from an OpenAI ChatCompletion response.

    Factor mapping:
        factor_a → SHA-256 of model identifier (model integrity)
        factor_b → latency in milliseconds (performance)
        factor_c → 0 if clean, 1 if refusal/violation detected
    """
    # Extract response text for hashing
    response_text = ""
    has_refusal = False

    # Handle ChatCompletion response object
    if hasattr(response, "choices") and response.choices:
        choice = response.choices[0]
        message = getattr(choice, "message", None)
        if message:
            content = getattr(message, "content", "") or ""
            response_text = content

            # Check for refusal (OpenAI's refusal field)
            refusal = getattr(message, "refusal", None)
            if refusal:
                has_refusal = True

        # Check finish_reason for content_filter
        finish_reason = getattr(choice, "finish_reason", "")
        if finish_reason == "content_filter":
            has_refusal = True

    # Extract token usage
    input_tokens = None
    output_tokens = None
    usage = getattr(response, "usage", None)
    if usage:
        input_tokens = getattr(usage, "prompt_tokens", None)
        output_tokens = getattr(usage, "completion_tokens", None)

    # Extract model info from response (may differ from request)
    actual_model = getattr(response, "model", model) or model
    system_fingerprint = getattr(response, "system_fingerprint", None)

    # Model hash: SHA-256 of model identifier + system_fingerprint (if available)
    model_hash_input = actual_model
    if system_fingerprint:
        model_hash_input = f"{actual_model}:{system_fingerprint}"
    model_hash = sha256_truncated(model_hash_input)

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
        provider="openai",
        system_fingerprint=system_fingerprint,
    )
