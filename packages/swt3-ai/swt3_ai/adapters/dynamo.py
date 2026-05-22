"""SWT3 AI Witness SDK -- NVIDIA Dynamo Adapter (Layer 1).

Infrastructure-layer compliance witnessing for NVIDIA Dynamo inference
pipelines. This adapter wraps async generator endpoints with transparent
witnessing -- chunks pass through untouched, anchors mint after stream
completion.

Zero external dependencies. Duck-types OpenAI-compatible request/response
formats that Dynamo uses natively. Works on any async generator.

Usage:
    from swt3_ai.adapters.dynamo import witness_endpoint

    @witness_endpoint()          # reads SWT3_DSN or env vars
    @dynamo_endpoint()
    async def generate(self, request):
        async for chunk in self.backend.generate(request):
            yield chunk

Configuration (pick one):
    1. SWT3_DSN=https://axm_live_xxx@sovereign.tenova.io/MY_ENCLAVE
    2. SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID (separate env vars)
    3. witness_endpoint(witness=my_witness)  (explicit Witness instance)

If unconfigured, the decorator is a transparent no-op.
"""

from __future__ import annotations

import functools
import inspect
import logging
import os
import time
from typing import Any, AsyncIterator, Callable, Optional, TYPE_CHECKING
from urllib.parse import urlparse

from ..fingerprint import sha256_truncated
from ..types import InferenceRecord

if TYPE_CHECKING:
    from ..witness import Witness

logger = logging.getLogger("swt3_ai.dynamo")

_warned_unconfigured = False


def witness_endpoint(
    witness: Optional["Witness"] = None,
    **overrides: Any,
) -> Callable:
    """Decorator factory for witnessing async generator endpoints.

    Wraps any async generator function with transparent compliance
    witnessing. Chunks pass through untouched in real-time. After
    stream completion, an InferenceRecord is built from accumulated
    data and handed to the Witness for background anchoring.

    Args:
        witness: Explicit Witness instance. If None, auto-creates from
            SWT3_DSN or individual env vars on first call.
        **overrides: Override env var config (clearing_level, agent_id, etc.)

    Returns:
        Decorated async generator function (transparent to callers).
    """
    # Lazy-init container: Witness created on first invocation, not import time
    state: dict = {"witness": witness, "initialized": witness is not None}

    def decorator(fn: Callable) -> Callable:
        if not inspect.isasyncgenfunction(fn):
            # If the function isn't an async generator, it might be wrapped
            # by another decorator already. Try to preserve it as-is.
            if inspect.iscoroutinefunction(fn):
                logger.warning(
                    "witness_endpoint applied to coroutine %s, not async generator. "
                    "Passing through without witnessing.",
                    fn.__name__,
                )
                return fn
            # Regular function -- pass through
            return fn

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> AsyncIterator[Any]:
            w = _resolve_witness(state, overrides)
            if w is None:
                # No-op: yield everything from the original generator
                async for chunk in fn(*args, **kwargs):
                    yield chunk
                return

            # Find the request object from args/kwargs
            request = _find_request(args, kwargs)

            # Pre-stream: extract request metadata
            model_id, prompt_hash, sys_hash = _extract_request(request)

            accumulated: list = []
            start = time.monotonic()

            # Stream: pass through every chunk untouched
            async for chunk in fn(*args, **kwargs):
                accumulated.append(chunk)
                yield chunk

            # Post-stream: build InferenceRecord and witness
            elapsed_ms = int((time.monotonic() - start) * 1000)
            resp_hash, in_tok, out_tok, refusal = _accumulate_chunks(accumulated)

            record = InferenceRecord(
                model_id=model_id,
                model_hash=sha256_truncated(model_id),
                prompt_hash=prompt_hash,
                response_hash=resp_hash,
                latency_ms=elapsed_ms,
                input_tokens=in_tok,
                output_tokens=out_tok,
                provider="nvidia-dynamo",
                has_refusal=refusal,
                system_prompt_hash=sys_hash,
            )
            w.record(record)

            if not getattr(state, "_first_logged", False):
                state["_first_logged"] = True
                logger.info(
                    "SWT3 witness active on %s (model: %s, clearing: %d)",
                    fn.__name__, model_id, w.config.clearing_level,
                )

        return wrapper
    return decorator


def _resolve_witness(state: dict, overrides: dict) -> Optional["Witness"]:
    """Resolve or lazily create the Witness instance."""
    if state["initialized"]:
        return state["witness"]

    state["initialized"] = True

    # Try DSN first, then individual env vars
    w = _witness_from_dsn(overrides) or _witness_from_env(overrides)
    state["witness"] = w

    if w is None:
        global _warned_unconfigured
        if not _warned_unconfigured:
            _warned_unconfigured = True
            logger.warning(
                "SWT3 witness not configured. Set SWT3_DSN or "
                "SWT3_ENDPOINT+SWT3_API_KEY+SWT3_TENANT_ID to enable. "
                "Decorator is a transparent no-op."
            )
    return w


def _parse_dsn(dsn: str) -> tuple:
    """Parse SWT3_DSN into (endpoint, api_key, tenant_id).

    Format: https://{api_key}@{host}/{tenant_id}
    Example: https://axm_live_abc123@sovereign.tenova.io/MY_ENCLAVE
    """
    parsed = urlparse(dsn)
    api_key = parsed.username or ""
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    port = f":{parsed.port}" if parsed.port else ""
    tenant_id = parsed.path.lstrip("/")
    endpoint = f"{scheme}://{host}{port}"
    return endpoint, api_key, tenant_id


def _witness_from_dsn(overrides: dict) -> Optional["Witness"]:
    """Create Witness from SWT3_DSN env var."""
    dsn = os.environ.get("SWT3_DSN", "")
    if not dsn:
        return None

    endpoint, api_key, tenant_id = _parse_dsn(dsn)
    if not all([endpoint, api_key, tenant_id]):
        logger.warning("SWT3_DSN is malformed: %s", dsn)
        return None

    return _create_witness(endpoint, api_key, tenant_id, overrides)


def _witness_from_env(overrides: dict) -> Optional["Witness"]:
    """Create Witness from individual env vars."""
    endpoint = os.environ.get("SWT3_ENDPOINT", "")
    api_key = os.environ.get("SWT3_API_KEY", "")
    tenant_id = os.environ.get("SWT3_TENANT_ID", "")

    if not all([endpoint, api_key, tenant_id]):
        return None

    return _create_witness(endpoint, api_key, tenant_id, overrides)


def _create_witness(
    endpoint: str, api_key: str, tenant_id: str, overrides: dict
) -> "Witness":
    """Construct a Witness instance with env var + override config."""
    from ..witness import Witness

    clearing = int(overrides.get(
        "clearing_level",
        os.environ.get("SWT3_CLEARING_LEVEL", "1"),
    ))

    return Witness(
        endpoint=endpoint,
        api_key=api_key,
        tenant_id=tenant_id,
        clearing_level=clearing,
        agent_id=overrides.get("agent_id", os.environ.get("SWT3_AGENT_ID")),
        signing_key=overrides.get("signing_key", os.environ.get("SWT3_SIGNING_KEY")),
        jurisdiction=overrides.get("jurisdiction", os.environ.get("SWT3_JURISDICTION")),
        legal_basis=overrides.get("legal_basis", os.environ.get("SWT3_LEGAL_BASIS")),
        purpose_class=overrides.get("purpose_class", os.environ.get("SWT3_PURPOSE_CLASS")),
    )


def _find_request(args: tuple, kwargs: dict) -> Any:
    """Find the request object from function arguments.

    Handles both positional (self, request) and keyword (request=...) patterns.
    """
    # Check kwargs first
    if "request" in kwargs:
        return kwargs["request"]

    # Positional: skip 'self' if present (method call)
    for arg in args:
        if _looks_like_request(arg):
            return arg

    # Fallback: return empty dict (best-effort extraction will handle it)
    return {}


def _looks_like_request(obj: Any) -> bool:
    """Check if an object looks like an OpenAI-compatible request."""
    if isinstance(obj, dict):
        return "model" in obj or "messages" in obj
    return hasattr(obj, "model") or hasattr(obj, "messages")


def _extract_request(request: Any) -> tuple:
    """Extract (model_id, prompt_hash, system_prompt_hash) from a request.

    Duck-types both dict and object (Pydantic/dataclass) formats.
    """
    model_id = "unknown"
    prompt_text = ""
    system_text = None

    try:
        # Model ID
        if isinstance(request, dict):
            model_id = request.get("model", "unknown")
            messages = request.get("messages", [])
        else:
            model_id = getattr(request, "model", "unknown") or "unknown"
            messages = getattr(request, "messages", []) or []

        # Extract prompt and system prompt from messages
        prompt_parts: list = []
        system_parts: list = []

        if isinstance(messages, (list, tuple)):
            for msg in messages:
                role, content = _extract_msg_role_content(msg)
                if role == "system":
                    system_parts.append(content)
                else:
                    prompt_parts.append(content)

        prompt_text = "\n".join(prompt_parts) if prompt_parts else str(model_id)
        system_text = "\n".join(system_parts) if system_parts else None
    except Exception:
        logger.debug("Failed to extract request metadata, using defaults")

    prompt_hash = sha256_truncated(prompt_text)
    sys_hash = sha256_truncated(system_text) if system_text else None
    return model_id, prompt_hash, sys_hash


def _extract_msg_role_content(msg: Any) -> tuple:
    """Extract (role, content_text) from a single message."""
    if isinstance(msg, dict):
        role = msg.get("role", "")
        content = msg.get("content", "")
    else:
        role = getattr(msg, "role", "") or ""
        content = getattr(msg, "content", "") or ""

    # Handle multimodal content lists
    if isinstance(content, (list, tuple)):
        text_parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                text_parts.append(part.get("text", ""))
            elif isinstance(part, str):
                text_parts.append(part)
        content = "\n".join(text_parts)
    elif not isinstance(content, str):
        content = str(content) if content else ""

    return role, content


def _accumulate_chunks(chunks: list) -> tuple:
    """Accumulate response data from streamed chunks.

    Returns (response_hash, input_tokens, output_tokens, has_refusal).
    Duck-types both dict and object chunk formats.
    """
    text_parts: list = []
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    has_refusal = False

    for chunk in chunks:
        try:
            # Extract delta content
            delta_content = _extract_delta_content(chunk)
            if delta_content:
                text_parts.append(delta_content)

            # Extract finish_reason
            finish_reason = _extract_finish_reason(chunk)
            if finish_reason == "content_filter":
                has_refusal = True

            # Extract usage (often in final chunk)
            usage = _extract_usage(chunk)
            if usage:
                in_t, out_t = usage
                if in_t is not None:
                    input_tokens = in_t
                if out_t is not None:
                    output_tokens = out_t
        except Exception:
            continue

    response_text = "".join(text_parts)
    response_hash = sha256_truncated(response_text) if response_text else sha256_truncated("")
    return response_hash, input_tokens, output_tokens, has_refusal


def _extract_delta_content(chunk: Any) -> Optional[str]:
    """Extract text content from a single streamed chunk."""
    try:
        if isinstance(chunk, dict):
            choices = chunk.get("choices", [])
            if choices:
                delta = choices[0].get("delta", {})
                return delta.get("content")
        elif hasattr(chunk, "choices"):
            choices = chunk.choices
            if choices:
                delta = getattr(choices[0], "delta", None)
                if delta:
                    return getattr(delta, "content", None)
    except (IndexError, KeyError, TypeError):
        pass
    return None


def _extract_finish_reason(chunk: Any) -> Optional[str]:
    """Extract finish_reason from a streamed chunk."""
    try:
        if isinstance(chunk, dict):
            choices = chunk.get("choices", [])
            if choices:
                return choices[0].get("finish_reason")
        elif hasattr(chunk, "choices"):
            choices = chunk.choices
            if choices:
                return getattr(choices[0], "finish_reason", None)
    except (IndexError, KeyError, TypeError):
        pass
    return None


def _extract_usage(chunk: Any) -> Optional[tuple]:
    """Extract (input_tokens, output_tokens) from a chunk's usage field."""
    try:
        if isinstance(chunk, dict):
            usage = chunk.get("usage")
            if usage:
                return (
                    usage.get("prompt_tokens"),
                    usage.get("completion_tokens"),
                )
        elif hasattr(chunk, "usage"):
            usage = chunk.usage
            if usage:
                return (
                    getattr(usage, "prompt_tokens", None),
                    getattr(usage, "completion_tokens", None),
                )
    except (AttributeError, TypeError):
        pass
    return None
