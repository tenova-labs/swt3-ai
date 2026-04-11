"""SWT3 AI Witness SDK — AWS Bedrock Adapter (ChainProxy).

Wraps the boto3 Bedrock Runtime client so that `client.converse()` and
`client.invoke_model()` are intercepted for witnessing.

AWS Bedrock API patterns:
    - converse(): High-level chat API (similar to OpenAI/Anthropic)
        client.converse(modelId="anthropic.claude-3-5-sonnet...", messages=[...])
        Response: { "output": { "message": { "content": [...] } }, "usage": {...} }

    - invoke_model(): Low-level API (raw JSON body)
        client.invoke_model(modelId="...", body=json.dumps({...}))
        Response: { "body": StreamingBody, "contentType": "application/json" }

The adapter intercepts both and extracts factors for witnessing.
The developer's code sees zero difference from using the raw client.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Set, TYPE_CHECKING

from ..types import InferenceRecord
from ..fingerprint import sha256_truncated

if TYPE_CHECKING:
    from ..witness import Witness

# Methods to intercept on the Bedrock Runtime client
INTERCEPTED_METHODS: Set[str] = {"converse", "invoke_model"}


def wrap_bedrock(client: Any, witness: "Witness") -> "_BedrockProxy":
    """Wrap a boto3 Bedrock Runtime client with transparent witnessing.

    Usage:
        import boto3
        from swt3_ai import Witness

        witness = Witness(endpoint=..., api_key=..., tenant_id=...)
        bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
        client = witness.wrap(bedrock)

        # Use exactly as before
        response = client.converse(
            modelId="anthropic.claude-3-5-sonnet-20241022-v2:0",
            messages=[{"role": "user", "content": [{"text": "Hello"}]}],
        )
    """
    return _BedrockProxy(client, witness)


class _BedrockProxy:
    """Proxy that intercepts converse() and invoke_model() on the Bedrock client."""

    __slots__ = ("_target", "_witness")

    def __init__(self, target: Any, witness: "Witness") -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")
        real_attr = getattr(target, name)

        if name in INTERCEPTED_METHODS and callable(real_attr):
            if name == "converse":
                return _make_converse_interceptor(real_attr, witness)
            elif name == "invoke_model":
                return _make_invoke_model_interceptor(real_attr, witness)

        return real_attr

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"<WitnessProxy({type(target).__name__})>"


def _make_converse_interceptor(
    real_method: Callable[..., Any],
    witness: "Witness",
) -> Callable[..., Any]:
    """Intercept bedrock_runtime.converse() calls."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        # Extract prompt from Bedrock Converse message format
        model_id = kwargs.get("modelId", "unknown")
        messages = kwargs.get("messages", [])
        prompt_text = _extract_converse_prompt(messages)
        prompt_hash = sha256_truncated(prompt_text)

        # Call and measure
        start = time.monotonic()
        response = real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Extract record
        record = _extract_converse_record(response, model_id, prompt_hash, elapsed_ms)
        witness.record(record)

        return response

    interceptor.__name__ = "converse"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _make_invoke_model_interceptor(
    real_method: Callable[..., Any],
    witness: "Witness",
) -> Callable[..., Any]:
    """Intercept bedrock_runtime.invoke_model() calls."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        model_id = kwargs.get("modelId", "unknown")

        # Parse the request body to extract prompt
        body_raw = kwargs.get("body", "{}")
        if isinstance(body_raw, (bytes, bytearray)):
            body_raw = body_raw.decode("utf-8")
        try:
            body = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
        except (json.JSONDecodeError, TypeError):
            body = {}

        prompt_text = _extract_invoke_prompt(body, model_id)
        prompt_hash = sha256_truncated(prompt_text)

        # Call and measure
        start = time.monotonic()
        response = real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Extract record from invoke_model response
        record = _extract_invoke_record(response, model_id, prompt_hash, elapsed_ms)
        witness.record(record)

        return response

    interceptor.__name__ = "invoke_model"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


# ── Prompt Extraction ────────────────────────────────────────────────

def _extract_converse_prompt(messages: Any) -> str:
    """Extract hashable text from Bedrock Converse message format.

    Bedrock Converse format:
        [{"role": "user", "content": [{"text": "Hello"}]}]
    """
    parts: list[str] = []
    if isinstance(messages, (list, tuple)):
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content", [])
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict):
                            text = block.get("text", "")
                            if text:
                                parts.append(text)
                elif isinstance(content, str):
                    parts.append(content)
    return "\n".join(parts)


def _extract_invoke_prompt(body: dict, model_id: str) -> str:
    """Extract prompt from invoke_model body (varies by model provider).

    Anthropic on Bedrock:
        {"messages": [{"role": "user", "content": "Hello"}], ...}

    Amazon Titan:
        {"inputText": "Hello", ...}

    Meta Llama:
        {"prompt": "Hello", ...}
    """
    # Anthropic format (most common on Bedrock)
    messages = body.get("messages", [])
    if messages:
        parts: list[str] = []
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            parts.append(block.get("text", ""))
        if parts:
            return "\n".join(parts)

    # Amazon Titan format
    if "inputText" in body:
        return str(body["inputText"])

    # Meta Llama format
    if "prompt" in body:
        return str(body["prompt"])

    return json.dumps(body)


# ── Record Extraction ────────────────────────────────────────────────

def _extract_converse_record(
    response: Any,
    model_id: str,
    prompt_hash: str,
    elapsed_ms: int,
) -> InferenceRecord:
    """Extract InferenceRecord from Bedrock Converse response.

    Response shape:
        {
            "output": {"message": {"role": "assistant", "content": [{"text": "..."}]}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 10, "outputTokens": 20},
            "metrics": {"latencyMs": 500}
        }
    """
    response_text = ""
    has_refusal = False

    output = response.get("output", {})
    message = output.get("message", {})
    content = message.get("content", [])

    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                text = block.get("text", "")
                if text:
                    response_text += text

    stop_reason = response.get("stopReason", "")
    if stop_reason == "content_filtered":
        has_refusal = True

    # Token usage
    usage = response.get("usage", {})
    input_tokens = usage.get("inputTokens")
    output_tokens = usage.get("outputTokens")

    # Model hash
    model_hash = sha256_truncated(model_id)
    response_hash = sha256_truncated(response_text) if response_text else sha256_truncated("")

    return InferenceRecord(
        model_id=model_id,
        model_hash=model_hash,
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        latency_ms=elapsed_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        has_refusal=has_refusal,
        provider="bedrock",
        system_fingerprint=None,
    )


def _extract_invoke_record(
    response: Any,
    model_id: str,
    prompt_hash: str,
    elapsed_ms: int,
) -> InferenceRecord:
    """Extract InferenceRecord from Bedrock invoke_model response.

    Response has a StreamingBody in response["body"] that must be read.
    """
    response_text = ""
    has_refusal = False
    input_tokens = None
    output_tokens = None

    try:
        body_bytes = response.get("body", b"")
        if hasattr(body_bytes, "read"):
            body_bytes = body_bytes.read()
        body = json.loads(body_bytes) if body_bytes else {}

        # Anthropic on Bedrock response
        if "content" in body:
            content = body["content"]
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        response_text += block.get("text", "")
            elif isinstance(content, str):
                response_text = content

        # Amazon Titan response
        elif "results" in body:
            results = body["results"]
            if isinstance(results, list) and results:
                response_text = results[0].get("outputText", "")

        # Meta Llama response
        elif "generation" in body:
            response_text = body.get("generation", "")

        # Token usage (Anthropic format)
        usage = body.get("usage", {})
        input_tokens = usage.get("input_tokens") or usage.get("inputTokens")
        output_tokens = usage.get("output_tokens") or usage.get("outputTokens")

        # Refusal check
        stop_reason = body.get("stop_reason", "") or body.get("stopReason", "")
        if "content_filter" in str(stop_reason).lower():
            has_refusal = True

    except (json.JSONDecodeError, AttributeError, TypeError):
        pass

    model_hash = sha256_truncated(model_id)
    response_hash = sha256_truncated(response_text) if response_text else sha256_truncated("")

    return InferenceRecord(
        model_id=model_id,
        model_hash=model_hash,
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        latency_ms=elapsed_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        has_refusal=has_refusal,
        provider="bedrock",
        system_fingerprint=None,
    )
