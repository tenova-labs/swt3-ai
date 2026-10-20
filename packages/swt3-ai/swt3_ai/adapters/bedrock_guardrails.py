"""SWT3 AI Witness SDK -- AWS Bedrock Guardrails Adapter.

Wraps a boto3 bedrock-runtime client to witness guardrail evaluations.
Intercepts apply_guardrail() calls, minting anchors for each policy
decision (AI-GRD.1).

This is a governance decision adapter, not an inference adapter. It
witnesses what the guardrail decided (INTERVENED vs NONE), not what
a model generated. For inference witnessing on Bedrock, use the
existing bedrock adapter.

Usage:
    from swt3_ai.adapters.bedrock_guardrails import wrap_bedrock_guardrails

    witness = Witness(endpoint="...", api_key="...", tenant_id="...")
    bedrock = boto3.client("bedrock-runtime")
    witnessed = wrap_bedrock_guardrails(bedrock, witness)

    result = witnessed.apply_guardrail(
        guardrailIdentifier="my-guardrail-id",
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": "user prompt here"}}],
    )

Duck-typed -- zero boto3 import at runtime.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import json
import time
from typing import Any, TYPE_CHECKING

from ..types import InferenceRecord
from ..fingerprint import sha256_truncated

if TYPE_CHECKING:
    from ..witness import Witness


def wrap_bedrock_guardrails(client: Any, witness: "Witness") -> "_GuardrailProxy":
    """Wrap a boto3 bedrock-runtime client with guardrail witnessing.

    Intercepts apply_guardrail() calls. All other methods pass through.
    """
    return _GuardrailProxy(client, witness)


class _GuardrailProxy:
    """Proxy for boto3 bedrock-runtime client.

    Flat API: client.apply_guardrail(). One level of proxy.
    """

    __slots__ = ("_target", "_witness")

    def __init__(self, target: Any, witness: "Witness") -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")
        real_attr = getattr(target, name)

        if name == "apply_guardrail":
            return _make_apply_guardrail_interceptor(real_attr, witness)

        return real_attr

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"<WitnessProxy({type(target).__name__})>"


def _make_apply_guardrail_interceptor(real_method: Any, witness: "Witness") -> Any:
    """Create an interceptor for client.apply_guardrail()."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        # Extract guardrail identity
        guardrail_id = kwargs.get("guardrailIdentifier", "unknown")
        guardrail_version = kwargs.get("guardrailVersion", "DRAFT")
        source = kwargs.get("source", "INPUT")
        content = kwargs.get("content", [])

        # Hash the content being evaluated
        content_text = _extract_content_text(content)
        prompt_hash = sha256_truncated(content_text)

        # Model identity = guardrail identifier + version
        model_id = f"guardrail:{guardrail_id}:{guardrail_version}"

        start = time.monotonic()
        response = real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Extract guardrail decision
        action = response.get("action", "NONE") if isinstance(response, dict) else "NONE"
        guardrail_passed = action == "NONE"

        # Hash the guardrail's assessment output
        assessments = response.get("assessments", []) if isinstance(response, dict) else []
        outputs = response.get("outputs", []) if isinstance(response, dict) else []
        response_summary = json.dumps(
            {"action": action, "assessments": assessments, "outputs": outputs},
            default=str,
            sort_keys=True,
            separators=(",", ":"),
        )
        response_hash = sha256_truncated(response_summary)

        # Extract usage (policy units evaluated)
        # Sum all numeric values in usage dict -- resilient to new policy types
        usage = response.get("usage", {}) if isinstance(response, dict) else {}
        total_units = sum(
            v for v in usage.values()
            if isinstance(v, (int, float))
        )

        record = InferenceRecord(
            model_id=model_id,
            model_hash=sha256_truncated(model_id),
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            latency_ms=elapsed_ms,
            input_tokens=total_units if total_units > 0 else None,
            output_tokens=None,
            has_refusal=not guardrail_passed,
            provider="aws-bedrock-guardrails",
            guardrails_active=1,
            guardrails_required=1,
            guardrail_passed=guardrail_passed,
            access_target=source,
            access_granted=guardrail_passed,
        )
        witness.record(record, procedures=["AI-GRD.1"])

        return response

    interceptor.__name__ = "apply_guardrail"
    interceptor.__qualname__ = "BedrockRuntime.apply_guardrail"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _extract_content_text(content: Any) -> str:
    """Extract hashable text from Bedrock guardrail content format.

    Bedrock content format:
        [{"text": {"text": "actual content"}}, ...]
    """
    parts: list[str] = []

    if isinstance(content, (list, tuple)):
        for item in content:
            if isinstance(item, dict):
                text_block = item.get("text", {})
                if isinstance(text_block, dict):
                    text = text_block.get("text", "")
                    if text:
                        parts.append(text)
                elif isinstance(text_block, str):
                    parts.append(text_block)

    return "\n".join(parts) if parts else ""
