"""SWT3 AI Witness SDK -- AWS Strands Agent Adapter.

Wraps a Strands Agent so that agent invocations (__call__) are witnessed,
minting anchors for each agent execution (AI-INF.1).

Strands agents are callable: result = agent("prompt"). This adapter
intercepts __call__ to witness the outer invocation -- what went in
and what came out. Individual tool calls within the agent loop are
not intercepted (use tool-level adapters for that).

Usage:
    from swt3_ai.adapters.strands import wrap_strands

    witness = Witness(endpoint="...", api_key="...", tenant_id="...")
    agent = Agent(tools=[...])
    witnessed = wrap_strands(agent, witness)

    result = witnessed("What is 2+2?")

Duck-typed -- zero strands import at runtime.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Optional, TYPE_CHECKING

from ..types import InferenceRecord
from ..fingerprint import sha256_truncated

if TYPE_CHECKING:
    from ..witness import Witness


def wrap_strands(
    agent: Any,
    witness: "Witness",
    model_id: Optional[str] = None,
) -> "_StrandsProxy":
    """Wrap a Strands Agent with transparent witnessing.

    Args:
        agent: A Strands Agent instance (or any callable with similar API).
        witness: Witness instance for minting anchors.
        model_id: Override model identifier. If None, extracted from agent.

    Returns:
        Proxy that behaves identically to the original agent.
    """
    return _StrandsProxy(agent, witness, model_id)


class _StrandsProxy:
    """Proxy for a Strands Agent.

    Intercepts __call__ (agent("prompt")) to witness each invocation.
    All other attribute access passes through to the real agent.
    """

    __slots__ = ("_target", "_witness", "_model_id_override")

    def __init__(
        self,
        target: Any,
        witness: "Witness",
        model_id_override: Optional[str],
    ) -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)
        object.__setattr__(self, "_model_id_override", model_id_override)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")

        # Extract prompt from first positional arg
        prompt = args[0] if args else kwargs.get("prompt", "")
        prompt_text = prompt if isinstance(prompt, str) else str(prompt)
        prompt_hash = sha256_truncated(prompt_text)

        model_id = _get_model_id(self)

        # Gatekeeper pre-call check (strict mode only)
        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(prompt_text, model_id)

        start = time.monotonic()
        result = target(*args, **kwargs)

        # Handle async agents: if result is a coroutine, wrap it
        if asyncio.iscoroutine(result):
            return _async_witness_result(
                result, witness, model_id, prompt_hash, start, authorization_id,
            )

        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Hash the result
        result_text = _stringify_result(result)
        response_hash = sha256_truncated(result_text)

        record = InferenceRecord(
            model_id=model_id,
            model_hash=sha256_truncated(model_id),
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            latency_ms=elapsed_ms,
            input_tokens=None,
            output_tokens=None,
            has_refusal=False,
            provider="aws-strands",
        )
        witness.record(record, authorization_id=authorization_id)

        return result

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        return getattr(target, name)

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"<WitnessProxy({type(target).__name__})>"


async def _async_witness_result(
    coro: Any,
    witness: "Witness",
    model_id: str,
    prompt_hash: str,
    start_time: float,
    authorization_id: str | None,
) -> Any:
    """Await an async agent result and witness it."""
    result = await coro
    elapsed_ms = int((time.monotonic() - start_time) * 1000)

    result_text = _stringify_result(result)
    response_hash = sha256_truncated(result_text)

    record = InferenceRecord(
        model_id=model_id,
        model_hash=sha256_truncated(model_id),
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        latency_ms=elapsed_ms,
        input_tokens=None,
        output_tokens=None,
        has_refusal=False,
        provider="aws-strands",
    )
    witness.record(record, authorization_id=authorization_id)

    return result


def _get_model_id(proxy: _StrandsProxy) -> str:
    """Extract model ID from the agent or override."""
    override = object.__getattribute__(proxy, "_model_id_override")
    if override:
        return override

    target = object.__getattribute__(proxy, "_target")

    # Strands Agent stores model in various attributes
    model = getattr(target, "model", None)
    if model:
        # model might be a string or an object with an id/name
        if isinstance(model, str):
            return model
        model_id = getattr(model, "model_id", None) or getattr(model, "id", None)
        if model_id:
            return str(model_id)

    model_id = getattr(target, "model_id", None)
    if model_id:
        return str(model_id)

    name = getattr(target, "name", None)
    if name:
        return f"strands-{name}"

    return "strands-agent"


def _stringify_result(result: Any) -> str:
    """Convert agent result to a hashable string."""
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    # AgentResult has a string representation
    try:
        text = str(result)
        if text:
            return text
    except Exception:
        pass
    try:
        return json.dumps(result, default=str)
    except Exception:
        return ""
