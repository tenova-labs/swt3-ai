"""SWT3 AI Witness SDK -- Microsoft Foundry Adapter.

Wraps any object with an execute() method (Microsoft Agent Framework pattern),
minting witness anchors on each agent execution without modifying
the agent logic or adding framework dependencies.

Usage:

    from swt3_ai.adapters.foundry import wrap_foundry

    witnessed = wrap_foundry(agent, witness)
    result = witnessed.execute("Summarize this document")

Configuration:
    1. SWT3_DSN=https://axm_live_xxx@sovereign.tenova.io/MY_ENCLAVE
    2. SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID
    3. wrap_foundry(agent, witness=my_witness)

Duck-typed: works with any object that has an execute() method.
No Microsoft SDK import required.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional, TYPE_CHECKING

from ..fingerprint import sha256_truncated
from ..types import InferenceRecord

if TYPE_CHECKING:
    from ..witness import Witness

logger = logging.getLogger("swt3_ai.foundry")


def _resolve_model_id(agent: Any, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    env_id = os.environ.get("SWT3_MODEL_ID")
    if env_id:
        return env_id
    if hasattr(agent, "model") and agent.model:
        return str(agent.model)
    if hasattr(agent, "name") and agent.name:
        return f"foundry-{agent.name}"
    return "foundry-agent"


def _stringify_message(msg: Any) -> str:
    if msg is None:
        return ""
    if isinstance(msg, str):
        return msg
    try:
        return json.dumps(msg, default=str)
    except Exception:
        return str(msg)


def wrap_foundry(
    agent: Any,
    witness: Optional["Witness"] = None,
    model_id: Optional[str] = None,
    **overrides: Any,
) -> Any:
    """Wrap a Microsoft Foundry agent to witness every execute() call.

    Args:
        agent: Any object with an execute() method (Foundry agent or compatible).
        witness: Explicit Witness instance. If None, auto-creates from env.
        model_id: Model identifier override.
        **overrides: Override config (clearing_level, agent_id, etc.)

    Returns:
        Proxy object that behaves identically to the original agent
        but mints a witness anchor on each execution.
    """
    if witness is None:
        try:
            from ..witness import SWT3Witness
            dsn = os.environ.get("SWT3_DSN")
            if dsn:
                witness = SWT3Witness.from_dsn(dsn, **overrides)
            else:
                endpoint = os.environ.get("SWT3_ENDPOINT", "")
                api_key = os.environ.get("SWT3_API_KEY", "")
                tenant_id = os.environ.get("SWT3_TENANT_ID", "")
                if endpoint and api_key and tenant_id:
                    witness = SWT3Witness(
                        endpoint=endpoint,
                        api_key=api_key,
                        tenant_id=tenant_id,
                        **overrides,
                    )
        except Exception:
            pass

    if witness is None:
        logger.debug("No witness configured; Foundry adapter is a no-op")
        return agent

    mid = _resolve_model_id(agent, model_id)

    class FoundryProxy:
        """Transparent proxy that witnesses Microsoft Foundry agent executions."""

        __slots__ = ("__target", "__witness")

        def __init__(self, target: Any, w: "Witness"):
            object.__setattr__(self, "_FoundryProxy__target", target)
            object.__setattr__(self, "_FoundryProxy__witness", w)

        def _record(self, message: Any, result: Any, elapsed: int) -> None:
            record = InferenceRecord(
                model_id=mid,
                model_hash=sha256_truncated(mid),
                prompt_hash=sha256_truncated(_stringify_message(message)),
                response_hash=sha256_truncated(_stringify_message(result)),
                latency_ms=elapsed,
                input_tokens=0,
                output_tokens=0,
                guardrails_active=0,
                guardrails_required=0,
                guardrail_passed=True,
                has_refusal=False,
                provider="microsoft-foundry",
                guardrail_names=[],
            )
            self.__witness.record(record)

        def execute(self, prompt: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            result = self.__target.execute(prompt, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._record(prompt, result, elapsed)
            return result

        def intercept_tool_call(self, tool_name: Any, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
            if not hasattr(self.__target, "intercept_tool_call"):
                raise AttributeError("intercept_tool_call")
            start = time.perf_counter()
            result = self.__target.intercept_tool_call(tool_name, tool_input, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._record(
                f"{tool_name}:{_stringify_message(tool_input)}",
                result,
                elapsed,
            )
            return result

        def __getattr__(self, name: str) -> Any:
            if name.startswith("_"):
                raise AttributeError(name)
            return getattr(self.__target, name)

    return FoundryProxy(agent, witness)
