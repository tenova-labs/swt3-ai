"""SWT3 AI Witness SDK -- A2A (Agent-to-Agent) Protocol Adapter.

Wraps any object with a send() method (Google A2A protocol pattern),
minting witness anchors on each inter-agent message without modifying
the agent logic or adding protocol dependencies.

Usage:

    from swt3_ai.adapters.a2a import wrap_a2a

    witnessed = wrap_a2a(agent, witness)
    result = witnessed.send({"text": "Analyze this data"})

Configuration:
    1. SWT3_DSN=https://axm_live_xxx@sovereign.tenova.io/MY_ENCLAVE
    2. SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID
    3. wrap_a2a(agent, witness=my_witness)

Duck-typed: works with any object that has a send() method.
No A2A protocol import required.

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

logger = logging.getLogger("swt3_ai.a2a")


def _resolve_model_id(agent: Any, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    env_id = os.environ.get("SWT3_MODEL_ID")
    if env_id:
        return env_id
    if hasattr(agent, "model") and agent.model:
        return str(agent.model)
    if hasattr(agent, "name") and agent.name:
        return f"a2a-{agent.name}"
    return "a2a-agent"


def _stringify_message(msg: Any) -> str:
    if msg is None:
        return ""
    if isinstance(msg, str):
        return msg
    try:
        return json.dumps(msg, default=str)
    except Exception:
        return str(msg)


def wrap_a2a(
    agent: Any,
    witness: Optional["Witness"] = None,
    model_id: Optional[str] = None,
    **overrides: Any,
) -> Any:
    """Wrap an A2A agent to witness every send() and handle_message() call.

    Args:
        agent: Any object with a send() method (A2A agent or compatible).
        witness: Explicit Witness instance. If None, auto-creates from env.
        model_id: Model identifier override.
        **overrides: Override config (clearing_level, agent_id, etc.)

    Returns:
        Proxy object that behaves identically to the original agent
        but mints a witness anchor on each message exchange.
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
        logger.debug("No witness configured; A2A adapter is a no-op")
        return agent

    mid = _resolve_model_id(agent, model_id)

    class A2AProxy:
        """Transparent proxy that witnesses A2A agent message exchanges."""

        __slots__ = ("__target", "__witness")

        def __init__(self, target: Any, w: "Witness"):
            object.__setattr__(self, "_A2AProxy__target", target)
            object.__setattr__(self, "_A2AProxy__witness", w)

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
                provider="a2a",
                guardrail_names=[],
            )
            self.__witness.record(record)

        def send(self, message: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            result = self.__target.send(message, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._record(message, result, elapsed)
            return result

        def handle_message(self, message: Any, *args: Any, **kwargs: Any) -> Any:
            if not hasattr(self.__target, "handle_message"):
                raise AttributeError("handle_message")
            start = time.perf_counter()
            result = self.__target.handle_message(message, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._record(message, result, elapsed)
            return result

        def __getattr__(self, name: str) -> Any:
            if name.startswith("_"):
                raise AttributeError(name)
            return getattr(self.__target, name)

    return A2AProxy(agent, witness)
