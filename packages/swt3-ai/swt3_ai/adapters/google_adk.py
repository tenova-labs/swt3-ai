"""SWT3 AI Witness SDK -- Google ADK (Agent Development Kit) Adapter.

Wraps any object with a run() method (Google ADK Agent pattern),
minting witness anchors on each agent execution without modifying
the agent logic or adding framework dependencies.

Usage (wrap pattern):

    from swt3_ai.adapters.google_adk import wrap_google_adk

    witnessed = wrap_google_adk(agent, witness)
    result = witnessed.run("What is the weather?")

Configuration:
    1. SWT3_DSN=https://axm_live_xxx@sovereign.tenova.io/MY_ENCLAVE
    2. SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID
    3. wrap_google_adk(agent, witness=my_witness)

Duck-typed: works with any object that has a run() method.
No google-adk import required.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional, TYPE_CHECKING

from ..fingerprint import sha256_truncated
from ..types import InferenceRecord

if TYPE_CHECKING:
    from ..witness import Witness

logger = logging.getLogger("swt3_ai.google_adk")


def _resolve_model_id(agent: Any, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    env_id = os.environ.get("SWT3_MODEL_ID") or os.environ.get("GOOGLE_ADK_MODEL")
    if env_id:
        return env_id
    if hasattr(agent, "model") and agent.model:
        return str(agent.model)
    if hasattr(agent, "name") and agent.name:
        return f"google-adk-{agent.name}"
    return "google-adk-agent"


def _stringify_result(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    try:
        import json
        return json.dumps(result, default=str)
    except Exception:
        return str(result)


def wrap_google_adk(
    agent: Any,
    witness: Optional["Witness"] = None,
    model_id: Optional[str] = None,
    **overrides: Any,
) -> Any:
    """Wrap a Google ADK Agent to witness every run() call.

    Args:
        agent: Any object with a run() method (Google ADK Agent or compatible).
        witness: Explicit Witness instance. If None, auto-creates from env.
        model_id: Model identifier override.
        **overrides: Override config (clearing_level, agent_id, etc.)

    Returns:
        Proxy object that behaves identically to the original agent
        but mints a witness anchor on each run().
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
        logger.debug("No witness configured; Google ADK adapter is a no-op")
        return agent

    mid = _resolve_model_id(agent, model_id)

    class GoogleADKProxy:
        """Transparent proxy that witnesses Google ADK agent runs."""

        __slots__ = ("__target", "__witness")

        def __init__(self, target: Any, w: "Witness"):
            object.__setattr__(self, "_GoogleADKProxy__target", target)
            object.__setattr__(self, "_GoogleADKProxy__witness", w)

        def run(self, prompt: str, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            result = self.__target.run(prompt, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)

            record = InferenceRecord(
                model_id=mid,
                model_hash=sha256_truncated(mid),
                prompt_hash=sha256_truncated(prompt),
                response_hash=sha256_truncated(_stringify_result(result)),
                latency_ms=elapsed,
                input_tokens=0,
                output_tokens=0,
                guardrails_active=0,
                guardrails_required=0,
                guardrail_passed=True,
                has_refusal=False,
                provider="google-adk",
                guardrail_names=[],
            )
            self.__witness.record(record)
            return result

        def __getattr__(self, name: str) -> Any:
            if name.startswith("_"):
                raise AttributeError(name)
            return getattr(self.__target, name)

    return GoogleADKProxy(agent, witness)
