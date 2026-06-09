"""SWT3 AI Witness SDK -- CrewAI Adapter.

Wraps any object with a kickoff() method (CrewAI Crew pattern),
minting witness anchors on each crew execution without modifying
the crew logic or adding framework dependencies.

Usage:

    from swt3_ai.adapters.crewai import wrap_crew_ai

    witnessed = wrap_crew_ai(crew, witness)
    result = witnessed.kickoff()

Configuration:
    1. SWT3_DSN=https://axm_live_xxx@sovereign.tenova.io/MY_ENCLAVE
    2. SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID
    3. wrap_crew_ai(crew, witness=my_witness)

Duck-typed: works with any object that has a kickoff() method.
No crewai import required.

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

logger = logging.getLogger("swt3_ai.crewai")


def _resolve_model_id(crew: Any, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    env_id = os.environ.get("SWT3_MODEL_ID")
    if env_id:
        return env_id
    if hasattr(crew, "name") and crew.name:
        return f"crewai-{crew.name}"
    return "crewai-crew"


def _stringify_result(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, default=str)
    except Exception:
        return str(result)


def wrap_crew_ai(
    crew: Any,
    witness: Optional["Witness"] = None,
    model_id: Optional[str] = None,
    **overrides: Any,
) -> Any:
    """Wrap a CrewAI Crew to witness every kickoff() call.

    Args:
        crew: Any object with a kickoff() method (CrewAI Crew or compatible).
        witness: Explicit Witness instance. If None, auto-creates from env.
        model_id: Model identifier override.
        **overrides: Override config (clearing_level, agent_id, etc.)

    Returns:
        Proxy object that behaves identically to the original crew
        but mints a witness anchor on each kickoff().
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
        logger.debug("No witness configured; CrewAI adapter is a no-op")
        return crew

    mid = _resolve_model_id(crew, model_id)
    agent_count = len(crew.agents) if hasattr(crew, "agents") and crew.agents else 0
    task_count = len(crew.tasks) if hasattr(crew, "tasks") and crew.tasks else 0

    class CrewAIProxy:
        """Transparent proxy that witnesses CrewAI crew executions."""

        __slots__ = ("__target", "__witness")

        def __init__(self, target: Any, w: "Witness"):
            object.__setattr__(self, "_CrewAIProxy__target", target)
            object.__setattr__(self, "_CrewAIProxy__witness", w)

        def kickoff(self, inputs: Any = None, **kwargs: Any) -> Any:
            start = time.perf_counter()
            input_str = json.dumps(inputs, default=str) if inputs else "kickoff"
            result = self.__target.kickoff(inputs, **kwargs) if inputs else self.__target.kickoff(**kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)

            record = InferenceRecord(
                model_id=mid,
                model_hash=sha256_truncated(mid),
                prompt_hash=sha256_truncated(input_str),
                response_hash=sha256_truncated(_stringify_result(result)),
                latency_ms=elapsed,
                input_tokens=agent_count,
                output_tokens=task_count,
                guardrails_active=0,
                guardrails_required=0,
                guardrail_passed=True,
                has_refusal=False,
                provider="crewai",
                guardrail_names=[],
            )
            self.__witness.record(record)
            return result

        def __getattr__(self, name: str) -> Any:
            if name.startswith("_"):
                raise AttributeError(name)
            return getattr(self.__target, name)

    return CrewAIProxy(crew, witness)
