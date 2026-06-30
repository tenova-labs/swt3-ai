"""SWT3 AI Witness SDK -- Microsoft AGT (Agent Governance Toolkit) Adapter.

Wraps any object with an evaluate() method (Microsoft AGT policy engine pattern),
minting witness anchors on each policy evaluation without modifying
the governance logic or adding framework dependencies.

SWT3 is the independent witness layer for AGT-managed agents. AGT enforces
policy; SWT3 proves what AGT decided, cryptographically, out-of-band.

Usage:

    from swt3_ai.adapters.agt import wrap_agt

    witnessed = wrap_agt(policy_engine, witness)
    decision = witnessed.evaluate(prompt, context={"model": "gpt-4o"})

Configuration:
    1. SWT3_DSN=https://axm_live_xxx@sovereign.tenova.io/MY_ENCLAVE
    2. SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID
    3. wrap_agt(engine, witness=my_witness)

Duck-typed: works with any object that has an evaluate() method.
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

logger = logging.getLogger("swt3_ai.agt")


def _resolve_model_id(engine: Any, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    env_id = os.environ.get("SWT3_MODEL_ID") or os.environ.get("AGT_MODEL_ID")
    if env_id:
        return env_id
    if hasattr(engine, "model") and engine.model:
        return str(engine.model)
    if hasattr(engine, "name") and engine.name:
        return f"agt-{engine.name}"
    return "agt-policy-engine"


def _stringify(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    try:
        return json.dumps(val, default=str)
    except Exception:
        return str(val)


def _extract_guardrails(result: Any) -> tuple:
    """Extract guardrail metadata from an AGT Decision BOM if available."""
    guardrails_active = 0
    guardrail_names: list = []
    guardrail_passed = True

    if isinstance(result, dict):
        policies = result.get("policies_evaluated") or result.get("guardrails") or []
        if isinstance(policies, (list, tuple)):
            guardrails_active = len(policies)
            for p in policies:
                if isinstance(p, dict):
                    name = p.get("name") or p.get("policy_name") or ""
                    if name:
                        guardrail_names.append(str(name))
                    if p.get("result") == "fail" or p.get("passed") is False:
                        guardrail_passed = False
                elif isinstance(p, str):
                    guardrail_names.append(p)
        verdict = result.get("verdict") or result.get("decision")
        if isinstance(verdict, str) and verdict.lower() in ("deny", "block", "fail", "rejected"):
            guardrail_passed = False
    elif hasattr(result, "policies_evaluated"):
        policies = getattr(result, "policies_evaluated", [])
        if isinstance(policies, (list, tuple)):
            guardrails_active = len(policies)

    return guardrails_active, guardrail_names, guardrail_passed


def wrap_agt(
    engine: Any,
    witness: Optional["Witness"] = None,
    model_id: Optional[str] = None,
    **overrides: Any,
) -> Any:
    """Wrap a Microsoft AGT policy engine to witness every evaluate() call.

    Args:
        engine: Any object with an evaluate() method (AGT engine or compatible).
        witness: Explicit Witness instance. If None, auto-creates from env.
        model_id: Model identifier override.
        **overrides: Override config (clearing_level, agent_id, etc.)

    Returns:
        Proxy object that behaves identically to the original engine
        but mints a witness anchor on each evaluation.
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
        logger.debug("No witness configured; AGT adapter is a no-op")
        return engine

    mid = _resolve_model_id(engine, model_id)

    class AGTProxy:
        """Transparent proxy that witnesses Microsoft AGT policy evaluations."""

        __slots__ = ("__target", "__witness")

        def __init__(self, target: Any, w: "Witness"):
            object.__setattr__(self, "_AGTProxy__target", target)
            object.__setattr__(self, "_AGTProxy__witness", w)

        def _record(self, prompt: Any, result: Any, elapsed: int) -> None:
            guardrails_active, guardrail_names, guardrail_passed = _extract_guardrails(result)
            record = InferenceRecord(
                model_id=mid,
                model_hash=sha256_truncated(mid),
                prompt_hash=sha256_truncated(_stringify(prompt)),
                response_hash=sha256_truncated(_stringify(result)),
                latency_ms=elapsed,
                input_tokens=0,
                output_tokens=0,
                guardrails_active=guardrails_active,
                guardrails_required=guardrails_active,
                guardrail_passed=guardrail_passed,
                has_refusal=not guardrail_passed,
                provider="microsoft-agt",
                guardrail_names=guardrail_names,
            )
            self.__witness.record(record)

        def evaluate(self, prompt: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            result = self.__target.evaluate(prompt, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._record(prompt, result, elapsed)
            return result

        def assess(self, config: Any, *args: Any, **kwargs: Any) -> Any:
            if not hasattr(self.__target, "assess"):
                raise AttributeError("assess")
            start = time.perf_counter()
            result = self.__target.assess(config, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._record(config, result, elapsed)
            return result

        def __getattr__(self, name: str) -> Any:
            if name.startswith("_"):
                raise AttributeError(name)
            return getattr(self.__target, name)

    return AGTProxy(engine, witness)
