"""SWT3 AI Witness SDK -- Jev (TypeSafe AI) Adapter.

Wraps a Jev client to auto-witness Choice, Score, and Noul API calls.
Jev returns typed decisions with calibrated probabilities instead of text.
Zero hard dependency -- pure duck-typing, no import of the Jev SDK.

Factor mapping:
  Choice: fa=option_index, fb=confidence*1000 (int), fc=cardinality
  Score:  fa=score_value*1000, fb=confidence*1000, fc=num_classes
  Noul:   fa=0 (null output), fb=0, fc=0

Usage:
    from swt3_ai.adapters.jev import wrap_jev

    witness = Witness(endpoint="...", api_key="...", tenant_id="...")
    client = JevClient(api_key="...")
    witnessed = wrap_jev(client, witness)

    result = witnessed.choice(options=["approve", "deny"], context=...)
    # result is untouched -- witnessing happens in the background

Expected Jev client interface (duck-typed):
    client.choice(options=..., **kwargs) -> obj with .index, .confidence, .options
    client.score(input=..., **kwargs)   -> obj with .value, .confidence, .classes
    client.noul(input=..., **kwargs)    -> obj (null/abstain decision)
    client.model (optional str)         -> model identifier

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, TYPE_CHECKING

from ..types import InferenceRecord
from ..fingerprint import sha256_truncated

if TYPE_CHECKING:
    from ..witness import Witness


def wrap_jev(client: Any, witness: "Witness") -> "_JevProxy":
    """Wrap a Jev client with transparent witnessing.

    Works with any object that has choice(), score(), noul() methods.
    """
    return _JevProxy(client, witness)


class _JevProxy:
    """Proxy for the Jev client. Flat API: three methods."""

    __slots__ = ("_target", "_witness")

    def __init__(self, target: Any, witness: "Witness") -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")
        real_attr = getattr(target, name)

        if name in ("choice", "score", "noul"):
            if asyncio.iscoroutinefunction(real_attr):
                return _make_async_interceptor(real_attr, witness, name, target)
            return _make_sync_interceptor(real_attr, witness, name, target)

        return real_attr

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"<WitnessProxy({type(target).__name__})>"


def _get_model_id(target: Any) -> str:
    """Extract model identifier from Jev client, if available."""
    return getattr(target, "model", None) or "jev"


def _extract_choice_factors(result: Any) -> tuple[float, float, float]:
    """Extract factors from a Jev Choice response."""
    index = getattr(result, "index", 0)
    confidence = getattr(result, "confidence", 0.0)
    options = getattr(result, "options", None)
    cardinality = len(options) if options else 0
    return float(index), float(int(confidence * 1000)), float(cardinality)


def _extract_score_factors(result: Any) -> tuple[float, float, float]:
    """Extract factors from a Jev Score response."""
    value = getattr(result, "value", 0.0)
    confidence = getattr(result, "confidence", 0.0)
    classes = getattr(result, "classes", None)
    num_classes = len(classes) if classes else 0
    return float(int(value * 1000)), float(int(confidence * 1000)), float(num_classes)


def _extract_noul_factors() -> tuple[float, float, float]:
    """Noul is a null/abstain decision -- factors are all zero."""
    return 0.0, 0.0, 0.0


_EXTRACTORS = {
    "choice": _extract_choice_factors,
    "score": _extract_score_factors,
}


def _build_record(
    method: str, target: Any, result: Any, elapsed_ms: float,
) -> InferenceRecord:
    """Build an InferenceRecord from a Jev response."""
    model_id = _get_model_id(target)
    if method == "noul":
        fa, fb, fc = _extract_noul_factors()
    else:
        fa, fb, fc = _EXTRACTORS[method](result)

    return InferenceRecord(
        model_id=f"jev-{method}",
        model_hash=sha256_truncated(model_id, 16),
        prompt_hash=sha256_truncated(str(id(result)), 12),
        response_hash=sha256_truncated(repr(result)[:256], 12),
        latency_ms=int(elapsed_ms),
        guardrails_active=0,
        guardrails_required=0,
        guardrail_passed=True,
        has_refusal=method == "noul",
        provider="jev",
    )


def _make_sync_interceptor(real_method: Any, witness: "Witness", method: str, target: Any) -> Any:
    """Create a sync interceptor for a Jev method."""
    def interceptor(*args: Any, **kwargs: Any) -> Any:
        t0 = time.monotonic()
        result = real_method(*args, **kwargs)
        elapsed_ms = (time.monotonic() - t0) * 1000
        record = _build_record(method, target, result, elapsed_ms)
        witness.record(record)
        return result
    return interceptor


def _make_async_interceptor(real_method: Any, witness: "Witness", method: str, target: Any) -> Any:
    """Create an async interceptor for a Jev method."""
    async def interceptor(*args: Any, **kwargs: Any) -> Any:
        t0 = time.monotonic()
        result = await real_method(*args, **kwargs)
        elapsed_ms = (time.monotonic() - t0) * 1000
        record = _build_record(method, target, result, elapsed_ms)
        witness.record(record)
        return result
    return interceptor
