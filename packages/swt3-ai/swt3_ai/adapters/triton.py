"""SWT3 AI Witness SDK -- NVIDIA Triton Inference Server Plugin.

Triton (BSD 3-Clause licensed) supports custom Python backends and
pre/post-processing pipelines. This adapter hooks into the Triton
execution lifecycle to mint SWT3 anchors after each inference request
without adding latency to the inference path.

Two integration modes:

1. **BLS (Business Logic Scripting) Middleware:**
   Wrap any Triton model's execute() with witnessing.

       from swt3_ai.adapters.triton import witness_execute

       class TritonPythonModel:
           @witness_execute()
           def execute(self, requests):
               # your inference logic
               return responses

2. **Post-Processing Observer:**
   Attach as a Triton "decoupled" observer that watches inference
   completions and mints anchors in the background.

       from swt3_ai.adapters.triton import TritonWitnessObserver
       observer = TritonWitnessObserver()
       observer.observe(request, response, model_name, latency_ms)

Configuration:
    1. SWT3_DSN=https://axm_live_xxx@sovereign.tenova.io/MY_ENCLAVE
    2. SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID
    3. witness_execute(witness=my_witness)

If unconfigured, all hooks are transparent no-ops.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from ..fingerprint import sha256_truncated
from ..types import InferenceRecord

if TYPE_CHECKING:
    from ..witness import Witness

logger = logging.getLogger("swt3_ai.triton")

_warned_unconfigured = False


def witness_execute(
    witness: Optional["Witness"] = None,
    model_name: Optional[str] = None,
    **overrides: Any,
) -> Callable:
    """Decorator factory for witnessing Triton Python backend execute().

    Wraps the TritonPythonModel.execute() method. The inference runs
    normally; after completion, an anchor is minted in the background
    from the request/response metadata.

    Args:
        witness: Explicit Witness instance. If None, auto-creates from env.
        model_name: Override model name (default: from TRITON_MODEL_NAME env
            or the class name).
        **overrides: Override config (clearing_level, agent_id, etc.)
    """
    state: dict = {"witness": witness, "initialized": witness is not None}

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(self_or_cls: Any, requests: Any) -> Any:
            w = _resolve_witness(state, overrides)

            start = time.monotonic()
            responses = fn(self_or_cls, requests)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if w is None:
                return responses

            # Mint anchors in background for each request/response pair
            resolved_model = (
                model_name
                or os.environ.get("TRITON_MODEL_NAME")
                or getattr(self_or_cls, "model_name", None)
                or type(self_or_cls).__name__
            )

            _witness_batch(w, resolved_model, requests, responses, elapsed_ms)

            if not state.get("_first_logged"):
                state["_first_logged"] = True
                logger.info(
                    "SWT3 witness active on Triton model %s (clearing: %d)",
                    resolved_model, w.config.clearing_level,
                )

            return responses

        return wrapper
    return decorator


class TritonWitnessObserver:
    """Standalone observer for Triton inference completions.

    Use this when you can't decorate execute() directly (e.g., when
    observing from an ensemble pipeline or external monitoring hook).
    """

    def __init__(
        self,
        witness: Optional["Witness"] = None,
        **overrides: Any,
    ) -> None:
        self._state: dict = {"witness": witness, "initialized": witness is not None}
        self._overrides = overrides
        self._observed_count = 0

    def observe(
        self,
        model_name: str,
        input_data: Any = None,
        output_data: Any = None,
        latency_ms: int = 0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record an inference observation.

        Call this after each Triton inference completion. The anchor is
        minted in the background via the Witness buffer.
        """
        w = _resolve_witness(self._state, self._overrides)
        if w is None:
            return

        prompt_hash = _hash_triton_data(input_data)
        response_hash = _hash_triton_data(output_data)

        record = InferenceRecord(
            model_id=model_name,
            model_hash=sha256_truncated(model_name),
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            latency_ms=latency_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            provider="nvidia-triton",
            has_refusal=False,
            system_prompt_hash="",
        )
        w.record(record)
        self._observed_count += 1

    @property
    def observed_count(self) -> int:
        return self._observed_count


# ── Internal helpers ──────────────────────────────────────────────────────


def _resolve_witness(state: dict, overrides: dict) -> Optional["Witness"]:
    """Resolve or lazily create the Witness instance from env."""
    global _warned_unconfigured

    if state["initialized"]:
        return state["witness"]

    dsn = os.environ.get("SWT3_DSN", "")
    endpoint = os.environ.get("SWT3_ENDPOINT", "")
    api_key = os.environ.get("SWT3_API_KEY", "")

    if not dsn and not (endpoint and api_key):
        if not _warned_unconfigured:
            _warned_unconfigured = True
            logger.debug("SWT3 unconfigured -- Triton witnessing disabled (no-op)")
        state["initialized"] = True
        state["witness"] = None
        return None

    from ..witness import Witness

    if dsn:
        w = Witness.from_dsn(dsn, **overrides)
    else:
        from ..types import WitnessConfig
        config = WitnessConfig(
            endpoint=endpoint,
            api_key=api_key,
            clearing_level=int(os.environ.get("SWT3_CLEARING_LEVEL", "1")),
            **{k: v for k, v in overrides.items() if k in WitnessConfig.__dataclass_fields__},
        )
        w = Witness(config)

    state["witness"] = w
    state["initialized"] = True
    return w


def _witness_batch(
    w: "Witness",
    model_name: str,
    requests: Any,
    responses: Any,
    elapsed_ms: int,
) -> None:
    """Witness a batch of Triton request/response pairs."""
    # Triton passes lists of InferenceRequest/InferenceResponse
    req_list = requests if isinstance(requests, (list, tuple)) else [requests]
    resp_list = responses if isinstance(responses, (list, tuple)) else [responses]

    for i, req in enumerate(req_list):
        resp = resp_list[i] if i < len(resp_list) else None

        prompt_hash = _hash_triton_request(req)
        response_hash = _hash_triton_response(resp)
        in_tokens, out_tokens = _estimate_triton_tokens(req, resp)

        record = InferenceRecord(
            model_id=model_name,
            model_hash=sha256_truncated(model_name),
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            latency_ms=elapsed_ms // max(len(req_list), 1),
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            provider="nvidia-triton",
            has_refusal=False,
            system_prompt_hash="",
        )
        w.record(record)


def _hash_triton_request(req: Any) -> str:
    """Hash a Triton InferenceRequest's input tensors."""
    if req is None:
        return ""
    try:
        # Triton InferenceRequest has inputs() method returning list of Tensor
        if hasattr(req, "inputs"):
            inputs = req.inputs()
            if callable(inputs):
                inputs = inputs()
            parts = []
            for inp in inputs:
                if hasattr(inp, "as_numpy"):
                    parts.append(inp.as_numpy().tobytes())
                elif hasattr(inp, "__bytes__"):
                    parts.append(bytes(inp))
            if parts:
                return hashlib.sha256(b"".join(parts)).hexdigest()[:12]
    except Exception:
        pass
    return hashlib.sha256(str(req).encode()).hexdigest()[:12]


def _hash_triton_response(resp: Any) -> str:
    """Hash a Triton InferenceResponse's output tensors."""
    if resp is None:
        return ""
    try:
        if hasattr(resp, "output_tensors"):
            tensors = resp.output_tensors()
            if callable(tensors):
                tensors = tensors()
            parts = []
            for t in tensors:
                if hasattr(t, "as_numpy"):
                    parts.append(t.as_numpy().tobytes())
            if parts:
                return hashlib.sha256(b"".join(parts)).hexdigest()[:12]
    except Exception:
        pass
    return hashlib.sha256(str(resp).encode()).hexdigest()[:12]


def _hash_triton_data(data: Any) -> str:
    """Hash arbitrary data for the observer pattern."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return hashlib.sha256(data).hexdigest()[:12]
    if isinstance(data, str):
        return hashlib.sha256(data.encode()).hexdigest()[:12]
    try:
        import numpy as np
        if isinstance(data, np.ndarray):
            return hashlib.sha256(data.tobytes()).hexdigest()[:12]
    except ImportError:
        pass
    return hashlib.sha256(str(data).encode()).hexdigest()[:12]


def _estimate_triton_tokens(req: Any, resp: Any) -> tuple:
    """Estimate input/output token counts from Triton objects."""
    in_tokens = 0
    out_tokens = 0
    try:
        if hasattr(req, "inputs"):
            inputs = req.inputs()
            if callable(inputs):
                inputs = inputs()
            for inp in inputs:
                if hasattr(inp, "as_numpy"):
                    arr = inp.as_numpy()
                    in_tokens += arr.size
    except Exception:
        pass
    try:
        if hasattr(resp, "output_tensors"):
            tensors = resp.output_tensors()
            if callable(tensors):
                tensors = tensors()
            for t in tensors:
                if hasattr(t, "as_numpy"):
                    arr = t.as_numpy()
                    out_tokens += arr.size
    except Exception:
        pass
    return in_tokens, out_tokens
