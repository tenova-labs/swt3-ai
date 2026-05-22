"""SWT3 AI Witness SDK -- Cerebras WSE-3 Adapter.

Infrastructure-layer compliance witnessing for Cerebras wafer-scale
inference. Wraps the SdkRuntime host client to intercept kernel launches
and device-to-host memory copies, minting anchors without modifying the
CSL kernel or adding latency to the token stream.

This adapter targets the Cerebras SDK host-side Python API. The actual
inference runs on the WSE-3 fabric; this observer sits on the host and
witnesses the I/O boundary.

Usage (decorator pattern):

    from swt3_ai.adapters.cerebras import witness_runtime

    @witness_runtime()
    def run_inference(runtime, input_data):
        runtime.launch("my_kernel", nonblock=False)
        result = runtime.memcpy_d2h(output_symbol, ...)
        return result

Usage (middleware pattern):

    from swt3_ai.adapters.cerebras import CerebrasWitnessMiddleware

    middleware = CerebrasWitnessMiddleware()
    middleware.patch(runtime)
    # runtime.launch() and runtime.memcpy_d2h() are now witnessed

Configuration:
    1. SWT3_DSN=https://axm_live_xxx@sovereign.tenova.io/MY_ENCLAVE
    2. SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID
    3. witness_runtime(witness=my_witness)

If unconfigured, all hooks are transparent no-ops.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import os
import time
from typing import Any, Callable, Optional, TYPE_CHECKING

from ..fingerprint import sha256_truncated
from ..types import InferenceRecord

if TYPE_CHECKING:
    from ..witness import Witness

logger = logging.getLogger("swt3_ai.cerebras")

_warned_unconfigured = False


def witness_runtime(
    witness: Optional["Witness"] = None,
    model_id: Optional[str] = None,
    **overrides: Any,
) -> Callable:
    """Decorator factory for witnessing Cerebras host-side inference.

    Wraps a function that uses SdkRuntime to launch kernels and read
    results. Measures wall-clock time and hashes I/O for witnessing.

    Args:
        witness: Explicit Witness instance. If None, auto-creates from env.
        model_id: Model identifier. Falls back to SWT3_MODEL_ID or
            CEREBRAS_MODEL_NAME env vars, then "cerebras-wse3".
        **overrides: Override config (clearing_level, agent_id, etc.)
    """
    state: dict = {"witness": witness, "initialized": witness is not None}

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            w = _resolve_witness(state, overrides)
            if w is None:
                return fn(*args, **kwargs)

            # Hash input data if present in args/kwargs
            input_hash = _hash_input(args, kwargs)
            mid = model_id or os.environ.get(
                "SWT3_MODEL_ID",
                os.environ.get("CEREBRAS_MODEL_NAME", "cerebras-wse3"),
            )

            start = time.monotonic()
            result = fn(*args, **kwargs)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            # Hash output
            output_hash = _hash_output(result)

            record = InferenceRecord(
                model_id=mid,
                model_hash=sha256_truncated(mid),
                prompt_hash=input_hash,
                response_hash=output_hash,
                latency_ms=elapsed_ms,
                input_tokens=0,
                output_tokens=0,
                provider="cerebras-wse3",
                has_refusal=False,
                system_prompt_hash="",
            )
            w.record(record)

            if not state.get("_first_logged"):
                state["_first_logged"] = True
                logger.info(
                    "SWT3 witness active on Cerebras runtime (model: %s, clearing: %d)",
                    mid, w.config.clearing_level,
                )

            return result

        return wrapper
    return decorator


class CerebrasWitnessMiddleware:
    """Middleware that patches a Cerebras SdkRuntime for transparent witnessing.

    Intercepts launch() and memcpy_d2h() to witness kernel executions
    and data transfers without modifying CSL kernels.

    Usage:
        middleware = CerebrasWitnessMiddleware()
        middleware.patch(runtime)
        # runtime.launch() now triggers witnessing on completion
    """

    def __init__(
        self,
        witness: Optional["Witness"] = None,
        model_id: Optional[str] = None,
        **overrides: Any,
    ) -> None:
        self._witness = witness
        self._model_id = model_id
        self._overrides = overrides
        self._patched = False
        self._state: dict = {
            "witness": witness,
            "initialized": witness is not None,
        }
        self._launch_time: Optional[float] = None
        self._kernel_name: Optional[str] = None
        self._launch_count = 0

    def patch(self, runtime: Any) -> None:
        """Monkey-patch runtime.launch and runtime.memcpy_d2h."""
        if self._patched:
            logger.warning("Runtime already patched -- skipping")
            return

        if not hasattr(runtime, "launch"):
            raise AttributeError(
                "Object does not have a launch() method. "
                "Expected Cerebras SdkRuntime or compatible."
            )

        original_launch = runtime.launch
        original_memcpy = getattr(runtime, "memcpy_d2h", None)

        middleware = self

        @functools.wraps(original_launch)
        def patched_launch(kernel_name: str, *args: Any, **kwargs: Any) -> Any:
            middleware._launch_time = time.monotonic()
            middleware._kernel_name = kernel_name
            middleware._launch_count += 1
            return original_launch(kernel_name, *args, **kwargs)

        runtime.launch = patched_launch

        if original_memcpy is not None:
            @functools.wraps(original_memcpy)
            def patched_memcpy(*args: Any, **kwargs: Any) -> Any:
                result = original_memcpy(*args, **kwargs)
                middleware._witness_transfer(result)
                return result

            runtime.memcpy_d2h = patched_memcpy

        self._patched = True
        logger.info("Cerebras runtime patched with SWT3 witnessing")

    def _witness_transfer(self, result: Any) -> None:
        """Mint an anchor after device-to-host transfer."""
        w = _resolve_witness(self._state, self._overrides)
        if w is None:
            return

        elapsed_ms = 0
        if self._launch_time is not None:
            elapsed_ms = int((time.monotonic() - self._launch_time) * 1000)

        mid = self._model_id or os.environ.get(
            "SWT3_MODEL_ID",
            os.environ.get("CEREBRAS_MODEL_NAME", "cerebras-wse3"),
        )
        kernel = self._kernel_name or "unknown_kernel"

        record = InferenceRecord(
            model_id=mid,
            model_hash=sha256_truncated(mid),
            prompt_hash=sha256_truncated(kernel),
            response_hash=_hash_output(result),
            latency_ms=elapsed_ms,
            input_tokens=0,
            output_tokens=0,
            provider="cerebras-wse3",
            has_refusal=False,
            system_prompt_hash="",
        )
        w.record(record)

    @property
    def is_patched(self) -> bool:
        return self._patched

    @property
    def launch_count(self) -> int:
        return self._launch_count


# -- Internal helpers --


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
            logger.debug("SWT3 unconfigured -- Cerebras witnessing disabled (no-op)")
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


def _hash_input(args: tuple, kwargs: dict) -> str:
    """Hash input data from function arguments."""
    # Look for numpy arrays or raw bytes in args
    for arg in args:
        h = _try_hash(arg)
        if h:
            return h
    for v in kwargs.values():
        h = _try_hash(v)
        if h:
            return h
    return sha256_truncated("")


def _hash_output(result: Any) -> str:
    """Hash output data from function return value."""
    h = _try_hash(result)
    return h if h else sha256_truncated("")


def _try_hash(obj: Any) -> Optional[str]:
    """Try to hash an object. Supports numpy arrays, bytes, and strings.

    Always returns 16-char hex (consistent with sha256_truncated).
    """
    if obj is None:
        return None
    if isinstance(obj, bytes):
        return hashlib.sha256(obj).hexdigest()[:16]
    if isinstance(obj, str):
        return sha256_truncated(obj)
    # numpy array
    if hasattr(obj, "tobytes"):
        try:
            return hashlib.sha256(obj.tobytes()).hexdigest()[:16]
        except Exception:
            pass
    # Fallback: str representation
    try:
        return sha256_truncated(str(obj))
    except Exception:
        return None
