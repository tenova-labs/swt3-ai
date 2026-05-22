"""SWT3 AI Witness SDK -- Native vLLM Plugin.

Deep integration with vLLM's AsyncLLMEngine. Unlike the OpenAI-compat
adapter (which wraps HTTP clients), this hooks directly into the engine's
generate() method for zero-network-hop witnessing inside vLLM serving.

This is the "Token Factory Observer" -- it sits inside the inference engine
and mints anchors as tokens are produced, without adding latency to the
token stream.

Usage (decorator pattern -- same as Dynamo):

    from swt3_ai.adapters.vllm_native import witness_engine

    # Wrap the engine's generate method
    engine = AsyncLLMEngine.from_engine_args(args)
    engine.generate = witness_engine()(engine.generate)

Usage (middleware pattern -- for vLLM serve):

    from swt3_ai.adapters.vllm_native import VllmWitnessMiddleware

    # In your vLLM entrypoint or plugin
    middleware = VllmWitnessMiddleware()
    # Patches the engine transparently
    middleware.patch(engine)

Configuration:
    Same as Dynamo adapter:
    1. SWT3_DSN=https://axm_live_xxx@sovereign.tenova.io/MY_ENCLAVE
    2. SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID
    3. witness_engine(witness=my_witness)

If unconfigured, all hooks are transparent no-ops.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import os
import time
from typing import Any, AsyncIterator, Callable, Optional, TYPE_CHECKING

from ..fingerprint import sha256_truncated
from ..types import InferenceRecord

if TYPE_CHECKING:
    from ..witness import Witness

logger = logging.getLogger("swt3_ai.vllm_native")

_warned_unconfigured = False


def witness_engine(
    witness: Optional["Witness"] = None,
    **overrides: Any,
) -> Callable:
    """Decorator factory for witnessing vLLM AsyncLLMEngine.generate().

    Wraps the async generator returned by engine.generate() with transparent
    compliance witnessing. RequestOutput objects pass through untouched.
    After stream completion, an InferenceRecord is minted in the background.

    Args:
        witness: Explicit Witness instance. If None, auto-creates from env.
        **overrides: Override config (clearing_level, agent_id, etc.)
    """
    state: dict = {"witness": witness, "initialized": witness is not None}

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> AsyncIterator[Any]:
            w = _resolve_witness(state, overrides)
            if w is None:
                async for output in fn(*args, **kwargs):
                    yield output
                return

            # Extract request metadata from vLLM's generate() signature:
            # generate(prompt, sampling_params, request_id, ...)
            model_id, prompt_hash, request_id = _extract_generate_args(args, kwargs)

            start = time.monotonic()
            total_tokens = 0
            output_text_parts: list = []
            finished = False

            async for request_output in fn(*args, **kwargs):
                yield request_output
                # Accumulate output data from RequestOutput
                if hasattr(request_output, "outputs") and request_output.outputs:
                    for output in request_output.outputs:
                        if hasattr(output, "token_ids"):
                            total_tokens = len(output.token_ids)
                        if hasattr(output, "text"):
                            output_text_parts = [output.text]
                        if hasattr(output, "finish_reason") and output.finish_reason:
                            finished = True

            elapsed_ms = int((time.monotonic() - start) * 1000)

            # Build response hash from final output text
            final_text = "".join(output_text_parts)
            response_hash = hashlib.sha256(final_text.encode()).hexdigest()[:12] if final_text else ""

            # Estimate input tokens from prompt (vLLM doesn't expose this directly in stream)
            input_tokens = _estimate_prompt_tokens(args, kwargs)

            record = InferenceRecord(
                model_id=model_id,
                model_hash=sha256_truncated(model_id),
                prompt_hash=prompt_hash,
                response_hash=response_hash,
                latency_ms=elapsed_ms,
                input_tokens=input_tokens,
                output_tokens=total_tokens,
                provider="vllm-native",
                has_refusal=False,
                system_prompt_hash="",
            )
            w.record(record)

            if not state.get("_first_logged"):
                state["_first_logged"] = True
                logger.info(
                    "SWT3 witness active on vLLM engine (model: %s, clearing: %d)",
                    model_id, w.config.clearing_level,
                )

        return wrapper
    return decorator


class VllmWitnessMiddleware:
    """Middleware that patches a vLLM engine for transparent witnessing.

    Usage:
        middleware = VllmWitnessMiddleware()
        middleware.patch(engine)
        # engine.generate() is now witnessed
    """

    def __init__(
        self,
        witness: Optional["Witness"] = None,
        **overrides: Any,
    ) -> None:
        self._witness = witness
        self._overrides = overrides
        self._patched = False

    def patch(self, engine: Any) -> None:
        """Monkey-patch engine.generate with witnessing wrapper."""
        if self._patched:
            logger.warning("Engine already patched -- skipping")
            return
        if not hasattr(engine, "generate"):
            raise AttributeError(
                "Object does not have a generate() method. "
                "Expected AsyncLLMEngine or compatible."
            )
        original = engine.generate
        decorated = witness_engine(witness=self._witness, **self._overrides)(original)
        engine.generate = decorated
        self._patched = True
        logger.info("vLLM engine patched with SWT3 witnessing")

    @property
    def is_patched(self) -> bool:
        return self._patched


# ── Internal helpers ──────────────────────────────────────────────────────


def _resolve_witness(state: dict, overrides: dict) -> Optional["Witness"]:
    """Resolve or lazily create the Witness instance from env."""
    global _warned_unconfigured

    if state["initialized"]:
        return state["witness"]

    # Try DSN first, then individual env vars
    dsn = os.environ.get("SWT3_DSN", "")
    endpoint = os.environ.get("SWT3_ENDPOINT", "")
    api_key = os.environ.get("SWT3_API_KEY", "")

    if not dsn and not (endpoint and api_key):
        if not _warned_unconfigured:
            _warned_unconfigured = True
            logger.debug("SWT3 unconfigured -- vLLM witnessing disabled (no-op)")
        state["initialized"] = True
        state["witness"] = None
        return None

    # Late import to avoid circular deps
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


def _extract_generate_args(args: tuple, kwargs: dict) -> tuple:
    """Extract model_id, prompt_hash, request_id from generate() args.

    vLLM AsyncLLMEngine.generate() signature (v0.20+):
        generate(prompt, sampling_params, request_id, ...)

    The engine itself holds model info via engine.engine.model_config.
    """
    # prompt is typically first arg or kwarg
    prompt = kwargs.get("prompt") or (args[0] if args else "")
    if isinstance(prompt, dict):
        # TokensPrompt or TextPrompt format
        prompt_str = str(prompt.get("prompt_token_ids", prompt.get("prompt", "")))
    elif isinstance(prompt, str):
        prompt_str = prompt
    else:
        prompt_str = str(prompt)

    prompt_hash = hashlib.sha256(prompt_str.encode()).hexdigest()[:12]

    # request_id
    request_id = kwargs.get("request_id", "")
    if not request_id and len(args) >= 3:
        request_id = str(args[2])

    # model_id from env (vLLM doesn't pass model name through generate())
    model_id = os.environ.get("SWT3_MODEL_ID", os.environ.get("MODEL_NAME", "vllm-model"))

    return model_id, prompt_hash, request_id


def _estimate_prompt_tokens(args: tuple, kwargs: dict) -> int:
    """Estimate input token count from prompt.

    If prompt is a TokensPrompt (dict with prompt_token_ids), use its length.
    Otherwise estimate from string length / 4 (rough tokenizer approximation).
    """
    prompt = kwargs.get("prompt") or (args[0] if args else "")
    if isinstance(prompt, dict):
        token_ids = prompt.get("prompt_token_ids", [])
        if token_ids:
            return len(token_ids)
    if isinstance(prompt, str):
        return max(1, len(prompt) // 4)
    return 0
