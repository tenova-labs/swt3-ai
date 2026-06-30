"""SWT3 AI Witness SDK -- LangGraph Adapter.

Wraps a LangGraph CompiledGraph to witness every graph invocation.
Supports invoke(), ainvoke(), stream(), and astream() methods.

Usage:

    from swt3_ai.adapters.langgraph import wrap_langgraph

    witnessed = wrap_langgraph(compiled_graph, witness)
    result = witnessed.invoke({"messages": [("user", "Hello")]})

Configuration:
    1. SWT3_DSN=https://axm_live_xxx@sovereign.tenova.io/MY_ENCLAVE
    2. SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID
    3. wrap_langgraph(graph, witness=my_witness)

Duck-typed: works with any object that has an invoke() method.
No langgraph import required.

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

logger = logging.getLogger("swt3_ai.langgraph")


def _resolve_model_id(graph: Any, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    env_id = os.environ.get("SWT3_MODEL_ID") or os.environ.get("LANGGRAPH_MODEL")
    if env_id:
        return env_id
    if hasattr(graph, "name") and graph.name:
        return str(graph.name)
    return "langgraph-agent"


def _stringify(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    try:
        return json.dumps(val, default=str)
    except Exception:
        return str(val)


def _build_record(
    model_id: str,
    input_val: Any,
    output_val: Any,
    elapsed_ms: int,
) -> InferenceRecord:
    return InferenceRecord(
        model_id=model_id,
        model_hash=sha256_truncated(model_id),
        prompt_hash=sha256_truncated(_stringify(input_val)),
        response_hash=sha256_truncated(_stringify(output_val)),
        latency_ms=elapsed_ms,
        input_tokens=0,
        output_tokens=0,
        guardrails_active=0,
        guardrails_required=0,
        guardrail_passed=True,
        has_refusal=False,
        provider="langgraph",
        guardrail_names=[],
    )


def wrap_langgraph(
    graph: Any,
    witness: Optional["Witness"] = None,
    model_id: Optional[str] = None,
    **overrides: Any,
) -> Any:
    """Wrap a LangGraph CompiledGraph to witness every invocation.

    Args:
        graph: Any object with an invoke() method (CompiledGraph or compatible).
        witness: Explicit Witness instance. If None, auto-creates from env.
        model_id: Model identifier override.
        **overrides: Override config (clearing_level, agent_id, etc.)

    Returns:
        Proxy object that behaves identically to the original graph
        but mints a witness anchor on each invocation.
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
        logger.debug("No witness configured; LangGraph adapter is a no-op")
        return graph

    mid = _resolve_model_id(graph, model_id)

    class LangGraphProxy:
        """Transparent proxy that witnesses LangGraph invocations."""

        __slots__ = ("__target", "__witness")

        def __init__(self, target: Any, w: "Witness"):
            object.__setattr__(self, "_LangGraphProxy__target", target)
            object.__setattr__(self, "_LangGraphProxy__witness", w)

        def invoke(self, input_val: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            result = self.__target.invoke(input_val, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            record = _build_record(mid, input_val, result, elapsed)
            self.__witness.record(record)
            return result

        async def ainvoke(self, input_val: Any, *args: Any, **kwargs: Any) -> Any:
            if not hasattr(self.__target, "ainvoke"):
                raise AttributeError("ainvoke")
            start = time.perf_counter()
            result = await self.__target.ainvoke(input_val, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            record = _build_record(mid, input_val, result, elapsed)
            self.__witness.record(record)
            return result

        def stream(self, input_val: Any, *args: Any, **kwargs: Any) -> Any:
            if not hasattr(self.__target, "stream"):
                raise AttributeError("stream")
            start = time.perf_counter()
            last_chunk = None
            for chunk in self.__target.stream(input_val, *args, **kwargs):
                last_chunk = chunk
                yield chunk
            elapsed = round((time.perf_counter() - start) * 1000)
            record = _build_record(mid, input_val, last_chunk, elapsed)
            self.__witness.record(record)

        async def astream(self, input_val: Any, *args: Any, **kwargs: Any) -> Any:
            if not hasattr(self.__target, "astream"):
                raise AttributeError("astream")
            start = time.perf_counter()
            last_chunk = None
            async for chunk in self.__target.astream(input_val, *args, **kwargs):
                last_chunk = chunk
                yield chunk
            elapsed = round((time.perf_counter() - start) * 1000)
            record = _build_record(mid, input_val, last_chunk, elapsed)
            self.__witness.record(record)

        def __getattr__(self, name: str) -> Any:
            if name.startswith("_"):
                raise AttributeError(name)
            return getattr(self.__target, name)

    return LangGraphProxy(graph, witness)
