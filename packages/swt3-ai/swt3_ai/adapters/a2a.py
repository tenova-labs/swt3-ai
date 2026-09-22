"""SWT3 AI Witness SDK -- A2A (Agent-to-Agent) Protocol Adapter.

Wraps any object with a send() method (Google A2A protocol pattern),
minting witness anchors on each inter-agent message without modifying
the agent logic or adding protocol dependencies.

v0.7.3: Also wraps create_task/get_task/cancel_task to auto-mint
AI-A2A.1 (task lifecycle) and AI-A2A.3 (context chain) anchors
when A2A task state transitions are detected.

Usage:

    from swt3_ai.adapters.a2a import wrap_a2a

    witnessed = wrap_a2a(agent, witness)
    result = witnessed.send({"text": "Analyze this data"})

    # Task lifecycle auto-witnessed (if agent supports create_task):
    task = witnessed.create_task({"text": "Analyze data"})
    task = witnessed.get_task(task_id)  # state transitions witnessed

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
from typing import Any, Dict, Optional, TYPE_CHECKING

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


_A2A_STATE_MAP: Dict[str, int] = {
    "submitted": 0, "working": 1, "input-required": 2, "input_required": 2,
    "completed": 3, "failed": 4, "canceled": 5, "rejected": 6,
}


def _extract_task_state(result: Any) -> Optional[int]:
    """Extract A2A task state code from a result object (duck-typed)."""
    status = None
    if isinstance(result, dict):
        status = result.get("status") or result.get("state")
        if isinstance(status, dict):
            status = status.get("state") or status.get("status")
    elif hasattr(result, "status"):
        status = result.status
        if hasattr(status, "state"):
            status = status.state
    if isinstance(status, str):
        return _A2A_STATE_MAP.get(status.lower())
    if isinstance(status, int) and 0 <= status <= 6:
        return status
    return None


def _extract_context_id(result: Any) -> Optional[str]:
    """Extract A2A contextId from a result object (duck-typed)."""
    if isinstance(result, dict):
        return result.get("contextId") or result.get("context_id")
    if hasattr(result, "contextId"):
        return result.contextId
    if hasattr(result, "context_id"):
        return result.context_id
    return None


def _extract_task_id(result: Any) -> Optional[str]:
    """Extract A2A task ID from a result object (duck-typed)."""
    if isinstance(result, dict):
        return result.get("id") or result.get("task_id") or result.get("taskId")
    if hasattr(result, "id"):
        return result.id
    if hasattr(result, "task_id"):
        return result.task_id
    return None


def wrap_a2a(
    agent: Any,
    witness: Optional["Witness"] = None,
    model_id: Optional[str] = None,
    **overrides: Any,
) -> Any:
    """Wrap an A2A agent to witness every send() and handle_message() call.

    Also wraps create_task/get_task/cancel_task to auto-mint AI-A2A.1
    (task lifecycle) and AI-A2A.3 (context chain) anchors when A2A
    task state transitions are detected in return values.

    Args:
        agent: Any object with a send() method (A2A agent or compatible).
        witness: Explicit Witness instance. If None, auto-creates from env.
        model_id: Model identifier override.
        **overrides: Override config (clearing_level, agent_id, etc.)

    Returns:
        Proxy object that behaves identically to the original agent
        but mints witness anchors on each interaction.
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
        """Transparent proxy that witnesses A2A agent interactions."""

        __slots__ = ("__target", "__witness", "__context_agents")

        def __init__(self, target: Any, w: "Witness"):
            object.__setattr__(self, "_A2AProxy__target", target)
            object.__setattr__(self, "_A2AProxy__witness", w)
            object.__setattr__(self, "_A2AProxy__context_agents", {})

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

        def _witness_task_result(self, result: Any, elapsed: int) -> None:
            """Auto-mint AI-A2A.1 and AI-A2A.3 from task result."""
            state = _extract_task_state(result)
            if state is None:
                return
            task_id = _extract_task_id(result)
            context_id = _extract_context_id(result)

            try:
                self.__witness.witness_task_lifecycle(
                    state_code=state,
                    latency_ms=elapsed,
                    depth=1,
                    task_id=task_id,
                    context_id=context_id,
                )
            except Exception:
                logger.debug("Failed to auto-witness task lifecycle", exc_info=True)

            if context_id:
                agents = self.__context_agents
                if context_id not in agents:
                    agents[context_id] = set()
                agents[context_id].add(mid)
                try:
                    self.__witness.witness_context_chain(
                        chain_length=1,
                        context_id=context_id,
                        agents_in_chain=len(agents[context_id]),
                        current_agent_id=mid,
                    )
                except Exception:
                    logger.debug("Failed to auto-witness context chain", exc_info=True)

        def send(self, message: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            result = self.__target.send(message, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._record(message, result, elapsed)
            self._witness_task_result(result, elapsed)
            return result

        def handle_message(self, message: Any, *args: Any, **kwargs: Any) -> Any:
            if not hasattr(self.__target, "handle_message"):
                raise AttributeError("handle_message")
            start = time.perf_counter()
            result = self.__target.handle_message(message, *args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._record(message, result, elapsed)
            self._witness_task_result(result, elapsed)
            return result

        def create_task(self, *args: Any, **kwargs: Any) -> Any:
            if not hasattr(self.__target, "create_task"):
                raise AttributeError("create_task")
            start = time.perf_counter()
            result = self.__target.create_task(*args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._witness_task_result(result, elapsed)
            return result

        def get_task(self, *args: Any, **kwargs: Any) -> Any:
            if not hasattr(self.__target, "get_task"):
                raise AttributeError("get_task")
            start = time.perf_counter()
            result = self.__target.get_task(*args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._witness_task_result(result, elapsed)
            return result

        def cancel_task(self, *args: Any, **kwargs: Any) -> Any:
            if not hasattr(self.__target, "cancel_task"):
                raise AttributeError("cancel_task")
            start = time.perf_counter()
            result = self.__target.cancel_task(*args, **kwargs)
            elapsed = round((time.perf_counter() - start) * 1000)
            self._witness_task_result(result, elapsed)
            return result

        def __getattr__(self, name: str) -> Any:
            if name.startswith("_"):
                raise AttributeError(name)
            return getattr(self.__target, name)

    return A2AProxy(agent, witness)
