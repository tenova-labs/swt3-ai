"""AI-TASK.1: Task Outcome Attestation (v8.3).

Witnesses composite AI tasks -- bounded units of work comprising one or
more inferences -- and cryptographically binds the declared outcome to
the evidence chain of constituent steps via a Merkle rollup.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from .fingerprint import sha256_truncated, timestamp_ms
from .merkle import get_merkle_root
from .types import (
    COST_SOURCE_CODES,
    TASK_OUTCOME_CODES,
    TASK_TYPE_CODES,
    TaskReceipt,
    WitnessPayload,
)

if TYPE_CHECKING:
    from .witness import LifecycleChain, Witness

logger = logging.getLogger("swt3_ai.task")

_TERMINAL_STAGES = frozenset({"resolved", "abandoned", "superseded"})


def _generate_task_id(tenant_id: str, chain_id: str, ts_ms: int) -> str:
    """Generate a deterministic task ID from tenant, chain, and timestamp."""
    h = sha256_truncated(f"TASK:{tenant_id}:{chain_id}:{ts_ms}", 16)
    return f"TASK-{h}"


def _estimate_cost(
    input_tokens: int, output_tokens: int, model_id: str,
) -> float:
    """Estimate inference cost from token counts and model ID.

    Stub for v8.3 -- returns 0.0. Provider billing API adapters
    will populate model pricing tables in v8.4+.
    """
    return 0.0


class TaskBuilder:
    """Accumulates step anchors and mints AI-TASK.1 on completion.

    Reuses existing LifecycleChain infrastructure for anchor linking.
    The lifecycle chain is initiated when the task starts and resolved
    (or abandoned) when the task completes.

    Usage (context manager -- recommended):
        async with witness.task("loan-underwriting", task_type="workflow") as task:
            result = await client.chat.completions.create(...)
            task.declare_cost(declared=0.0042, source="sdk_estimated")
            task.declare_outcome("approved: DTI 32%")

    Usage (manual):
        task = witness.begin_task("fraud-detection", task_type="agent_loop")
        task.add_step(fingerprint="a1b2c3d4e5f6")
        receipt = task.complete()
    """

    def __init__(
        self,
        witness: "Witness",
        name: str,
        task_type: str,
        chain: "LifecycleChain",
    ) -> None:
        self._witness = witness
        self._name = name
        self._task_type = task_type
        self._chain = chain
        self._steps: List[str] = []
        self._step_procedures: Set[str] = set()
        self._start_ms = timestamp_ms()[0]
        self._cost_declared: Optional[float] = None
        self._cost_witnessed: float = 0.0
        self._cost_source: int = 0
        self._outcome_desc: Optional[str] = None
        self._outcome_status: int = TASK_OUTCOME_CODES["completed"]
        self._steps_complete: bool = False
        self._explicitly_failed: bool = False
        self._tool_call_count: int = 0
        self._agent_ids: Set[str] = set()

    @property
    def chain_id(self) -> str:
        return self._chain.chain_id

    @property
    def step_count(self) -> int:
        return len(self._steps)

    @property
    def steps_complete(self) -> bool:
        return self._steps_complete

    def add_step(
        self,
        *,
        fingerprint: Optional[str] = None,
        payload: Optional[WitnessPayload] = None,
    ) -> None:
        """Register a sub-inference anchor as a task step.

        Either provide a raw fingerprint string or a WitnessPayload object.
        The payload path is higher trust -- it extracts the fingerprint and
        accumulates procedure IDs, tool calls, agent IDs, and token costs.
        """
        if payload is not None:
            fingerprint = payload.anchor_fingerprint
            if payload.procedure_id:
                self._step_procedures.add(payload.procedure_id)
            if payload.ai_input_tokens and payload.ai_output_tokens:
                model_id = payload.ai_model_id or "unknown"
                self._cost_witnessed += _estimate_cost(
                    payload.ai_input_tokens, payload.ai_output_tokens, model_id,
                )
            if getattr(payload, "tool_name", None) or (
                payload.procedure_id == "AI-TOOL.1"
            ):
                self._tool_call_count += 1
            if payload.agent_id:
                self._agent_ids.add(payload.agent_id)
        if not fingerprint:
            raise ValueError("Either fingerprint or payload is required")
        self._steps.append(fingerprint)

    def declare_cost(
        self, declared: float, source: str = "manual",
    ) -> None:
        """Declare the provider's stated cost for the task (USD).

        Args:
            declared: Cost in USD.
            source: Trust level -- "manual", "sdk_estimated",
                    "provider_api", or "invoice_verified".
        """
        self._cost_declared = declared
        self._cost_source = COST_SOURCE_CODES.get(source, 0)

    def declare_outcome(self, description: str) -> None:
        """Declare the task outcome (hashed at clearing level 1+)."""
        self._outcome_desc = description

    def mark_steps_complete(self) -> None:
        """Mark all inference steps as successfully completed.

        Call this after all AI inferences are done but before post-processing.
        If the context manager exits via exception after this call, the task
        is recorded as "partial" (outcome_status=1) instead of "abandoned" (4).
        """
        self._steps_complete = True

    def fail(self, reason: str = "") -> TaskReceipt:
        """Mark the task as failed and mint the terminal anchor."""
        self._explicitly_failed = True
        self._outcome_status = TASK_OUTCOME_CODES["failed"]
        if reason:
            self._outcome_desc = reason
        return self._finalize()

    def complete(self) -> TaskReceipt:
        """Finalize the task and mint the AI-TASK.1 anchor."""
        return self._finalize()

    def _finalize(self) -> TaskReceipt:
        """Compute Merkle root, build envelope, mint terminal anchor."""
        end_ms = timestamp_ms()[0]
        duration = int(end_ms - self._start_ms)

        # Merkle root from step fingerprints
        merkle_root = get_merkle_root(self._steps) if self._steps else ""

        # Cost reconciliation
        cost_ratio = 0
        if self._cost_declared and self._cost_declared > 0 and self._cost_witnessed > 0:
            cost_ratio = int((self._cost_witnessed / self._cost_declared) * 1000)

        # Factors
        fa = float(len(self._steps))
        fb = float(cost_ratio)
        fc = float(self._outcome_status)

        # Task ID
        task_id = _generate_task_id(
            self._witness._tenant_id, self._chain.chain_id, self._start_ms,
        )

        # Mint terminal anchor (bypass chain._mint for clearing-level control)
        payload = self._witness._mint_and_sign("AI-TASK.1", fa, fb, fc)
        payload.lifecycle_chain_id = self._chain.chain_id
        payload.lifecycle_parent = self._chain.last_fingerprint
        payload.lifecycle_stage = "resolved"

        # Build clearing-level-aware envelope
        clearing = self._witness._config.clearing_level
        envelope = self._build_envelope(
            task_id, merkle_root, duration, cost_ratio, clearing,
        )

        if clearing < 3 and envelope:
            payload.ai_context = {"provider": "task", **envelope}

        # Enqueue and close chain
        self._witness._buffer.enqueue_many([payload])
        self._chain._last_fingerprint = payload.anchor_fingerprint
        self._chain._anchor_count += 1
        self._chain._closed = True

        # Clear active task on witness (manual builder cleanup)
        if self._witness._active_task is self:
            self._witness._active_task = None

        return TaskReceipt(
            task_id=task_id,
            merkle_root=merkle_root,
            step_count=len(self._steps),
            chain_id=self._chain.chain_id,
            duration_ms=duration,
            cost_ratio=cost_ratio if cost_ratio else None,
            anchor=payload,
        )

    def _build_envelope(
        self,
        task_id: str,
        merkle_root: str,
        duration: int,
        cost_ratio: int,
        clearing: int,
    ) -> Dict[str, Any]:
        """Build the task envelope dict with clearing-level filtering."""
        if clearing >= 3:
            return {}

        envelope: Dict[str, Any] = {
            "task_id": task_id,
            "outcome_status": self._outcome_status,
            "outcome_hash": sha256_truncated(self._outcome_desc or "", 16),
            "step_count": len(self._steps),
            "merkle_root": merkle_root,
            "step_procedures": sorted(self._step_procedures),
            "duration_ms": duration,
            "start_epoch": int(self._start_ms // 1000),
            "end_epoch": int((self._start_ms + duration) // 1000),
            "tool_call_count": self._tool_call_count,
        }

        if clearing == 0 and self._outcome_desc:
            envelope["declared_outcome"] = self._outcome_desc

        if clearing <= 1:
            envelope["task_type"] = self._task_type
            envelope["lifecycle_chain_id"] = self._chain.chain_id
            if self._cost_declared is not None:
                envelope["cost_declared"] = int(self._cost_declared * 1_000_000)
                envelope["cost_source"] = self._cost_source
            if self._cost_witnessed > 0:
                envelope["cost_witnessed"] = int(self._cost_witnessed * 1_000_000)
            envelope["cost_ratio"] = cost_ratio
            envelope["agent_ids"] = [
                sha256_truncated(a, 8) if clearing >= 1 else a
                for a in sorted(self._agent_ids)
            ]

        return envelope
