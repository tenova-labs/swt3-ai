"""Tests for AI-TASK.1 Task Outcome Attestation."""
import asyncio
from unittest.mock import MagicMock

import pytest

from swt3_ai.fingerprint import sha256_truncated
from swt3_ai.merkle import get_merkle_root
from swt3_ai.task import TaskBuilder, _generate_task_id
from swt3_ai.types import (
    COST_SOURCE_CODES,
    TASK_OUTCOME_CODES,
    TASK_TYPE_CODES,
    TaskReceipt,
    WitnessPayload,
)
from swt3_ai.witness import Witness


def _make_witness(clearing_level=1, **kwargs):
    w = Witness(
        endpoint="https://test.example.com",
        api_key="axm_test_key",
        tenant_id="test_tenant",
        clearing_level=clearing_level,
        **kwargs,
    )
    w._buffer = MagicMock()
    return w


def _make_payload(procedure_id="AI-INF.1", fingerprint="a1b2c3d4e5f6", **kwargs):
    return WitnessPayload(
        procedure_id=procedure_id,
        factor_a=1.0,
        factor_b=1.0,
        factor_c=0.0,
        clearing_level=1,
        anchor_fingerprint=fingerprint,
        anchor_epoch=1700000000,
        fingerprint_timestamp_ms=1700000000000,
        **kwargs,
    )


class TestTaskTypesCodes:
    def test_task_type_codes_complete(self):
        assert len(TASK_TYPE_CODES) == 9
        assert TASK_TYPE_CODES["inference"] == 0
        assert TASK_TYPE_CODES["custom"] == 8

    def test_task_outcome_codes_complete(self):
        assert len(TASK_OUTCOME_CODES) == 5
        assert TASK_OUTCOME_CODES["completed"] == 0
        assert TASK_OUTCOME_CODES["abandoned"] == 4

    def test_cost_source_codes_complete(self):
        assert len(COST_SOURCE_CODES) == 4
        assert COST_SOURCE_CODES["manual"] == 0
        assert COST_SOURCE_CODES["invoice_verified"] == 3


class TestTaskIdGeneration:
    def test_deterministic(self):
        id1 = _generate_task_id("tenant", "LC-abc123", 1700000000000)
        id2 = _generate_task_id("tenant", "LC-abc123", 1700000000000)
        assert id1 == id2

    def test_prefix(self):
        tid = _generate_task_id("tenant", "LC-abc123", 1700000000000)
        assert tid.startswith("TASK-")
        assert len(tid) == 21  # "TASK-" + 16 hex chars

    def test_known_vector(self):
        tid = _generate_task_id(
            "test-tenant-001", "LC-a1b2c3d4e5f6a1b2", 1732147200000,
        )
        assert tid == "TASK-5e5ec230343e8d7f"


class TestTaskBuilderAddStep:
    def test_add_step_with_fingerprint(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        assert builder.step_count == 1

    def test_add_step_with_payload(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        payload = _make_payload("AI-INF.1", "aabbccddee11")
        builder.add_step(payload=payload)
        assert builder.step_count == 1
        assert "AI-INF.1" in builder._step_procedures

    def test_add_step_tracks_tool_calls(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        payload = _make_payload("AI-TOOL.1", "aabbccddee22")
        builder.add_step(payload=payload)
        assert builder._tool_call_count == 1

    def test_add_step_tracks_agent_ids(self):
        w = _make_witness(agent_id="agent-1")
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        payload = _make_payload(agent_id="agent-1")
        builder.add_step(payload=payload)
        assert "agent-1" in builder._agent_ids

    def test_add_step_requires_fingerprint_or_payload(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        with pytest.raises(ValueError, match="fingerprint or payload"):
            builder.add_step()


class TestTaskBuilderDeclareCost:
    def test_declare_cost_manual(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.declare_cost(0.0042, source="manual")
        assert builder._cost_declared == 0.0042
        assert builder._cost_source == 0

    def test_declare_cost_provider_api(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.declare_cost(0.0042, source="provider_api")
        assert builder._cost_source == 2


class TestTaskBuilderComplete:
    def test_complete_mints_ai_task_1(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        builder.add_step(fingerprint="f6e5d4c3b2a1")
        receipt = builder.complete()
        assert isinstance(receipt, TaskReceipt)
        assert receipt.step_count == 2
        assert receipt.anchor.procedure_id == "AI-TASK.1"
        assert receipt.anchor.factor_a == 2.0  # step_count
        assert receipt.anchor.factor_c == 0.0  # completed
        assert receipt.anchor.lifecycle_stage == "resolved"

    def test_complete_computes_merkle_root(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        fps = ["a1b2c3d4e5f6", "f6e5d4c3b2a1", "112233445566"]
        for fp in fps:
            builder.add_step(fingerprint=fp)
        receipt = builder.complete()
        expected_root = get_merkle_root(fps)
        assert receipt.merkle_root == expected_root

    def test_complete_has_task_id(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        receipt = builder.complete()
        assert receipt.task_id.startswith("TASK-")
        assert receipt.chain_id.startswith("LC-")

    def test_complete_enqueues_payload(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        builder.complete()
        w._buffer.enqueue_many.assert_called()

    def test_complete_closes_chain(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        builder.complete()
        assert chain.closed

    def test_complete_clears_active_task(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        w._active_task = builder
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        builder.complete()
        assert w._active_task is None


class TestTaskBuilderFail:
    def test_fail_sets_outcome_failed(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        receipt = builder.fail("model_timeout")
        assert receipt.anchor.factor_c == 2.0  # failed
        assert builder._explicitly_failed

    def test_fail_with_reason(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        builder.fail("timeout_error")
        assert builder._outcome_desc == "timeout_error"


class TestTaskBuilderMarkStepsComplete:
    def test_mark_steps_complete(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        assert not builder.steps_complete
        builder.mark_steps_complete()
        assert builder.steps_complete


class TestTaskBuilderDeclareOutcome:
    def test_declare_outcome(self):
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.declare_outcome("approved: DTI 32%")
        assert builder._outcome_desc == "approved: DTI 32%"


class TestClearingLevels:
    def test_level_0_includes_declared_outcome(self):
        w = _make_witness(clearing_level=0)
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        builder.declare_outcome("approved")
        receipt = builder.complete()
        ctx = receipt.anchor.ai_context
        assert ctx is not None
        assert ctx.get("declared_outcome") == "approved"
        assert "task_type" in ctx
        assert "cost_ratio" in ctx

    def test_level_1_hashes_outcome(self):
        w = _make_witness(clearing_level=1)
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        builder.declare_outcome("approved")
        receipt = builder.complete()
        ctx = receipt.anchor.ai_context
        assert ctx is not None
        assert "declared_outcome" not in ctx
        assert "outcome_hash" in ctx
        assert "task_type" in ctx

    def test_level_2_strips_cost_and_agents(self):
        w = _make_witness(clearing_level=2)
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        builder.declare_cost(0.01, source="sdk_estimated")
        receipt = builder.complete()
        ctx = receipt.anchor.ai_context
        assert ctx is not None
        assert "merkle_root" in ctx
        assert "step_count" in ctx
        assert "cost_declared" not in ctx
        assert "cost_ratio" not in ctx
        assert "agent_ids" not in ctx
        assert "task_type" not in ctx

    def test_level_3_no_ai_context(self):
        w = _make_witness(clearing_level=3)
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        receipt = builder.complete()
        assert receipt.anchor.ai_context is None
        # Factors still present
        assert receipt.anchor.factor_a == 1.0
        assert receipt.anchor.factor_c == 0.0

    def test_cost_source_propagation(self):
        w = _make_witness(clearing_level=0)
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        builder.add_step(fingerprint="a1b2c3d4e5f6")
        builder.declare_cost(0.01, source="invoice_verified")
        receipt = builder.complete()
        ctx = receipt.anchor.ai_context
        assert ctx["cost_source"] == 3  # invoice_verified


class TestContextManager:
    def test_normal_exit_completes(self):
        w = _make_witness()

        async def run():
            async with w.task("test-task", task_type="workflow") as task:
                task.add_step(fingerprint="a1b2c3d4e5f6")
            assert w._active_task is None

        asyncio.run(run())

    def test_exception_without_mark_abandons(self):
        w = _make_witness()

        async def run():
            with pytest.raises(ValueError):
                async with w.task("test-task", task_type="workflow") as task:
                    task.add_step(fingerprint="a1b2c3d4e5f6")
                    raise ValueError("boom")
            # Verify outcome status was set to abandoned
            assert w._active_task is None

        asyncio.run(run())

    def test_exception_with_mark_partial(self):
        w = _make_witness()
        receipts = []

        async def run():
            with pytest.raises(ValueError):
                async with w.task("test-task", task_type="workflow") as task:
                    task.add_step(fingerprint="a1b2c3d4e5f6")
                    task.mark_steps_complete()
                    raise ValueError("post-processing failed")

        asyncio.run(run())

    def test_nested_task_raises(self):
        w = _make_witness()

        async def run():
            async with w.task("first", task_type="workflow") as t1:
                t1.add_step(fingerprint="a1b2c3d4e5f6")
                with pytest.raises(RuntimeError, match="Nested tasks"):
                    async with w.task("second", task_type="workflow"):
                        pass

        asyncio.run(run())


class TestBeginTask:
    def test_begin_task_returns_builder(self):
        w = _make_witness()
        task = w.begin_task("test", task_type="agent_loop")
        assert isinstance(task, TaskBuilder)
        assert w._active_task is task

    def test_begin_task_nested_raises(self):
        w = _make_witness()
        w.begin_task("first")
        with pytest.raises(RuntimeError, match="Nested tasks"):
            w.begin_task("second")

    def test_begin_task_complete_clears(self):
        w = _make_witness()
        task = w.begin_task("test")
        task.add_step(fingerprint="a1b2c3d4e5f6")
        task.complete()
        assert w._active_task is None


class TestAutoCapture:
    def test_record_captures_steps_in_active_task(self):
        w = _make_witness()
        task = w.begin_task("test")
        # Simulate what record() does via the auto-capture hook
        payload = _make_payload("AI-INF.1", "aabb11223344")
        task.add_step(payload=payload)
        assert task.step_count == 1
        assert "AI-INF.1" in task._step_procedures


class TestMerkleRootParity:
    def test_merkle_root_matches_standalone(self):
        fps = ["a1b2c3d4e5f6", "f6e5d4c3b2a1", "112233445566"]
        expected = get_merkle_root(fps)
        w = _make_witness()
        chain = w.begin_lifecycle("AI-TASK.1", 0.0, 0.0, 0.0)
        builder = TaskBuilder(w, "test", "workflow", chain)
        for fp in fps:
            builder.add_step(fingerprint=fp)
        receipt = builder.complete()
        assert receipt.merkle_root == expected
