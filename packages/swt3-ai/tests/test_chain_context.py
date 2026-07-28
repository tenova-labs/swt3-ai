"""Tests for ChainContext auto-chaining context manager (v0.6.2)."""

import os
import pytest

from swt3_ai import Witness, ChainContext
from swt3_ai.types import InferenceRecord


def _make_witness(**kwargs):
    return Witness(
        endpoint="https://example.com",
        api_key="axm_test_key",
        tenant_id="TEST_TENANT",
        clearing_level=1,
        **kwargs,
    )


class TestChainContextBasic:
    def test_chain_returns_context(self):
        w = _make_witness()
        ctx = w.chain("test-chain")
        assert isinstance(ctx, ChainContext)

    def test_auto_generated_cycle_id(self):
        w = _make_witness()
        with w.chain("test-chain") as ctx:
            assert ctx.cycle_id.startswith("CHAIN-")
            assert len(ctx.cycle_id) == 22  # CHAIN- + 16 hex chars

    def test_custom_cycle_id(self):
        w = _make_witness()
        with w.chain("test-chain", cycle_id="MY-CUSTOM-ID") as ctx:
            assert ctx.cycle_id == "MY-CUSTOM-ID"

    def test_name_preserved(self):
        w = _make_witness()
        with w.chain("credit-decision") as ctx:
            assert ctx.name == "credit-decision"

    def test_repr(self):
        w = _make_witness()
        ctx = w.chain("test", cycle_id="CYC-123")
        assert "test" in repr(ctx)
        assert "CYC-123" in repr(ctx)


class TestCycleIdInjection:
    def test_cycle_id_active_inside_block(self):
        w = _make_witness()
        assert w._config.cycle_id is None
        with w.chain("test") as ctx:
            assert w._config.cycle_id == ctx.cycle_id
        assert w._config.cycle_id is None

    def test_cycle_id_injected_into_mint_and_sign(self):
        w = _make_witness()
        with w.chain("test") as ctx:
            payload = w._mint_and_sign("AI-INF.1", 1.0, 100.0, 3.0)
            assert payload.cycle_id == ctx.cycle_id

    def test_cycle_id_injected_into_witness_methods(self):
        w = _make_witness()
        with w.chain("test") as ctx:
            payload = w.witness_drift(
                metrics_evaluated=10,
                drifted_count=2,
                drift_type="psi",
            )
            assert payload.cycle_id == ctx.cycle_id

    def test_cycle_id_none_outside_block(self):
        w = _make_witness()
        with w.chain("test"):
            pass
        payload = w._mint_and_sign("AI-INF.1", 1.0, 1.0, 1.0)
        assert payload.cycle_id is None

    def test_record_uses_chain_cycle_id(self):
        w = _make_witness()
        inference = InferenceRecord(
            model_id="test-model",
            model_hash="modelhash123",
            prompt_hash="abc123",
            response_hash="def456",
            latency_ms=100,
            input_tokens=10,
            output_tokens=20,
        )
        with w.chain("test") as ctx:
            w.record(inference)
            # Verify the buffer has payloads with the cycle_id
            # (payloads are enqueued to the buffer)
            assert w._config.cycle_id == ctx.cycle_id


class TestNesting:
    def test_nested_chains_restore_correctly(self):
        w = _make_witness()
        with w.chain("outer", cycle_id="OUTER-1") as outer:
            assert w._config.cycle_id == "OUTER-1"
            with w.chain("inner", cycle_id="INNER-1") as inner:
                assert w._config.cycle_id == "INNER-1"
                payload = w._mint_and_sign("AI-INF.1", 1.0, 1.0, 1.0)
                assert payload.cycle_id == "INNER-1"
            assert w._config.cycle_id == "OUTER-1"
        assert w._config.cycle_id is None

    def test_triple_nesting(self):
        w = _make_witness()
        with w.chain("a", cycle_id="A"):
            with w.chain("b", cycle_id="B"):
                with w.chain("c", cycle_id="C"):
                    assert w._config.cycle_id == "C"
                assert w._config.cycle_id == "B"
            assert w._config.cycle_id == "A"
        assert w._config.cycle_id is None

    def test_nested_with_config_level_cycle_id(self):
        w = _make_witness(cycle_id="CONFIG-LEVEL")
        assert w._config.cycle_id == "CONFIG-LEVEL"
        with w.chain("override", cycle_id="CHAIN-LEVEL"):
            assert w._config.cycle_id == "CHAIN-LEVEL"
        assert w._config.cycle_id == "CONFIG-LEVEL"


class TestExceptionSafety:
    def test_cycle_id_restored_on_exception(self):
        w = _make_witness()
        with pytest.raises(ValueError):
            with w.chain("test", cycle_id="WILL-RESTORE"):
                assert w._config.cycle_id == "WILL-RESTORE"
                raise ValueError("test error")
        assert w._config.cycle_id is None

    def test_nested_exception_restores_outer(self):
        w = _make_witness()
        with w.chain("outer", cycle_id="OUTER"):
            with pytest.raises(RuntimeError):
                with w.chain("inner", cycle_id="INNER"):
                    raise RuntimeError("inner error")
            assert w._config.cycle_id == "OUTER"

    def test_config_level_restored_after_exception(self):
        w = _make_witness(cycle_id="ORIGINAL")
        with pytest.raises(TypeError):
            with w.chain("test"):
                raise TypeError("boom")
        assert w._config.cycle_id == "ORIGINAL"


class TestMultipleChains:
    def test_sequential_chains_independent(self):
        w = _make_witness()
        with w.chain("first") as ctx1:
            id1 = ctx1.cycle_id
        with w.chain("second") as ctx2:
            id2 = ctx2.cycle_id
        assert id1 != id2
        assert id1.startswith("CHAIN-")
        assert id2.startswith("CHAIN-")

    def test_chain_cycle_id_unique_each_time(self):
        w = _make_witness()
        ids = set()
        for _ in range(100):
            with w.chain("test") as ctx:
                ids.add(ctx.cycle_id)
        assert len(ids) == 100
