"""Tests for AI-DEL.3 Delegation Chain Integrity witnessing."""
from unittest.mock import MagicMock

from swt3_ai import Witness


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


class TestWitnessDelegationChain:
    def test_mints_correct_procedure_and_factors(self):
        w = _make_witness()
        p = w.witness_delegation_chain(5, 0)
        assert p.procedure_id == "AI-DEL.3"
        assert p.factor_a == 5.0
        assert p.factor_b == 0.0
        assert p.factor_c == 0.0  # "complete" = 0
        assert p.anchor_fingerprint

    def test_orphaned_hops_recorded(self):
        w = _make_witness()
        p = w.witness_delegation_chain(4, 2, "partial")
        assert p.factor_a == 4.0
        assert p.factor_b == 2.0
        assert p.factor_c == 1.0  # "partial" = 1

    def test_broken_chain(self):
        w = _make_witness()
        p = w.witness_delegation_chain(3, 3, "broken")
        assert p.factor_c == 2.0  # "broken" = 2

    def test_zero_length_chain(self):
        w = _make_witness()
        p = w.witness_delegation_chain(0, 0)
        assert p.factor_a == 0.0
        assert p.factor_b == 0.0

    def test_negative_values_clamped(self):
        w = _make_witness()
        p = w.witness_delegation_chain(-1, -5)
        assert p.factor_a == 0.0
        assert p.factor_b == 0.0

    def test_context_at_cl1(self):
        w = _make_witness(clearing_level=1)
        p = w.witness_delegation_chain(
            3, 0,
            root_grant_fingerprint="abc123",
            leaf_grant_fingerprint="def456",
        )
        ctx = p.ai_context
        assert ctx is not None
        assert ctx["provider"] == "delegation-chain"
        assert ctx["chain_status"] == "complete"
        assert ctx["chain_complete"] is True
        assert ctx["root_grant_fingerprint"] == "abc123"
        assert ctx["leaf_grant_fingerprint"] == "def456"

    def test_context_stripped_at_cl3(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_delegation_chain(3, 1, "partial",
                                       root_grant_fingerprint="abc")
        assert p.ai_context is None

    def test_unknown_status_defaults_to_complete(self):
        w = _make_witness()
        p = w.witness_delegation_chain(2, 0, "unknown_status")
        assert p.factor_c == 0.0  # default to "complete" = 0

    def test_model_id_reflects_status(self):
        w = _make_witness()
        p = w.witness_delegation_chain(3, 0, "complete")
        assert p.ai_model_id == "delegation-chain-complete"

        p2 = w.witness_delegation_chain(3, 1, "partial")
        assert p2.ai_model_id == "delegation-chain-partial"

    def test_enqueue_called(self):
        w = _make_witness()
        w.witness_delegation_chain(2, 0)
        w._buffer.enqueue_many.assert_called_once()
