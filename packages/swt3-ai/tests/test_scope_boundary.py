"""Tests for AI-SAND.2 Scope Boundary Attestation witnessing."""
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


class TestWitnessScopeBoundary:
    def test_mints_correct_procedure_clean(self):
        w = _make_witness()
        p = w.witness_scope_boundary(100, 0)
        assert p.procedure_id == "AI-SAND.2"
        assert p.factor_a == 100.0
        assert p.factor_b == 0.0
        assert p.factor_c == 0.0  # "blocked" = 0 (default)
        assert p.anchor_fingerprint

    def test_out_of_scope_actions_recorded(self):
        w = _make_witness()
        p = w.witness_scope_boundary(50, 3, "logged")
        assert p.factor_a == 50.0
        assert p.factor_b == 3.0
        assert p.factor_c == 1.0  # "logged" = 1

    def test_escalated_response(self):
        w = _make_witness()
        p = w.witness_scope_boundary(20, 5, "escalated")
        assert p.factor_c == 2.0

    def test_allowed_with_override(self):
        w = _make_witness()
        p = w.witness_scope_boundary(10, 2, "allowed_with_override")
        assert p.factor_c == 3.0

    def test_negative_values_clamped(self):
        w = _make_witness()
        p = w.witness_scope_boundary(-5, -1)
        assert p.factor_a == 0.0
        assert p.factor_b == 0.0

    def test_context_at_cl1(self):
        w = _make_witness(clearing_level=1)
        p = w.witness_scope_boundary(
            100, 0,
            scope_definition_hash="abc123",
            observation_window_ms=5000,
        )
        ctx = p.ai_context
        assert ctx is not None
        assert ctx["provider"] == "scope-governance"
        assert ctx["boundary_response"] == "blocked"
        assert ctx["scope_clean"] is True
        assert ctx["scope_definition_hash"] == "abc123"
        assert ctx["observation_window_ms"] == 5000

    def test_context_stripped_at_cl3(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_scope_boundary(50, 3, "escalated",
                                     scope_definition_hash="abc")
        assert p.ai_context is None

    def test_model_id_clean_vs_violation(self):
        w = _make_witness()
        p_clean = w.witness_scope_boundary(100, 0)
        assert p_clean.ai_model_id == "scope-clean"

        p_violation = w.witness_scope_boundary(100, 5, "escalated")
        assert p_violation.ai_model_id == "scope-escalated"

    def test_unknown_response_defaults_to_blocked(self):
        w = _make_witness()
        p = w.witness_scope_boundary(10, 1, "unknown_response")
        assert p.factor_c == 0.0  # defaults to "blocked" = 0

    def test_zero_observation_window_not_in_context(self):
        w = _make_witness(clearing_level=1)
        p = w.witness_scope_boundary(10, 0, observation_window_ms=0)
        ctx = p.ai_context
        assert "observation_window_ms" not in ctx

    def test_enqueue_called(self):
        w = _make_witness()
        w.witness_scope_boundary(10, 0)
        w._buffer.enqueue_many.assert_called_once()
