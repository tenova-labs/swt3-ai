"""Tests for AI-BASE.1 Agent Behavioral Baseline."""

from unittest.mock import MagicMock
from swt3_ai.witness import Witness, BASELINE_MODE_CODES


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


class TestWitnessAgentBaseline:
    def test_mints_correct_procedure_establishing(self):
        w = _make_witness()
        p = w.witness_agent_baseline(
            8, True, "establishing", 0.0, "baseline_abc", "current_abc",
        )
        assert p.procedure_id == "AI-BASE.1"
        assert p.factor_a == 8.0
        assert p.factor_b == 1.0
        assert p.factor_c == 0.0  # establishing
        assert p.anchor_fingerprint
        w._buffer.enqueue_many.assert_called_once()

    def test_maps_all_mode_codes(self):
        w = _make_witness()
        for mode, code in BASELINE_MODE_CODES.items():
            p = w.witness_agent_baseline(
                5, mode != "drift_detected", mode,
                0.8 if mode == "drift_detected" else 0.1, "bh", "ch",
            )
            assert p.factor_c == float(code), f"Failed for {mode}"

    def test_drift_detected_sets_factor_b_zero(self):
        w = _make_witness()
        p = w.witness_agent_baseline(12, False, "drift_detected", 0.85, "bh", "ch")
        assert p.factor_b == 0.0
        assert p.factor_c == 2.0

    def test_includes_drift_score_and_hashes(self):
        w = _make_witness()
        p = w.witness_agent_baseline(
            10, True, "monitoring", 0.23, "bl_hash", "cur_hash",
            drift_threshold=0.6, baseline_window_hours=72,
        )
        assert p.ai_context["drift_score"] == 0.23
        assert p.ai_context["baseline_hash"] == "bl_hash"
        assert p.ai_context["current_hash"] == "cur_hash"
        assert p.ai_context["drift_threshold"] == 0.6
        assert p.ai_context["baseline_window_hours"] == 72

    def test_defaults_drift_threshold(self):
        w = _make_witness()
        p = w.witness_agent_baseline(5, True, "monitoring", 0.1, "bh", "ch")
        assert p.ai_context["drift_threshold"] == 0.5

    def test_auto_hashes_agent_id(self):
        w = _make_witness(agent_id="agent-sentinel-1")
        p = w.witness_agent_baseline(5, True, "monitoring", 0.1, "bh", "ch")
        assert "agent_id_hash" in p.ai_context
        assert isinstance(p.ai_context["agent_id_hash"], str)
        assert p.agent_id == "agent-sentinel-1"

    def test_strips_ai_context_at_level_3(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_agent_baseline(20, False, "drift_detected", 0.9, "bh", "ch")
        assert p.ai_context is None
        assert p.factor_a == 20.0
        assert p.factor_b == 0.0
        assert p.factor_c == 2.0

    def test_unknown_mode_defaults_to_zero(self):
        w = _make_witness()
        p = w.witness_agent_baseline(5, True, "unknown_mode", 0.1, "bh", "ch")
        assert p.factor_c == 0.0

    def test_baseline_reset_sets_code_3(self):
        w = _make_witness()
        p = w.witness_agent_baseline(15, True, "baseline_reset", 0.0, "new_bl", "new_cur")
        assert p.factor_c == 3.0
