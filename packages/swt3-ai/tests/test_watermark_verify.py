"""Tests for AI-WATERMARK.1 watermark verification witnessing."""
from unittest.mock import MagicMock
from swt3_ai.witness import Witness, DETECTION_METHOD_CODES


def _make_witness(clearing_level=1, **kwargs):
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="test_tenant", clearing_level=clearing_level, **kwargs)
    w._buffer = MagicMock()
    return w


class TestWitnessWatermarkVerification:
    def test_mints_correct_procedure_and_factors(self):
        w = _make_witness()
        p = w.witness_watermark_verification(50, 45, "c2pa_verify")
        assert p.procedure_id == "AI-WATERMARK.1"
        assert isinstance(p.factor_a, float)
        assert isinstance(p.factor_b, float)
        assert isinstance(p.factor_c, float)
        assert p.anchor_fingerprint
        w._buffer.enqueue_many.assert_called()

    def test_maps_all_type_codes(self):
        w = _make_witness()
        for code_name, code_value in DETECTION_METHOD_CODES.items():
            p = w.witness_watermark_verification(50, 45, code_name)
            assert p.factor_c == float(code_value)

    def test_unknown_type_defaults(self):
        w = _make_witness()
        p = w.witness_watermark_verification(50, 45, "unknown_xyz")
        assert p.factor_c == 4.0

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_watermark_verification(50, 45, "c2pa_verify")
        assert p.ai_context is not None
        assert "provider" in p.ai_context
        assert "detection_method" in p.ai_context
        assert p.ai_model_id is not None

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_watermark_verification(50, 45, "c2pa_verify")
        assert p.ai_context is None
        assert isinstance(p.factor_a, float)
        assert isinstance(p.factor_b, float)
        assert isinstance(p.factor_c, float)

    def test_propagates_agent_id(self):
        w = _make_witness(agent_id="test-agent")
        p = w.witness_watermark_verification(50, 45, "c2pa_verify")
        assert p.agent_id == "test-agent"

    def test_valid_fingerprint(self):
        w = _make_witness()
        p = w.witness_watermark_verification(50, 45, "c2pa_verify")
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)
