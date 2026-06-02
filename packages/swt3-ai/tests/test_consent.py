"""Tests for AI-CONSENT.1 Data Subject Consent Witnessing."""

from unittest.mock import MagicMock
from swt3_ai.witness import Witness, CONSENT_BASIS_CODES


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


class TestWitnessConsent:
    def test_mints_correct_procedure_and_factors(self):
        w = _make_witness()
        p = w.witness_consent(1000, "consent", True)
        assert p.procedure_id == "AI-CONSENT.1"
        assert p.factor_a == 1000.0
        assert p.factor_b == 0.0  # consent code
        assert p.factor_c == 1.0  # withdrawal available
        assert p.anchor_fingerprint
        w._buffer.enqueue_many.assert_called_once()

    def test_maps_all_basis_codes(self):
        w = _make_witness()
        for basis, code in CONSENT_BASIS_CODES.items():
            p = w.witness_consent(1, basis, False)
            assert p.factor_b == float(code), f"Failed for {basis}"

    def test_unknown_basis_defaults_to_zero(self):
        w = _make_witness()
        p = w.witness_consent(50, "unknown_basis", True)
        assert p.factor_b == 0.0

    def test_withdrawal_not_available(self):
        w = _make_witness()
        p = w.witness_consent(500, "legitimate_interest", False)
        assert p.factor_c == 0.0
        assert p.factor_b == 5.0  # legitimate_interest

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_consent(
            2000, "contract", True,
            purpose="fraud detection",
            retention_days=365,
            consent_mechanism="api-consent-endpoint",
            consent_hash="sha256abc",
            data_categories=["financial", "identity"],
        )
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "consent-management"
        assert p.ai_context["legal_basis_type"] == "contract"
        assert p.ai_context["purpose"] == "fraud detection"
        assert p.ai_context["retention_days"] == 365
        assert p.ai_context["consent_mechanism"] == "api-consent-endpoint"
        assert p.ai_context["consent_hash"] == "sha256abc"
        assert p.ai_context["data_categories"] == ["financial", "identity"]
        assert p.ai_model_id == "consent-contract"

    def test_omits_optional_context_fields(self):
        w = _make_witness(clearing_level=0)
        p = w.witness_consent(10, "consent", True)
        assert p.ai_context is not None
        assert "purpose" not in p.ai_context
        assert "retention_days" not in p.ai_context

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_consent(
            1000, "legal_obligation", False,
            purpose="regulatory reporting",
        )
        assert p.ai_context is None
        assert p.factor_a == 1000.0
        assert p.factor_b == 2.0  # legal_obligation
        assert p.factor_c == 0.0

    def test_handles_single_subject(self):
        w = _make_witness()
        p = w.witness_consent(1, "vital_interest", True)
        assert p.factor_a == 1.0
        assert p.factor_b == 3.0  # vital_interest

    def test_valid_fingerprint(self):
        w = _make_witness()
        p = w.witness_consent(1, "consent", False)
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)
