"""Tests for AI-LIC.1 License Provenance Witnessing."""

from unittest.mock import MagicMock
from swt3_ai.witness import Witness, LICENSE_TYPE_CODES


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


class TestWitnessLicenseProvenance:
    def test_mints_correct_procedure_and_factors(self):
        w = _make_witness()
        p = w.witness_license_provenance(3, True, "permissive")
        assert p.procedure_id == "AI-LIC.1"
        assert p.factor_a == 3.0
        assert p.factor_b == 1.0
        assert p.factor_c == 0.0  # permissive
        assert p.anchor_fingerprint
        w._buffer.enqueue_many.assert_called_once()

    def test_maps_all_license_type_codes(self):
        w = _make_witness()
        for license_type, code in LICENSE_TYPE_CODES.items():
            p = w.witness_license_provenance(1, True, license_type)
            assert p.factor_c == float(code), f"Failed for {license_type}"

    def test_violation_sets_factor_b_zero(self):
        w = _make_witness()
        p = w.witness_license_provenance(2, False, "copyleft")
        assert p.factor_b == 0.0
        assert p.factor_c == 1.0  # copyleft

    def test_unknown_license_type_defaults_to_five(self):
        w = _make_witness()
        p = w.witness_license_provenance(1, True, "alien_license")
        assert p.factor_c == 5.0

    def test_openmdw_code_is_four(self):
        w = _make_witness()
        p = w.witness_license_provenance(1, True, "openmdw")
        assert p.factor_c == 4.0

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_license_provenance(
            3, True, "permissive",
            base_model_license="Apache-2.0",
            adapter_licenses=["CC-BY-4.0", "MIT"],
            spdx_ids=["Apache-2.0", "CC-BY-4.0", "MIT"],
            license_hash="abc123",
        )
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "license-provenance"
        assert p.ai_context["license_type"] == "permissive"
        assert p.ai_context["base_model_license"] == "Apache-2.0"
        assert p.ai_context["adapter_licenses"] == ["CC-BY-4.0", "MIT"]
        assert p.ai_context["spdx_ids"] == ["Apache-2.0", "CC-BY-4.0", "MIT"]
        assert p.ai_context["license_hash"] == "abc123"
        assert p.ai_model_id == "license-permissive"

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_license_provenance(
            3, True, "openmdw",
            base_model_license="OpenMDW-1.1",
        )
        assert p.ai_context is None
        assert p.factor_a == 3.0
        assert p.factor_c == 4.0  # openmdw
