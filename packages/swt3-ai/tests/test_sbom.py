"""Tests for AI-SBOM.1 AI Bill of Materials Witnessing."""

from unittest.mock import MagicMock
from swt3_ai.witness import Witness, SBOM_FORMAT_CODES


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


class TestWitnessSbom:
    def test_mints_correct_procedure_and_factors(self):
        w = _make_witness()
        p = w.witness_sbom(42, 7, "cyclonedx", "abc123def456")
        assert p.procedure_id == "AI-SBOM.1"
        assert p.factor_a == 42.0
        assert p.factor_b == 7.0
        assert p.factor_c == 0.0  # cyclonedx
        assert p.anchor_fingerprint
        w._buffer.enqueue_many.assert_called_once()

    def test_maps_all_sbom_format_codes(self):
        w = _make_witness()
        for fmt, code in SBOM_FORMAT_CODES.items():
            p = w.witness_sbom(10, 3, fmt, "hash123")
            assert p.factor_c == float(code), f"Failed for {fmt}"

    def test_unknown_format_defaults_to_three(self):
        w = _make_witness()
        p = w.witness_sbom(5, 2, "proprietary_format", "hash123")
        assert p.factor_c == 3.0

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_sbom(
            42, 7, "cyclonedx", "abc123def456",
            version="1.6.0", model_count=3, dataset_count=5,
            infrastructure_components=12,
        )
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "ai-sbom"
        assert p.ai_context["bom_hash"] == "abc123def456"
        assert p.ai_context["format"] == "cyclonedx"
        assert p.ai_context["version"] == "1.6.0"
        assert p.ai_context["model_count"] == 3
        assert p.ai_context["dataset_count"] == 5
        assert p.ai_context["infrastructure_components"] == 12
        assert p.ai_model_id == "sbom-cyclonedx"

    def test_omits_optional_context_fields(self):
        w = _make_witness(clearing_level=0)
        p = w.witness_sbom(10, 4, "spdx", "hash456")
        assert p.ai_context is not None
        assert "version" not in p.ai_context
        assert "model_count" not in p.ai_context

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_sbom(42, 7, "cyclonedx", "abc123", version="1.6.0")
        assert p.ai_context is None
        assert p.factor_a == 42.0
        assert p.factor_b == 7.0
        assert p.factor_c == 0.0

    def test_context_stripped_at_clearing_level_3(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_sbom(20, 5, "spdx", "hash789")
        assert p.ai_context is None
        assert p.factor_a == 20.0

    def test_propagates_agent_id(self):
        w = _make_witness(agent_id="sbom-scanner-agent")
        p = w.witness_sbom(15, 6, "cyclonedx", "hash123")
        assert p.agent_id == "sbom-scanner-agent"

    def test_valid_fingerprint(self):
        w = _make_witness()
        p = w.witness_sbom(1, 1, "custom", "h")
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)  # validates hex
