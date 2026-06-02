"""Tests for AI-MARK.1 Content Provenance Marking."""

from unittest.mock import MagicMock
from swt3_ai.witness import Witness, CONTENT_TYPE_CODES


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


class TestWitnessContentMark:
    def test_mints_correct_procedure_and_factors(self):
        w = _make_witness()
        p = w.witness_content_mark(5, "text", "c2pa", has_metadata=True)
        assert p.procedure_id == "AI-MARK.1"
        assert p.factor_a == 5.0
        assert p.factor_b == 1.0
        assert p.factor_c == 0.0  # text
        assert p.anchor_fingerprint
        w._buffer.enqueue_many.assert_called_once()

    def test_maps_all_content_type_codes(self):
        w = _make_witness()
        for content_type, code in CONTENT_TYPE_CODES.items():
            p = w.witness_content_mark(1, content_type, "watermark")
            assert p.factor_c == float(code), f"Failed for {content_type}"

    def test_no_metadata_sets_factor_b_zero(self):
        w = _make_witness()
        p = w.witness_content_mark(1, "image", "watermark", has_metadata=False)
        assert p.factor_b == 0.0
        assert p.factor_c == 1.0  # image

    def test_unknown_content_type_defaults_to_zero(self):
        w = _make_witness()
        p = w.witness_content_mark(1, "hologram", "manifest")
        assert p.factor_c == 0.0

    def test_auto_hashes_content_string(self):
        w = _make_witness()
        p = w.witness_content_mark(1, "text", "c2pa", has_metadata=True, content="Hello AI world")
        assert p.ai_context is not None
        assert "content_hash" in p.ai_context
        assert isinstance(p.ai_context["content_hash"], str)

    def test_uses_provided_content_hash(self):
        w = _make_witness()
        p = w.witness_content_mark(
            1, "text", "c2pa", has_metadata=True,
            content="ignored", content_hash="abc123def456",
        )
        assert p.ai_context["content_hash"] == "abc123def456"

    def test_includes_standard_and_manifest_hash(self):
        w = _make_witness()
        p = w.witness_content_mark(
            1, "image", "c2pa", has_metadata=True,
            manifest_hash="mh_value", standard="C2PA-1.4",
        )
        assert p.ai_context["manifest_hash"] == "mh_value"
        assert p.ai_context["standard"] == "C2PA-1.4"

    def test_strips_ai_context_at_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_content_mark(3, "video", "watermark", has_metadata=True)
        assert p.ai_context is None
        assert p.factor_a == 3.0
        assert p.factor_c == 3.0  # video
