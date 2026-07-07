"""SWT3 AI Witness SDK -- Provenance Chain References Tests."""

import pytest

from swt3_ai.types import InferenceRecord, WitnessPayload
from swt3_ai.clearing import extract_payloads, normalize_references


def mk_record(**overrides):
    defaults = dict(
        model_id="gpt-4",
        model_hash="abc123",
        prompt_hash="p_hash",
        response_hash="r_hash",
        latency_ms=200,
        guardrails_active=1,
        guardrails_required=1,
        guardrail_passed=True,
        has_refusal=False,
        provider="openai",
        guardrail_names=["filter"],
    )
    defaults.update(overrides)
    return InferenceRecord(**defaults)


class TestNormalizeReferences:
    def test_returns_none_for_empty(self):
        assert normalize_references(None) is None
        assert normalize_references([]) is None

    def test_normalizes_strings(self):
        result = normalize_references(["abc123", "def456"])
        assert result == [
            {"fingerprint": "abc123"},
            {"fingerprint": "def456"},
        ]

    def test_passes_through_dicts(self):
        refs = [
            {"fingerprint": "abc123", "relationship": "model_source"},
            {"fingerprint": "def456", "provenance_token": "tok_xyz"},
        ]
        result = normalize_references(refs)
        assert result == refs

    def test_handles_mixed_input(self):
        result = normalize_references([
            "abc123",
            {"fingerprint": "def456", "relationship": "training_data"},
        ])
        assert result == [
            {"fingerprint": "abc123"},
            {"fingerprint": "def456", "relationship": "training_data"},
        ]


class TestReferencesInExtractPayloads:
    def test_references_in_payload(self):
        refs = [{"fingerprint": "upstream_fp_1"}]
        payloads = extract_payloads(mk_record(), "tenant_1", 1, references=refs)
        assert len(payloads) > 0
        assert payloads[0].references == refs

    def test_no_references_when_not_provided(self):
        payloads = extract_payloads(mk_record(), "tenant_1", 1)
        assert len(payloads) > 0
        assert payloads[0].references is None

    def test_references_survive_clearing_level_0(self):
        refs = [{"fingerprint": "fp_0", "relationship": "infra"}]
        payloads = extract_payloads(mk_record(), "t", 0, references=refs)
        assert payloads[0].references == refs

    def test_references_survive_clearing_level_2(self):
        refs = [{"fingerprint": "fp_2"}]
        payloads = extract_payloads(mk_record(), "t", 2, references=refs)
        assert payloads[0].references == refs

    def test_references_survive_clearing_level_3(self):
        refs = [{"fingerprint": "fp_3"}]
        payloads = extract_payloads(mk_record(), "t", 3, references=refs)
        assert payloads[0].references == refs

    def test_multiple_references_preserved_in_order(self):
        refs = [
            {"fingerprint": "first", "relationship": "model_source"},
            {"fingerprint": "second", "relationship": "training_data"},
            {"fingerprint": "third", "provenance_token": "tok_abc"},
        ]
        payloads = extract_payloads(mk_record(), "t", 1, references=refs)
        assert payloads[0].references == refs
        assert len(payloads[0].references) == 3

    def test_references_in_to_dict(self):
        refs = [{"fingerprint": "fp_dict"}]
        payloads = extract_payloads(mk_record(), "t", 1, references=refs)
        d = payloads[0].to_dict()
        assert "references" in d
        assert d["references"] == refs

    def test_no_references_in_to_dict_when_absent(self):
        payloads = extract_payloads(mk_record(), "t", 1)
        d = payloads[0].to_dict()
        assert "references" not in d
