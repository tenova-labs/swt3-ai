"""Tests for Model Trust Profiles (profile.py)."""

import pytest
from swt3_ai.types import ProcedureAttestation, AnchorReference, ModelTrustProfile
from swt3_ai.profile import (
    generate_profile,
    sign_profile,
    verify_profile_signature,
    is_profile_valid,
    coverage_score,
    build_profile_message,
    RECOMMENDED_PROCEDURES,
)

NOW = 1_700_000_000_000
KEY = "test-signing-key-256bit-abcdef"


def mk_attestation(proc: str, status: str = "pass") -> ProcedureAttestation:
    return ProcedureAttestation(procedure=proc, fingerprint=f"fp_{proc}", timestamp=NOW - 1000, status=status)


class TestGenerateProfile:
    def test_builds_profile_with_correct_score(self):
        attestations = [mk_attestation("AI-INF.1"), mk_attestation("AI-GRD.1"), mk_attestation("AI-MDL.1", "fail")]
        profile = generate_profile(model_id="gpt-4o", model_hash="abc123", attestations=attestations, now_ms=NOW)
        assert profile.model_id == "gpt-4o"
        assert profile.model_hash == "abc123"
        assert abs(profile.coverage_score - 2 / 3) < 1e-10
        assert profile.generated_at == NOW
        assert profile.valid_until == NOW + 86_400_000
        assert profile.signature is None

    def test_empty_attestations_score_zero(self):
        profile = generate_profile(model_id="m", model_hash="h", attestations=[], now_ms=NOW)
        assert profile.coverage_score == 0

    def test_all_pass_score_one(self):
        attestations = [mk_attestation("AI-INF.1"), mk_attestation("AI-GRD.1")]
        profile = generate_profile(model_id="m", model_hash="h", attestations=attestations, now_ms=NOW)
        assert profile.coverage_score == 1.0

    def test_signs_when_key_provided(self):
        attestations = [mk_attestation("AI-INF.1")]
        profile = generate_profile(model_id="m", model_hash="h", attestations=attestations, signing_key=KEY, now_ms=NOW)
        assert profile.signature is not None
        assert len(profile.signature) == 64

    def test_includes_upstream_references(self):
        refs = [AnchorReference(fingerprint="upstream_fp")]
        profile = generate_profile(model_id="m", model_hash="h", attestations=[], upstream_references=refs, now_ms=NOW)
        assert len(profile.upstream_references) == 1
        assert profile.upstream_references[0].fingerprint == "upstream_fp"

    def test_custom_ttl(self):
        profile = generate_profile(model_id="m", model_hash="h", attestations=[], ttl_ms=3600_000, now_ms=NOW)
        assert profile.valid_until == NOW + 3600_000


class TestSignProfile:
    def test_round_trip(self):
        attestations = [mk_attestation("AI-INF.1"), mk_attestation("AI-GRD.1")]
        profile = generate_profile(model_id="m", model_hash="h", attestations=attestations, signing_key=KEY, now_ms=NOW)
        assert verify_profile_signature(profile, KEY) is True

    def test_rejects_tampered_model_id(self):
        attestations = [mk_attestation("AI-INF.1")]
        profile = generate_profile(model_id="m", model_hash="h", attestations=attestations, signing_key=KEY, now_ms=NOW)
        profile.model_id = "tampered"
        assert verify_profile_signature(profile, KEY) is False

    def test_rejects_wrong_key(self):
        attestations = [mk_attestation("AI-INF.1")]
        profile = generate_profile(model_id="m", model_hash="h", attestations=attestations, signing_key=KEY, now_ms=NOW)
        assert verify_profile_signature(profile, "wrong-key") is False

    def test_unsigned_profile(self):
        profile = generate_profile(model_id="m", model_hash="h", attestations=[], now_ms=NOW)
        assert verify_profile_signature(profile, KEY) is False


class TestBuildProfileMessage:
    def test_sorts_procedures(self):
        attestations = [mk_attestation("AI-GRD.1"), mk_attestation("AI-INF.1"), mk_attestation("AI-ACC.1")]
        profile = generate_profile(model_id="m", model_hash="h", attestations=attestations, now_ms=NOW)
        msg = build_profile_message(profile)
        assert "AI-ACC.1,AI-GRD.1,AI-INF.1" in msg

    def test_score_3dp(self):
        attestations = [mk_attestation("AI-INF.1"), mk_attestation("AI-GRD.1"), mk_attestation("AI-MDL.1", "fail")]
        profile = generate_profile(model_id="m", model_hash="h", attestations=attestations, now_ms=NOW)
        msg = build_profile_message(profile)
        assert ":0.667" in msg


class TestIsProfileValid:
    def test_within_window(self):
        profile = generate_profile(model_id="m", model_hash="h", attestations=[], now_ms=NOW)
        assert is_profile_valid(profile, NOW + 1000) is True

    def test_after_expiry(self):
        profile = generate_profile(model_id="m", model_hash="h", attestations=[], ttl_ms=1000, now_ms=NOW)
        assert is_profile_valid(profile, NOW + 2000) is False

    def test_exact_boundary(self):
        profile = generate_profile(model_id="m", model_hash="h", attestations=[], ttl_ms=1000, now_ms=NOW)
        assert is_profile_valid(profile, NOW + 1000) is True


class TestCoverageScore:
    def test_full_coverage(self):
        result = coverage_score(["AI-INF.1", "AI-INF.2", "AI-MDL.1", "AI-MDL.2", "AI-GRD.1", "AI-GRD.2"], "standard")
        assert result.score == 1.0
        assert len(result.missing) == 0
        assert len(result.extra) == 0

    def test_half_coverage(self):
        result = coverage_score(["AI-INF.1", "AI-INF.2", "AI-MDL.1"], "standard")
        assert result.score == 0.5
        assert len(result.covered) == 3
        assert len(result.missing) == 3

    def test_defaults_to_standard(self):
        result = coverage_score(["AI-INF.1"])
        assert result.target == RECOMMENDED_PROCEDURES["standard"]

    def test_custom_array_target(self):
        result = coverage_score(["AI-INF.1", "AI-GRD.1"], ["AI-INF.1", "AI-GRD.1", "AI-FAIR.1"])
        assert abs(result.score - 2 / 3) < 1e-10
        assert result.missing == ["AI-FAIR.1"]

    def test_identifies_extra(self):
        result = coverage_score(["AI-INF.1", "AI-HW.1"], "minimal")
        assert result.extra == ["AI-HW.1"]

    def test_unknown_profile_raises(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            coverage_score([], "nonexistent")

    def test_empty_target(self):
        result = coverage_score(["AI-INF.1"], [])
        assert result.score == 0
