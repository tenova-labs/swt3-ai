"""Tests for METAGOV namespace procedures (AI-METAGOV.1 through AI-METAGOV.8).

Covers:
- Fingerprint parity with test-vectors.json
- witness_governance_config (AI-METAGOV.1)
- register_governance_layer / witness_governance_output (AI-METAGOV.2)
- check_policy_downgrade (AI-METAGOV.3)
- validate_governance_graph cycle detection (AI-METAGOV.4)
- authorize_governance_change (AI-METAGOV.5)
- witness_emergency_override (AI-METAGOV.6)
- witness_governance_sync (AI-METAGOV.7)
- verify_attestation_purity (AI-METAGOV.8)
"""

import json
import hashlib
from pathlib import Path

import pytest

from swt3_ai import Witness, validate_governance_graph
from swt3_ai.fingerprint import mint_fingerprint


VECTORS_PATH = Path(__file__).resolve().parent.parent / "test-vectors.json"


@pytest.fixture
def vectors():
    with open(VECTORS_PATH) as f:
        data = json.load(f)
    return [v for v in data["fingerprint_vectors"] if "METAGOV" in v["procedure_id"]]


@pytest.fixture
def witness():
    return Witness(
        endpoint="https://test.example.com",
        api_key="axm_test_key",
        tenant_id="TEST_METAGOV",
        clearing_level=1,
    )


# ── Fingerprint parity with test vectors ────────────────────────────────


class TestMetagovFingerprints:
    def test_all_metagov_vectors_present(self, vectors):
        assert len(vectors) == 8
        procs = {v["procedure_id"] for v in vectors}
        for i in range(1, 9):
            assert f"AI-METAGOV.{i}" in procs

    def test_fingerprint_parity(self, vectors):
        for v in vectors:
            computed = mint_fingerprint(
                v["tenant_id"],
                v["procedure_id"],
                v["factor_a"],
                v["factor_b"],
                v["factor_c"],
                v["fingerprint_timestamp_ms"],
            )
            assert computed == v["expected_fingerprint"], (
                f"{v['procedure_id']}: expected {v['expected_fingerprint']}, got {computed}"
            )

    def test_all_vectors_use_enclave_prod(self, vectors):
        for v in vectors:
            assert v["tenant_id"] == "ENCLAVE_PROD"

    def test_all_vectors_clearing_level_1(self, vectors):
        for v in vectors:
            assert v["clearing_level"] == 1


# ── AI-METAGOV.1: Governance Config ────────────────────────────────────


class TestGovernanceConfig:
    def test_mints_metagov1_anchor(self, witness):
        rules = [
            {"id": "R1", "expression": "trust_level >= 3", "version": "1"},
            {"id": "R2", "expression": "signing_required", "version": "1"},
        ]
        payload = witness.witness_governance_config(rules, governance_version=1)
        assert payload.procedure_id == "AI-METAGOV.1"
        assert payload.factor_a == 2  # 2 rules
        assert payload.factor_c == 1  # version 1

    def test_config_hash_deterministic(self, witness):
        rules = [{"id": "A", "expression": "x", "version": "1"}]
        p1 = witness.witness_governance_config(rules, governance_version=1)
        p2 = witness.witness_governance_config(rules, governance_version=1)
        # factor_b is derived from config hash, should be identical
        assert p1.factor_b == p2.factor_b

    def test_different_rules_different_hash(self, witness):
        r1 = [{"id": "A", "expression": "x", "version": "1"}]
        r2 = [{"id": "A", "expression": "y", "version": "1"}]
        p1 = witness.witness_governance_config(r1, governance_version=1)
        p2 = witness.witness_governance_config(r2, governance_version=1)
        assert p1.factor_b != p2.factor_b

    def test_context_includes_operator(self, witness):
        rules = [{"id": "R1", "expression": "x"}]
        payload = witness.witness_governance_config(
            rules, governance_version=2, operator_id="admin-1"
        )
        assert payload.ai_context["operator_id"] == "admin-1"
        assert payload.ai_context["governance_version"] == 2


# ── AI-METAGOV.2: Governance Layer ────────────────────────────────────


class TestGovernanceLayer:
    def test_register_mints_metagov2(self, witness):
        payload = witness.register_governance_layer(
            "nemo-guardrails", "abc123hash", 0
        )
        assert payload.procedure_id == "AI-METAGOV.2"
        assert payload.factor_a == 1  # registered
        assert payload.factor_c == 0  # stack position 0

    def test_witness_output_pass(self, witness):
        payload = witness.witness_governance_output(
            "nemo-guardrails", "PASS", "a1b2c3d4e5f60000"
        )
        assert payload.procedure_id == "AI-METAGOV.2"
        assert payload.factor_c == 1  # PASS

    def test_witness_output_fail(self, witness):
        payload = witness.witness_governance_output(
            "nemo-guardrails", "FAIL", "f0e1d2c3b4a50000"
        )
        assert payload.factor_c == 0  # FAIL


# ── AI-METAGOV.3: Policy Downgrade ────────────────────────────────────


class TestPolicyDowngrade:
    def test_no_downgrade_returns_none(self, witness):
        result = witness.check_policy_downgrade(5, "a1b2c3d4e5f6")
        assert result is None

    def test_detects_downgrade(self, witness):
        witness.check_policy_downgrade(5, "a1b2c3d4e5f6")  # set baseline
        payload = witness.check_policy_downgrade(3, "f0e1d2c3b4a5")
        assert payload is not None
        assert payload.procedure_id == "AI-METAGOV.3"
        assert payload.factor_a == 3  # loaded version
        assert payload.factor_c == 1  # downgrade detected

    def test_strict_raises(self, witness):
        witness.check_policy_downgrade(5, "a1b2c3d4e5f6")
        with pytest.raises(RuntimeError, match="Policy downgrade"):
            witness.check_policy_downgrade(2, "f0e1d2c3b4a5", strict=True)


# ── AI-METAGOV.4: Governance Graph ────────────────────────────────────


class TestGovernanceGraph:
    def test_valid_dag(self):
        rules = [
            {"id": "A", "dependencies": []},
            {"id": "B", "dependencies": ["A"]},
            {"id": "C", "dependencies": ["A", "B"]},
        ]
        result = validate_governance_graph(rules)
        assert result["valid"] is True
        assert result["cycles"] == []
        assert result["rule_count"] == 3
        assert result["max_depth"] == 2

    def test_detects_cycle(self):
        rules = [
            {"id": "A", "dependencies": ["B"]},
            {"id": "B", "dependencies": ["A"]},
        ]
        result = validate_governance_graph(rules)
        assert result["valid"] is False
        assert len(result["cycles"]) > 0

    def test_detects_self_cycle(self):
        rules = [{"id": "A", "dependencies": ["A"]}]
        result = validate_governance_graph(rules)
        assert result["valid"] is False

    def test_empty_graph(self):
        result = validate_governance_graph([])
        assert result["valid"] is True
        assert result["rule_count"] == 0

    def test_single_node(self):
        result = validate_governance_graph([{"id": "A", "dependencies": []}])
        assert result["valid"] is True
        assert result["max_depth"] == 0

    def test_deep_chain(self):
        rules = [{"id": f"N{i}", "dependencies": [f"N{i-1}"] if i > 0 else []} for i in range(10)]
        result = validate_governance_graph(rules)
        assert result["valid"] is True
        assert result["max_depth"] == 9


# ── AI-METAGOV.5: Governance Authorization ────────────────────────────


class TestGovernanceAuthorization:
    def test_mints_metagov5(self, witness):
        payload = witness.authorize_governance_change(
            "verdict_rules", "modify", "admin-1",
            "Update trust threshold", "a1b2c3d4e5f60000"
        )
        assert payload.procedure_id == "AI-METAGOV.5"
        assert payload.factor_a == 0  # verdict_rules = 0
        assert payload.factor_b == 1  # modify = 1

    def test_scope_codes_mapped(self, witness):
        for scope, expected in [("verdict_rules", 0), ("trust_mesh", 1), ("enforcement", 2), ("clearing", 3), ("full", 4)]:
            payload = witness.authorize_governance_change(
                scope, "read", "op", "desc", "a1b2c3d4e5f6"
            )
            assert payload.factor_a == expected


# ── AI-METAGOV.6: Emergency Override ──────────────────────────────────


class TestEmergencyOverride:
    def test_mints_metagov6(self, witness):
        payload = witness.witness_emergency_override(
            "incident_response", 48, "admin-1", "Disabling guardrails for incident"
        )
        assert payload.procedure_id == "AI-METAGOV.6"
        assert payload.factor_a == 1  # incident_response = 1
        assert payload.factor_b == 48  # review window
        assert payload.factor_c == 0  # unreviewed

    def test_reason_codes_mapped(self, witness):
        for reason, expected in [("unspecified", 0), ("incident_response", 1), ("regulatory_deadline", 2), ("system_failure", 3), ("security_breach", 4)]:
            payload = witness.witness_emergency_override(
                reason, 24, "op", "desc"
            )
            assert payload.factor_a == expected


# ── AI-METAGOV.7: Governance Sync ────────────────────────────────────


class TestGovernanceSync:
    def test_mints_metagov7(self, witness):
        payload = witness.witness_governance_sync(
            "version_divergent", "a1b2c3d4e5f60000", "f0e1d2c3b4a50000"
        )
        assert payload.procedure_id == "AI-METAGOV.7"
        assert payload.factor_a == 1  # version_divergent = 1

    def test_equivalent_code(self, witness):
        payload = witness.witness_governance_sync(
            "equivalent", "abcdef1234567890", "abcdef1234567890"
        )
        assert payload.factor_a == 0

    def test_remote_tenant_in_context(self, witness):
        payload = witness.witness_governance_sync(
            "equivalent", "a1b2c3d4e5f60000", "f0e1d2c3b4a50000",
            remote_tenant_id="PARTNER_TENANT"
        )
        assert payload.ai_context["remote_tenant_id"] == "PARTNER_TENANT"


# ── AI-METAGOV.8: Attestation Purity ────────────────────────────────


class TestAttestationPurity:
    def test_mints_metagov8(self, witness):
        files = [
            {"path": "witness.py", "hash": "abc123"},
            {"path": "clearing.py", "hash": "def456"},
        ]
        payload = witness.verify_attestation_purity(files)
        assert payload.procedure_id == "AI-METAGOV.8"
        assert payload.factor_a == 2  # 2 source files
        assert payload.factor_c == 1  # pure

    def test_hash_deterministic(self, witness):
        files = [{"path": "a.py", "hash": "h1"}, {"path": "b.py", "hash": "h2"}]
        p1 = witness.verify_attestation_purity(files)
        p2 = witness.verify_attestation_purity(files)
        assert p1.factor_b == p2.factor_b

    def test_order_independent(self, witness):
        f1 = [{"path": "a.py", "hash": "h1"}, {"path": "b.py", "hash": "h2"}]
        f2 = [{"path": "b.py", "hash": "h2"}, {"path": "a.py", "hash": "h1"}]
        p1 = witness.verify_attestation_purity(f1)
        p2 = witness.verify_attestation_purity(f2)
        assert p1.factor_b == p2.factor_b  # sorted internally

    def test_build_hash_in_context(self, witness):
        files = [{"path": "x.py", "hash": "abc"}]
        payload = witness.verify_attestation_purity(files, build_hash="build123")
        assert payload.ai_context["build_hash"] == "build123"
