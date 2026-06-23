"""Tests for PPA #23 agent lifecycle methods: AI-DEL.1, AI-CAP.1, AI-AUTO.3, AI-COST.1, AI-CLR.2."""

import unittest
from unittest.mock import MagicMock
from swt3_ai.witness import Witness


def _w(clearing_level=1) -> Witness:
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="TEST", clearing_level=clearing_level)
    w._buffer = MagicMock()
    return w


class TestDelegationWitness(unittest.TestCase):
    """AI-DEL.1: Delegation Tree Witnessing."""

    def test_mints_correct_procedure(self):
        p = _w().witness_delegation("abc123", 2, 3600, "parent-agent", "child-agent")
        assert p.procedure_id == "AI-DEL.1"

    def test_factor_b_is_delegation_depth(self):
        p = _w().witness_delegation("abc", 5, 3600, "p", "c")
        assert p.factor_b == 5.0

    def test_factor_c_is_ttl_seconds(self):
        p = _w().witness_delegation("abc", 1, 7200, "p", "c")
        assert p.factor_c == 7200.0

    def test_factor_a_is_scope_hash_derived(self):
        p = _w().witness_delegation("test-scope", 1, 3600, "p", "c")
        assert isinstance(p.factor_a, float)
        assert p.factor_a > 0

    def test_factor_a_zero_for_empty_scope(self):
        p = _w().witness_delegation("", 1, 3600, "p", "c")
        assert p.factor_a == 0.0

    def test_context_at_level_1(self):
        p = _w().witness_delegation("abc", 2, 3600, "parent", "child")
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "delegation-tree"
        assert p.ai_context["scope_hash"] == "abc"
        assert p.ai_context["delegation_depth"] == 2
        assert p.ai_context["ttl_seconds"] == 3600
        assert p.ai_context["parent_agent_id"] == "parent"
        assert p.ai_context["child_agent_id"] == "child"

    def test_context_stripped_at_level_2(self):
        p = _w(clearing_level=2).witness_delegation("abc", 1, 3600, "p", "c")
        assert p.ai_context is None

    def test_cascade_revocation_flag(self):
        p = _w().witness_delegation("abc", 1, 3600, "p", "c", cascade_revocation=True)
        assert p.ai_context["cascade_revocation"] is True

    def test_sub_delegation_allowed_flag(self):
        p = _w().witness_delegation("abc", 1, 3600, "p", "c", sub_delegation_allowed=True)
        assert p.ai_context["sub_delegation_allowed"] is True

    def test_optional_delegated_capabilities(self):
        p = _w().witness_delegation("abc", 1, 3600, "p", "c", delegated_capabilities=["read", "write"])
        assert p.ai_context["delegated_capabilities"] == ["read", "write"]

    def test_optional_chain_merkle(self):
        p = _w().witness_delegation("abc", 1, 3600, "p", "c", delegation_chain_merkle="merkle123")
        assert p.ai_context["delegation_chain_merkle"] == "merkle123"

    def test_optional_authorization_chain(self):
        p = _w().witness_delegation("abc", 1, 3600, "p", "c", authorization_chain=["human", "agent-a", "agent-b"])
        assert p.ai_context["authorization_chain"] == ["human", "agent-a", "agent-b"]

    def test_fingerprint_is_12_hex(self):
        p = _w().witness_delegation("abc", 1, 3600, "p", "c")
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)

    def test_deterministic_factor_a(self):
        """Same scope_hash produces same factor_a."""
        a1 = _w().witness_delegation("same-scope", 1, 3600, "p", "c").factor_a
        a2 = _w().witness_delegation("same-scope", 1, 3600, "p", "c").factor_a
        assert a1 == a2

    def test_different_scope_different_factor_a(self):
        a1 = _w().witness_delegation("scope-a", 1, 3600, "p", "c").factor_a
        a2 = _w().witness_delegation("scope-b", 1, 3600, "p", "c").factor_a
        assert a1 != a2


class TestCapabilityAttestationWitness(unittest.TestCase):
    """AI-CAP.1: Capability Attestation."""

    def test_mints_correct_procedure(self):
        p = _w().witness_capability_attestation("manifest-hash", 5, 2)
        assert p.procedure_id == "AI-CAP.1"

    def test_factor_b_is_capability_count(self):
        p = _w().witness_capability_attestation("h", 10, 1)
        assert p.factor_b == 10.0

    def test_factor_c_is_autonomy_level(self):
        p = _w().witness_capability_attestation("h", 5, 3)
        assert p.factor_c == 3.0

    def test_factor_a_is_manifest_hash_derived(self):
        p = _w().witness_capability_attestation("my-manifest", 5, 2)
        assert isinstance(p.factor_a, float)
        assert p.factor_a > 0

    def test_context_at_level_1(self):
        p = _w().witness_capability_attestation("mh", 5, 2)
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "capability-attestation"
        assert p.ai_context["manifest_hash"] == "mh"
        assert p.ai_context["capability_count"] == 5
        assert p.ai_context["autonomy_level"] == 2

    def test_context_stripped_at_level_2(self):
        p = _w(clearing_level=2).witness_capability_attestation("mh", 5, 2)
        assert p.ai_context is None

    def test_drift_detected_flag(self):
        p = _w().witness_capability_attestation("mh", 5, 2, drift_detected=True)
        assert p.ai_context["drift_detected"] is True

    def test_hitl_required_flag(self):
        p = _w().witness_capability_attestation("mh", 5, 2, hitl_required=True)
        assert p.ai_context["hitl_required"] is True

    def test_optional_declared_capabilities(self):
        p = _w().witness_capability_attestation("mh", 5, 2, declared_capabilities=["search", "code"])
        assert p.ai_context["declared_capabilities"] == ["search", "code"]

    def test_optional_observed_capabilities(self):
        p = _w().witness_capability_attestation("mh", 5, 2, observed_capabilities=["search"])
        assert p.ai_context["observed_capabilities"] == ["search"]

    def test_model_id_used_when_provided(self):
        p = _w().witness_capability_attestation("mh", 5, 2, model_id="gpt-4o")
        assert p.ai_model_id == "gpt-4o"

    def test_model_id_default(self):
        p = _w().witness_capability_attestation("mh", 5, 2)
        assert p.ai_model_id == "capability-level-2"

    def test_capability_version(self):
        p = _w().witness_capability_attestation("mh", 5, 2, capability_version="v3.1")
        assert p.ai_context["capability_version"] == "v3.1"

    def test_fingerprint_is_12_hex(self):
        p = _w().witness_capability_attestation("mh", 5, 2)
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)


class TestAutonomyTransitionWitness(unittest.TestCase):
    """AI-AUTO.3: Autonomy Level Transition."""

    def test_mints_correct_procedure(self):
        p = _w().witness_autonomy_transition(1, 2, "policy")
        assert p.procedure_id == "AI-AUTO.3"

    def test_factor_a_is_from_level(self):
        p = _w().witness_autonomy_transition(0, 3, "manual")
        assert p.factor_a == 0.0

    def test_factor_b_is_to_level(self):
        p = _w().witness_autonomy_transition(1, 3, "manual")
        assert p.factor_b == 3.0

    def test_factor_c_is_trigger_hash(self):
        p = _w().witness_autonomy_transition(1, 2, "policy")
        assert isinstance(p.factor_c, float)
        assert p.factor_c > 0

    def test_trigger_case_insensitive(self):
        a = _w().witness_autonomy_transition(1, 2, "POLICY").factor_c
        b = _w().witness_autonomy_transition(1, 2, "policy").factor_c
        assert a == b

    def test_direction_promotion(self):
        p = _w().witness_autonomy_transition(1, 2, "policy")
        assert p.ai_context["direction"] == "promotion"

    def test_direction_demotion(self):
        p = _w().witness_autonomy_transition(2, 1, "risk")
        assert p.ai_context["direction"] == "demotion"

    def test_direction_lateral(self):
        p = _w().witness_autonomy_transition(2, 2, "refresh")
        assert p.ai_context["direction"] == "lateral"

    def test_context_at_level_1(self):
        p = _w().witness_autonomy_transition(0, 1, "manual")
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "autonomy-transition"
        assert p.ai_context["from_level"] == 0
        assert p.ai_context["to_level"] == 1
        assert p.ai_context["trigger_type"] == "manual"

    def test_context_stripped_at_level_2(self):
        p = _w(clearing_level=2).witness_autonomy_transition(0, 1, "manual")
        assert p.ai_context is None

    def test_hitl_checkpoint(self):
        p = _w().witness_autonomy_transition(0, 1, "manual", hitl_checkpoint=True)
        assert p.ai_context["hitl_checkpoint"] is True

    def test_optional_justification(self):
        p = _w().witness_autonomy_transition(0, 1, "policy", justification="Earned trust over 30 days")
        assert p.ai_context["justification"] == "Earned trust over 30 days"

    def test_optional_risk_score(self):
        p = _w().witness_autonomy_transition(2, 1, "risk", risk_score=0.85)
        assert p.ai_context["risk_score"] == 0.85

    def test_optional_transition_authorized_by(self):
        p = _w().witness_autonomy_transition(0, 1, "manual", transition_authorized_by="admin-42")
        assert p.ai_context["transition_authorized_by"] == "admin-42"

    def test_model_id_used_when_provided(self):
        p = _w().witness_autonomy_transition(0, 1, "manual", model_id="agent-v2")
        assert p.ai_model_id == "agent-v2"

    def test_fingerprint_is_12_hex(self):
        p = _w().witness_autonomy_transition(0, 1, "manual")
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)


class TestResourceConsumptionWitness(unittest.TestCase):
    """AI-COST.1: Resource Consumption Witnessing."""

    def test_mints_correct_procedure(self):
        p = _w().witness_resource_consumption(5000, 10, "0.42")
        assert p.procedure_id == "AI-COST.1"

    def test_factor_a_is_token_count(self):
        p = _w().witness_resource_consumption(12345, 10, "1.00")
        assert p.factor_a == 12345.0

    def test_factor_b_is_api_calls(self):
        p = _w().witness_resource_consumption(5000, 25, "0.50")
        assert p.factor_b == 25.0

    def test_factor_c_is_estimated_cost(self):
        p = _w().witness_resource_consumption(5000, 10, "3.14")
        assert p.factor_c == 3.14

    def test_context_at_level_1(self):
        p = _w().witness_resource_consumption(5000, 10, "0.42")
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "resource-consumption"
        assert p.ai_context["token_count"] == 5000
        assert p.ai_context["api_calls"] == 10
        assert p.ai_context["estimated_cost"] == "0.42"

    def test_context_stripped_at_level_2(self):
        p = _w(clearing_level=2).witness_resource_consumption(5000, 10, "0.42")
        assert p.ai_context is None

    def test_cost_anomaly_flag(self):
        p = _w().witness_resource_consumption(5000, 10, "0.42", cost_anomaly=True)
        assert p.ai_context["cost_anomaly"] is True

    def test_optional_budget_threshold(self):
        p = _w().witness_resource_consumption(5000, 10, "0.42", budget_threshold="100.00")
        assert p.ai_context["budget_threshold"] == "100.00"

    def test_optional_resource_attribution_id(self):
        p = _w().witness_resource_consumption(5000, 10, "0.42", resource_attribution_id="project-x")
        assert p.ai_context["resource_attribution_id"] == "project-x"

    def test_optional_consumption_window(self):
        p = _w().witness_resource_consumption(5000, 10, "0.42", consumption_window_seconds=300)
        assert p.ai_context["consumption_window_seconds"] == 300

    def test_model_id_default(self):
        p = _w().witness_resource_consumption(5000, 10, "0.42")
        assert p.ai_model_id == "cost-witness"

    def test_model_id_used_when_provided(self):
        p = _w().witness_resource_consumption(5000, 10, "0.42", model_id="claude-4")
        assert p.ai_model_id == "claude-4"

    def test_fingerprint_is_12_hex(self):
        p = _w().witness_resource_consumption(5000, 10, "0.42")
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)


class TestClearingFidelityWitness(unittest.TestCase):
    """AI-CLR.2: Clearing Fidelity Attestation."""

    def test_mints_correct_procedure(self):
        p = _w().witness_clearing_fidelity(2, 15, 8)
        assert p.procedure_id == "AI-CLR.2"

    def test_factor_a_is_clearing_level(self):
        p = _w().witness_clearing_fidelity(3, 15, 5)
        assert p.factor_a == 3.0

    def test_factor_b_is_input_field_count(self):
        p = _w().witness_clearing_fidelity(2, 20, 10)
        assert p.factor_b == 20.0

    def test_factor_c_is_output_field_count(self):
        p = _w().witness_clearing_fidelity(2, 15, 7)
        assert p.factor_c == 7.0

    def test_context_at_level_1(self):
        p = _w().witness_clearing_fidelity(2, 15, 8)
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "clearing-fidelity"
        assert p.ai_context["clearing_level_applied"] == 2
        assert p.ai_context["input_field_count"] == 15
        assert p.ai_context["output_field_count"] == 8

    def test_context_stripped_at_level_2(self):
        p = _w(clearing_level=2).witness_clearing_fidelity(2, 15, 8)
        assert p.ai_context is None

    def test_anomaly_detected_flag(self):
        p = _w().witness_clearing_fidelity(2, 15, 8, anomaly_detected=True)
        assert p.ai_context["anomaly_detected"] is True

    def test_optional_engine_version(self):
        p = _w().witness_clearing_fidelity(2, 15, 8, clearing_engine_version="v2.1.0")
        assert p.ai_context["clearing_engine_version"] == "v2.1.0"

    def test_optional_fidelity_hash(self):
        p = _w().witness_clearing_fidelity(2, 15, 8, fidelity_hash="abc123def456")
        assert p.ai_context["fidelity_hash"] == "abc123def456"

    def test_optional_stripped_fields(self):
        p = _w().witness_clearing_fidelity(2, 15, 8, stripped_fields=["prompt", "response", "system_prompt"])
        assert p.ai_context["stripped_fields"] == ["prompt", "response", "system_prompt"]

    def test_model_id_default(self):
        p = _w().witness_clearing_fidelity(2, 15, 8)
        assert p.ai_model_id == "clearing-fidelity"

    def test_model_id_used_when_provided(self):
        p = _w().witness_clearing_fidelity(2, 15, 8, model_id="custom")
        assert p.ai_model_id == "custom"

    def test_fingerprint_is_12_hex(self):
        p = _w().witness_clearing_fidelity(2, 15, 8)
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)

    def test_clearing_level_0_full_retention(self):
        """At CL0, all fields retained -- output should equal input."""
        p = _w(clearing_level=0).witness_clearing_fidelity(0, 15, 15)
        assert p.factor_a == 0.0
        assert p.factor_b == 15.0
        assert p.factor_c == 15.0

    def test_clearing_level_3_maximum_stripping(self):
        """At CL3, most fields stripped -- output much less than input."""
        p = _w().witness_clearing_fidelity(3, 15, 3)
        assert p.factor_a == 3.0
        assert p.factor_c == 3.0


if __name__ == "__main__":
    unittest.main()
