"""Tests for NHI (Non-Human Identity) governance witness methods."""
from unittest.mock import MagicMock
from swt3_ai.witness import (
    Witness, NHI_LIFECYCLE_EVENT_CODES, NHI_ROTATION_REASON_CODES,
    NHI_REVOCATION_REASON_CODES,
)


def _make_witness(clearing_level=1, **kwargs):
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="test_tenant", clearing_level=clearing_level, **kwargs)
    w._buffer = MagicMock()
    return w


class TestWitnessNhiScope:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_nhi_scope("cred-abc-123", "read,write", 3600)
        assert p.procedure_id == "NHI-SCOPE.1"
        assert isinstance(p.factor_a, float)
        assert isinstance(p.factor_b, float)
        assert p.factor_c == 3600.0
        assert len(p.anchor_fingerprint) == 12

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_nhi_scope("cred-abc-123", "read,write")
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "nhi-governance"
        assert "credential_id_hash" in p.ai_context
        assert "scope_hash" in p.ai_context

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_nhi_scope("cred-abc-123", "read,write")
        assert p.ai_context is None

    def test_default_ttl_zero(self):
        w = _make_witness()
        p = w.witness_nhi_scope("cred", "scope")
        assert p.factor_c == 0.0

    def test_deterministic_hashing(self):
        w = _make_witness()
        p1 = w.witness_nhi_scope("same-cred", "same-scope")
        p2 = w.witness_nhi_scope("same-cred", "same-scope")
        assert p1.factor_a == p2.factor_a
        assert p1.factor_b == p2.factor_b


class TestWitnessNhiLifecycle:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_nhi_lifecycle("issued", "cred-123", "EntraID")
        assert p.procedure_id == "NHI-CYCLE.1"
        assert p.factor_a == 1.0

    def test_maps_all_event_types(self):
        w = _make_witness()
        for event, code in NHI_LIFECYCLE_EVENT_CODES.items():
            p = w.witness_nhi_lifecycle(event, "cred", "issuer")
            assert p.factor_a == float(code)

    def test_unknown_event_defaults_zero(self):
        w = _make_witness()
        p = w.witness_nhi_lifecycle("unknown_event", "cred", "issuer")
        assert p.factor_a == 0.0


class TestWitnessNhiPrivilegeChange:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_nhi_privilege_change("cred-123", "read", "read,write,admin")
        assert p.procedure_id == "NHI-PRIV.1"
        assert p.factor_b != 0.0
        assert p.factor_c != 0.0

    def test_empty_previous_scope(self):
        w = _make_witness()
        p = w.witness_nhi_privilege_change("cred-123", "", "read,write")
        assert p.factor_b == 0.0
        assert p.factor_c != 0.0


class TestWitnessNhiRotation:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_nhi_rotation("old-cred", "new-cred", "scheduled")
        assert p.procedure_id == "NHI-ROTATE.1"
        assert p.factor_c == 1.0

    def test_maps_all_reason_codes(self):
        w = _make_witness()
        for reason, code in NHI_ROTATION_REASON_CODES.items():
            p = w.witness_nhi_rotation("old", "new", reason)
            assert p.factor_c == float(code)

    def test_old_new_are_distinct_factors(self):
        w = _make_witness()
        p = w.witness_nhi_rotation("old-cred", "new-cred")
        assert p.factor_a != p.factor_b


class TestWitnessNhiDelegation:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_nhi_delegation("agent-a-cred", "agent-b-cred", 1)
        assert p.procedure_id == "NHI-AGENT.1"
        assert p.factor_c == 1.0

    def test_depth_minimum_is_one(self):
        w = _make_witness()
        p = w.witness_nhi_delegation("a", "b", 0)
        assert p.factor_c == 1.0

    def test_chained_delegation(self):
        w = _make_witness()
        p = w.witness_nhi_delegation("a", "b", 3)
        assert p.factor_c == 3.0


class TestWitnessNhiRevocation:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_nhi_revocation("cred-123", "policy_violation", cascade=True)
        assert p.procedure_id == "NHI-REVOKE.1"
        assert p.factor_b == 2.0
        assert p.factor_c == 1.0

    def test_maps_all_reason_codes(self):
        w = _make_witness()
        for reason, code in NHI_REVOCATION_REASON_CODES.items():
            p = w.witness_nhi_revocation("cred", reason)
            assert p.factor_b == float(code)

    def test_no_cascade_default(self):
        w = _make_witness()
        p = w.witness_nhi_revocation("cred")
        assert p.factor_c == 0.0

    def test_propagates_agent_id(self):
        w = _make_witness(agent_id="test-agent")
        p = w.witness_nhi_revocation("cred")
        assert p.agent_id == "test-agent"
