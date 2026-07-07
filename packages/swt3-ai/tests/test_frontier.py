"""Tests for v0.5.7 frontier procedures: AI-FIN.1, AI-TOOL.2, AI-LCM.1, AI-JUR.1."""

import unittest
from unittest.mock import MagicMock
from swt3_ai.witness import Witness


def _w(clearing_level=1) -> Witness:
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="TEST", clearing_level=clearing_level)
    w._buffer = MagicMock()
    return w


class TestTransactionWitness(unittest.TestCase):
    """AI-FIN.1: Agent Transaction Witnessing."""

    def test_mints_correct_procedure(self):
        p = _w().witness_transaction(5000, "human", "authorized")
        assert p.procedure_id == "AI-FIN.1"

    def test_authorization_codes(self):
        w = _w()
        assert w.witness_transaction(100, "none", "pending").factor_a == 0
        assert w.witness_transaction(100, "pre_approved", "pending").factor_a == 1
        assert w.witness_transaction(100, "human", "pending").factor_a == 2
        assert w.witness_transaction(100, "policy", "pending").factor_a == 3
        assert w.witness_transaction(100, "budget_limit", "pending").factor_a == 4

    def test_amount_cents(self):
        p = _w().witness_transaction(9999, "human", "authorized")
        assert p.factor_b == 9999

    def test_status_codes(self):
        w = _w()
        assert w.witness_transaction(100, "human", "pending").factor_c == 0
        assert w.witness_transaction(100, "human", "authorized").factor_c == 1
        assert w.witness_transaction(100, "human", "denied").factor_c == 2
        assert w.witness_transaction(100, "human", "escalated").factor_c == 3

    def test_context_at_level_1(self):
        p = _w().witness_transaction(5000, "human", "authorized", currency="USD", purpose="payment")
        assert p.ai_context is not None
        assert p.ai_context["currency"] == "USD"
        assert p.ai_context["purpose"] == "payment"

    def test_context_stripped_at_level_2(self):
        p = _w(clearing_level=2).witness_transaction(5000, "human", "authorized")
        assert p.ai_context is None

    def test_fingerprint_is_12_hex(self):
        p = _w().witness_transaction(100, "human", "authorized")
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)


class TestToolPermissionWitness(unittest.TestCase):
    """AI-TOOL.2: Tool Permission Attestation."""

    def test_mints_correct_procedure(self):
        p = _w().witness_tool_permissions(["read", "write"], True)
        assert p.procedure_id == "AI-TOOL.2"

    def test_tool_count(self):
        p = _w().witness_tool_permissions(["a", "b", "c"], True)
        assert p.factor_a == 3

    def test_charter_match(self):
        assert _w().witness_tool_permissions(["a"], True).factor_b == 1
        assert _w().witness_tool_permissions(["a"], False).factor_b == 0

    def test_change_types(self):
        w = _w()
        assert w.witness_tool_permissions(["a"], True, change_type="none").factor_c == 0
        assert w.witness_tool_permissions(["a"], True, change_type="added").factor_c == 1
        assert w.witness_tool_permissions(["a"], True, change_type="removed").factor_c == 2
        assert w.witness_tool_permissions(["a"], True, change_type="escalated").factor_c == 3

    def test_context_includes_tool_info(self):
        p = _w().witness_tool_permissions(["read", "write"], True, charter_hash="abc")
        assert p.ai_context is not None
        assert p.ai_context["tool_count"] == 2
        assert p.ai_context["charter_hash"] == "abc"

    def test_context_stripped_at_level_2(self):
        p = _w(clearing_level=2).witness_tool_permissions(["a"], True)
        assert p.ai_context is None


class TestLifecycleWitness(unittest.TestCase):
    """AI-LCM.1: Agent Lifecycle Witnessing."""

    def test_mints_correct_procedure(self):
        p = _w().witness_lifecycle("spawn")
        assert p.procedure_id == "AI-LCM.1"

    def test_event_codes(self):
        w = _w()
        assert w.witness_lifecycle("spawn").factor_a == 0
        assert w.witness_lifecycle("checkpoint").factor_a == 1
        assert w.witness_lifecycle("migrate").factor_a == 2
        assert w.witness_lifecycle("terminate").factor_a == 3
        assert w.witness_lifecycle("crash").factor_a == 4

    def test_context_tokens(self):
        p = _w().witness_lifecycle("checkpoint", context_tokens=4096)
        assert p.factor_b == 4096

    def test_state_hash_presence(self):
        assert _w().witness_lifecycle("checkpoint", state_hash="abc123").factor_c == 1
        assert _w().witness_lifecycle("checkpoint").factor_c == 0

    def test_context_at_level_1(self):
        p = _w().witness_lifecycle("spawn", parent_agent_id="parent-1", uptime_ms=5000)
        assert p.ai_context is not None
        assert p.ai_context["event"] == "spawn"

    def test_context_stripped_at_level_2(self):
        p = _w(clearing_level=2).witness_lifecycle("terminate")
        assert p.ai_context is None


class TestRoutingWitness(unittest.TestCase):
    """AI-JUR.1: Cross-Border Inference Routing."""

    def test_mints_correct_procedure(self):
        p = _w().witness_routing("US", "DE")
        assert p.procedure_id == "AI-JUR.1"

    def test_region_codes(self):
        p = _w().witness_routing("US", "DE")
        assert p.factor_a == 840  # US ISO numeric
        assert p.factor_b == 276  # DE ISO numeric

    def test_compliance_status_codes(self):
        w = _w()
        assert w.witness_routing("US", "US", "unchecked").factor_c == 0
        assert w.witness_routing("US", "US", "compliant").factor_c == 1
        assert w.witness_routing("US", "US", "blocked").factor_c == 2
        assert w.witness_routing("US", "US", "override").factor_c == 3

    def test_unknown_region_defaults_to_zero(self):
        p = _w().witness_routing("ZZ", "XX")
        assert p.factor_a == 0
        assert p.factor_b == 0

    def test_context_at_level_1(self):
        p = _w().witness_routing("US", "FR", "compliant", routing_decision="geo-route")
        assert p.ai_context is not None
        assert p.ai_context["serving_region"] == "US"
        assert p.ai_context["user_region"] == "FR"

    def test_context_stripped_at_level_2(self):
        p = _w(clearing_level=2).witness_routing("US", "DE")
        assert p.ai_context is None


if __name__ == "__main__":
    unittest.main()
