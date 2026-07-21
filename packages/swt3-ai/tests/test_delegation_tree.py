"""Tests for AI-DEL.1 Delegation Tree Witnessing."""

from unittest.mock import MagicMock
from swt3_ai.witness import Witness
from swt3_ai.fingerprint import sha256_truncated


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


class TestWitnessDelegationTree:
    def test_mints_correct_procedure_and_factors(self):
        w = _make_witness()
        p = w.witness_delegation_tree("agent-root", "read_file,write_file", 2)
        assert p.procedure_id == "AI-DEL.1"
        # fa = uint32 from SHA256(delegator_id)[:8]
        delegator_hash = sha256_truncated("agent-root", 16)
        assert p.factor_a == float(int(delegator_hash[:8], 16))
        # fb = uint32 from SHA256(scope)[:8]
        scope_hash = sha256_truncated("read_file,write_file", 16)
        assert p.factor_b == float(int(scope_hash[:8], 16))
        assert p.factor_c == 2.0
        assert p.anchor_fingerprint
        w._buffer.enqueue_many.assert_called_once()

    def test_depth_zero_root_grant(self):
        w = _make_witness()
        p = w.witness_delegation_tree("root", "admin", 0)
        assert p.factor_c == 0.0

    def test_context_fields_at_cl1(self):
        w = _make_witness(clearing_level=1)
        p = w.witness_delegation_tree(
            "orchestrator", "execute_query", 1,
            delegates=["worker-a", "worker-b"],
            tree_hash="abc123",
            cascade_revocation=True,
            time_bound_minutes=60,
            parent_grant_fingerprint="f1f2f3f4f5f6",
        )
        ctx = p.ai_context
        assert ctx is not None
        assert ctx["provider"] == "delegation-tree"
        assert ctx["delegator_hash"] == sha256_truncated("orchestrator", 16)
        assert ctx["scope_hash"] == sha256_truncated("execute_query", 16)
        assert ctx["cascade_revocation"] is True
        assert ctx["time_bound_minutes"] == 60
        assert ctx["tree_hash"] == "abc123"
        assert ctx["parent_grant_fingerprint"] == "f1f2f3f4f5f6"
        # Delegates must be hashed
        assert len(ctx["delegates"]) == 2
        assert ctx["delegates"][0] == sha256_truncated("worker-a")
        assert ctx["delegates"][1] == sha256_truncated("worker-b")
        assert p.ai_model_id == "delegation-tree-depth-1"

    def test_cascade_revocation_default_false(self):
        w = _make_witness()
        p = w.witness_delegation_tree("root", "scope", 0)
        assert p.ai_context["cascade_revocation"] is False

    def test_clearing_level_3_strips_context(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_delegation_tree(
            "root", "scope", 2,
            delegates=["child"],
            cascade_revocation=True,
        )
        assert p.ai_context is None

    def test_from_tools_helper(self):
        w = _make_witness()
        p = Witness.delegation_tree_from_tools(
            w, "agent-1", ["write_file", "read_file", "execute"],
        )
        assert p.procedure_id == "AI-DEL.1"
        # Scope should be sorted join
        expected_scope = "execute,read_file,write_file"
        scope_hash = sha256_truncated(expected_scope, 16)
        assert p.factor_b == float(int(scope_hash[:8], 16))
        assert p.factor_c == 1.0  # default depth=1

    def test_from_capabilities_helper(self):
        w = _make_witness()
        p = Witness.delegation_tree_from_capabilities(
            w, "agent-1", ["internet_access", "code_execution"],
        )
        assert p.procedure_id == "AI-DEL.1"
        expected_scope = "code_execution,internet_access"
        scope_hash = sha256_truncated(expected_scope, 16)
        assert p.factor_b == float(int(scope_hash[:8], 16))

    def test_from_tools_custom_depth(self):
        w = _make_witness()
        p = Witness.delegation_tree_from_tools(
            w, "agent-1", ["tool_a"], delegation_depth=3,
        )
        assert p.factor_c == 3.0

    def test_fingerprint_is_valid_hex(self):
        w = _make_witness()
        p = w.witness_delegation_tree("agent", "scope", 1)
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)  # Should not raise

    def test_deep_delegation_tree(self):
        w = _make_witness()
        p = w.witness_delegation_tree("agent", "scope", 99)
        assert p.factor_c == 99.0
