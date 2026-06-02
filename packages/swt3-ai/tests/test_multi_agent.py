"""Tests for AI-MULTI.1 Multi-Agent Delegation Witnessing."""

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


class TestWitnessMultiAgentDelegation:
    def test_mints_correct_procedure_and_factors(self):
        w = _make_witness()
        p = w.witness_multi_agent_delegation(
            2, 5, 60, "orchestrator-1", "worker-2",
        )
        assert p.procedure_id == "AI-MULTI.1"
        assert p.factor_a == 2.0
        assert p.factor_b == 5.0
        assert p.factor_c == 60.0
        assert p.anchor_fingerprint
        w._buffer.enqueue_many.assert_called_once()

    def test_unbounded_delegation(self):
        w = _make_witness()
        p = w.witness_multi_agent_delegation(
            1, 3, 0, "parent", "child",
        )
        assert p.factor_c == 0.0

    def test_hashes_agent_ids_in_context(self):
        w = _make_witness()
        p = w.witness_multi_agent_delegation(
            1, 2, 30, "orchestrator-1", "worker-2",
        )
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "multi-agent"
        # Agent IDs must be hashed
        assert p.ai_context["parent_agent_hash"] != "orchestrator-1"
        assert p.ai_context["child_agent_hash"] != "worker-2"
        assert p.ai_context["parent_agent_hash"] == sha256_truncated("orchestrator-1")
        assert p.ai_context["child_agent_hash"] == sha256_truncated("worker-2")
        assert p.ai_model_id == "delegation-depth-1"

    def test_includes_delegated_tools(self):
        w = _make_witness(clearing_level=0)
        p = w.witness_multi_agent_delegation(
            1, 3, 120, "p", "c",
            delegated_tools=["read_file", "write_file", "execute_query"],
        )
        assert p.ai_context["delegated_tools"] == [
            "read_file", "write_file", "execute_query",
        ]

    def test_includes_scope_hash(self):
        w = _make_witness()
        p = w.witness_multi_agent_delegation(
            1, 2, 60, "p", "c",
            scope_hash="abc123def456",
        )
        assert p.ai_context["scope_hash"] == "abc123def456"

    def test_hashes_authorization_chain(self):
        w = _make_witness()
        p = w.witness_multi_agent_delegation(
            3, 2, 60, "mid-agent", "leaf-agent",
            authorization_chain=["human-user", "orchestrator", "mid-agent"],
        )
        chain = p.ai_context["authorization_chain"]
        assert len(chain) == 3
        assert chain[0] != "human-user"
        assert chain[0] == sha256_truncated("human-user")
        assert chain[1] == sha256_truncated("orchestrator")
        assert chain[2] == sha256_truncated("mid-agent")

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_multi_agent_delegation(
            2, 5, 60, "p", "c",
            delegated_tools=["tool1"],
        )
        assert p.ai_context is None
        assert p.factor_a == 2.0
        assert p.factor_b == 5.0
        assert p.factor_c == 60.0

    def test_preserves_factors_at_clearing_level_3(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_multi_agent_delegation(
            4, 10, 0, "p", "c",
        )
        assert p.ai_context is None
        assert p.factor_a == 4.0
        assert p.factor_b == 10.0
        assert p.factor_c == 0.0

    def test_deep_delegation(self):
        w = _make_witness()
        p = w.witness_multi_agent_delegation(
            10, 1, 5, "agent-9", "agent-10",
        )
        assert p.factor_a == 10.0

    def test_valid_fingerprint(self):
        w = _make_witness()
        p = w.witness_multi_agent_delegation(
            1, 1, 0, "a", "b",
        )
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)
