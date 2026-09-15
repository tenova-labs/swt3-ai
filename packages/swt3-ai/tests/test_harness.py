"""Tests for Harness Governance witness methods (v0.7.2)."""
from unittest.mock import MagicMock
from swt3_ai.types import ORCHESTRATION_TOPOLOGY_CODES, EVICTION_METHOD_CODES


def _make_witness(clearing_level=1, **kwargs):
    from swt3_ai.witness import Witness
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="test_tenant", clearing_level=clearing_level, **kwargs)
    w._buffer = MagicMock()
    return w


class TestWitnessOrchestrationTopology:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_orchestration_topology("parallel", 3, 2)
        assert p.procedure_id == "AI-ORCH.1"
        assert p.factor_a == 1.0  # parallel = 1
        assert p.factor_b == 3.0
        assert p.factor_c == 2.0
        assert len(p.anchor_fingerprint) == 12

    def test_maps_all_topologies(self):
        w = _make_witness()
        for topo, code in ORCHESTRATION_TOPOLOGY_CODES.items():
            p = w.witness_orchestration_topology(topo, 1)
            assert p.factor_a == float(code), f"{topo} should map to {code}"

    def test_unknown_topology_defaults_zero(self):
        w = _make_witness()
        p = w.witness_orchestration_topology("unknown_topology", 1)
        assert p.factor_a == 0.0

    def test_default_dependency_depth_zero(self):
        w = _make_witness()
        p = w.witness_orchestration_topology("sequential", 2)
        assert p.factor_c == 0.0

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_orchestration_topology("hierarchical", 5, 3)
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "harness-governance"
        assert p.ai_context["topology"] == "hierarchical"
        assert p.ai_context["agent_count"] == 5
        assert p.ai_context["dependency_depth"] == 3

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_orchestration_topology("parallel", 3)
        assert p.ai_context is None

    def test_negative_agent_count_clamped(self):
        w = _make_witness()
        p = w.witness_orchestration_topology("parallel", -1)
        assert p.factor_b == 0.0


class TestWitnessAgentHandoff:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_agent_handoff("agent-a", "agent-b", 0)
        assert p.procedure_id == "AI-ORCH.2"
        assert isinstance(p.factor_a, float)
        assert isinstance(p.factor_b, float)
        assert p.factor_c == 0.0
        assert len(p.anchor_fingerprint) == 12

    def test_distinct_agent_hashes(self):
        w = _make_witness()
        p = w.witness_agent_handoff("agent-a", "agent-b")
        assert p.factor_a != p.factor_b

    def test_deterministic_hashing(self):
        w = _make_witness()
        p1 = w.witness_agent_handoff("same-agent", "same-target")
        p2 = w.witness_agent_handoff("same-agent", "same-target")
        assert p1.factor_a == p2.factor_a
        assert p1.factor_b == p2.factor_b

    def test_permission_delta_clamping(self):
        w = _make_witness()
        p = w.witness_agent_handoff("a", "b", 5)
        assert p.factor_c == 1.0
        p = w.witness_agent_handoff("a", "b", -5)
        assert p.factor_c == -1.0

    def test_escalation_label(self):
        w = _make_witness()
        p = w.witness_agent_handoff("a", "b", 1)
        assert p.ai_model_id == "orch-handoff-escalation"
        assert p.ai_context["permission_delta"] == 1

    def test_restriction_label(self):
        w = _make_witness()
        p = w.witness_agent_handoff("a", "b", -1)
        assert p.ai_model_id == "orch-handoff-restriction"
        assert p.ai_context["permission_delta"] == -1

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_agent_handoff("a", "b", 1)
        assert p.ai_context is None


class TestWitnessContextWindow:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_context_window(8000, 4000, "truncation")
        assert p.procedure_id == "AI-CTX.1"
        assert p.factor_a == 8000.0
        assert p.factor_b == 4000.0
        assert p.factor_c == 1.0  # truncation = 1
        assert len(p.anchor_fingerprint) == 12

    def test_maps_all_eviction_methods(self):
        w = _make_witness()
        for method, code in EVICTION_METHOD_CODES.items():
            p = w.witness_context_window(1000, 500, method)
            assert p.factor_c == float(code), f"{method} should map to {code}"

    def test_unknown_eviction_defaults_zero(self):
        w = _make_witness()
        p = w.witness_context_window(1000, 500, "unknown_method")
        assert p.factor_c == 0.0

    def test_default_eviction_none(self):
        w = _make_witness()
        p = w.witness_context_window(1000, 1000)
        assert p.factor_c == 0.0  # none = 0

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_context_window(8000, 4000, "summarization")
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "harness-governance"
        assert p.ai_context["tokens_before"] == 8000
        assert p.ai_context["tokens_after"] == 4000
        assert p.ai_context["eviction_method"] == "summarization"

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_context_window(8000, 4000)
        assert p.ai_context is None

    def test_negative_tokens_clamped(self):
        w = _make_witness()
        p = w.witness_context_window(-100, -50)
        assert p.factor_a == 0.0
        assert p.factor_b == 0.0


class TestWitnessSandboxEnforcement:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_sandbox_enforcement(10, 5, 0)
        assert p.procedure_id == "AI-SAND.1"
        assert p.factor_a == 10.0
        assert p.factor_b == 5.0
        assert p.factor_c == 0.0
        assert len(p.anchor_fingerprint) == 12

    def test_clean_sandbox_model_id(self):
        w = _make_witness()
        p = w.witness_sandbox_enforcement(10, 5, 0)
        assert p.ai_model_id == "sandbox-clean"

    def test_violation_model_id(self):
        w = _make_witness()
        p = w.witness_sandbox_enforcement(10, 5, 2)
        assert p.ai_model_id == "sandbox-violation"

    def test_default_violations_zero(self):
        w = _make_witness()
        p = w.witness_sandbox_enforcement(10, 5)
        assert p.factor_c == 0.0

    def test_negative_violations_clamped(self):
        w = _make_witness()
        p = w.witness_sandbox_enforcement(10, 5, -3)
        assert p.factor_c == 0.0

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_sandbox_enforcement(10, 5, 1)
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "harness-governance"
        assert p.ai_context["tools_declared"] == 10
        assert p.ai_context["tools_invoked"] == 5
        assert p.ai_context["violations"] == 1

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_sandbox_enforcement(10, 5, 0)
        assert p.ai_context is None


class TestWitnessEvalGate:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_eval_gate(100, 85)
        assert p.procedure_id == "AI-GATE.1"
        assert p.factor_a == 100.0
        assert p.factor_b == 85.0
        assert p.factor_c == 85.0  # auto-computed: 85/100 * 100
        assert len(p.anchor_fingerprint) == 12

    def test_auto_computed_gate_score(self):
        w = _make_witness()
        p = w.witness_eval_gate(200, 150)
        assert p.factor_c == 75.0  # 150/200 * 100

    def test_explicit_gate_score(self):
        w = _make_witness()
        p = w.witness_eval_gate(100, 85, gate_score=90)
        assert p.factor_c == 90.0

    def test_gate_score_clamped_to_100(self):
        w = _make_witness()
        p = w.witness_eval_gate(100, 85, gate_score=150)
        assert p.factor_c == 100.0

    def test_gate_score_clamped_to_zero(self):
        w = _make_witness()
        p = w.witness_eval_gate(100, 85, gate_score=-10)
        assert p.factor_c == 0.0

    def test_pass_model_id(self):
        w = _make_witness()
        p = w.witness_eval_gate(100, 80)
        assert p.ai_model_id == "eval-gate-pass"

    def test_fail_model_id(self):
        w = _make_witness()
        p = w.witness_eval_gate(100, 50)
        assert p.ai_model_id == "eval-gate-fail"

    def test_zero_total_evals(self):
        w = _make_witness()
        p = w.witness_eval_gate(0, 0)
        assert p.factor_c == 0.0  # 0/1 * 100 = 0

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_eval_gate(100, 85)
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "harness-governance"
        assert p.ai_context["total_evals"] == 100
        assert p.ai_context["evals_passed"] == 85
        assert p.ai_context["gate_score"] == 85

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_eval_gate(100, 85)
        assert p.ai_context is None

    def test_propagates_agent_id(self):
        w = _make_witness(agent_id="harness-001")
        p = w.witness_eval_gate(100, 85)
        assert p.agent_id == "harness-001"
