"""Tests for AI-SAFE.2 Agent Interrupt Witnessing."""
from unittest.mock import MagicMock

from swt3_ai import Witness


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


class TestWitnessAgentInterrupt:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_agent_interrupt("human_operator")
        assert p.procedure_id == "AI-SAFE.2"
        assert p.factor_a == 0.0  # human_operator = 0
        assert p.factor_b == 0.0  # default actions_suspended
        assert p.factor_c == 1.0  # default state_preserved = True
        assert p.anchor_fingerprint

    def test_all_trigger_codes(self):
        w = _make_witness()
        codes = {
            "human_operator": 0, "automated_threshold": 1, "chain_break": 2,
            "policy_engine": 3, "external_signal": 4, "peer_agent": 5,
        }
        for name, code in codes.items():
            p = w.witness_agent_interrupt(name)
            assert p.factor_a == float(code), f"Failed for {name}"

    def test_actions_suspended(self):
        w = _make_witness()
        p = w.witness_agent_interrupt("policy_engine", actions_suspended=7)
        assert p.factor_b == 7.0

    def test_state_not_preserved(self):
        w = _make_witness()
        p = w.witness_agent_interrupt("chain_break", state_preserved=False)
        assert p.factor_c == 0.0

    def test_negative_actions_clamped(self):
        w = _make_witness()
        p = w.witness_agent_interrupt("human_operator", actions_suspended=-3)
        assert p.factor_b == 0.0

    def test_unknown_trigger_defaults_to_zero(self):
        w = _make_witness()
        p = w.witness_agent_interrupt("unknown_source")
        assert p.factor_a == 0.0

    def test_context_at_cl1(self):
        w = _make_witness(clearing_level=1)
        p = w.witness_agent_interrupt(
            "external_signal",
            actions_suspended=3,
            state_preserved=True,
            interrupt_reason="safety threshold exceeded",
            resume_allowed=True,
        )
        ctx = p.ai_context
        assert ctx is not None
        assert ctx["provider"] == "interrupt-governance"
        assert ctx["trigger_source"] == "external_signal"
        assert ctx["state_preserved"] is True
        assert ctx["resume_allowed"] is True
        assert ctx["interrupt_reason"] == "safety threshold exceeded"

    def test_context_stripped_at_cl3(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_agent_interrupt("human_operator",
                                      interrupt_reason="test")
        assert p.ai_context is None

    def test_model_id_reflects_trigger(self):
        w = _make_witness()
        p = w.witness_agent_interrupt("peer_agent")
        assert p.ai_model_id == "interrupt-peer_agent"

    def test_always_passes(self):
        w = _make_witness()
        # Even with state lost and actions suspended, verdict should be informational
        p = w.witness_agent_interrupt("chain_break", actions_suspended=10,
                                      state_preserved=False)
        assert p.procedure_id == "AI-SAFE.2"
        # factor_c = 0 (state not preserved) but this is informational, not a failure

    def test_enqueue_called(self):
        w = _make_witness()
        w.witness_agent_interrupt("human_operator")
        w._buffer.enqueue_many.assert_called_once()
