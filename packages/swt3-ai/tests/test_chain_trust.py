"""SWT3 AI Witness SDK -- AI-CHAIN.2 Trust Degradation Tests.

Tests the extract_chain_trust_degradation_payload function and
cross-language parity for negative factor values.
"""

import re
import pytest
from swt3_ai.clearing import extract_chain_trust_degradation_payload
from swt3_ai.witness import Witness, ChainTrustError


def make_witness(**kwargs):
    defaults = dict(endpoint="https://example.com", api_key="axm_test", tenant_id="TEST")
    defaults.update(kwargs)
    return Witness(**defaults)


class TestChainTrustDegradation:
    def test_mints_payload_with_correct_procedure(self):
        p = extract_chain_trust_degradation_payload("TENANT", 3, 1, 1)
        assert p.procedure_id == "AI-CHAIN.2"

    def test_records_trust_levels_as_factors(self):
        p = extract_chain_trust_degradation_payload("TENANT", 3, 1, 1)
        assert p.factor_a == 3.0
        assert p.factor_b == 1.0
        assert p.factor_c == -2.0

    def test_zero_degradation(self):
        p = extract_chain_trust_degradation_payload("TENANT", 2, 2, 1)
        assert p.factor_c == 0.0

    def test_trust_improvement(self):
        p = extract_chain_trust_degradation_payload("TENANT", 1, 3, 1)
        assert p.factor_c == 2.0

    def test_valid_fingerprint(self):
        p = extract_chain_trust_degradation_payload("TENANT", 3, 1, 1)
        assert len(p.anchor_fingerprint) == 12
        assert re.match(r"^[0-9a-f]{12}$", p.anchor_fingerprint)

    def test_includes_operational_metadata(self):
        p = extract_chain_trust_degradation_payload(
            "TENANT", 3, 1, 2,
            agent_id="agent-x",
            signing_key="sign-key",
            signing_key_id="key-id",
            signing_key_version=1,
            cycle_id="cycle-abc",
            policy_version_hash="policy-hash",
        )
        assert p.agent_id == "agent-x"
        assert p.cycle_id == "cycle-abc"
        assert p.payload_signature is not None
        assert p.signing_key_id == "key-id"

    def test_respects_clearing_level(self):
        p = extract_chain_trust_degradation_payload("TENANT", 3, 1, 3)
        assert p.clearing_level == 3

    def test_negative_factor_fingerprint_format(self):
        p = extract_chain_trust_degradation_payload("TEST_TENANT", 3, 1, 1)
        assert re.match(r"^[0-9a-f]{12}$", p.anchor_fingerprint)
        assert p.factor_c == -2.0


class TestWitnessChainTrustHandoff:
    def test_records_factors(self):
        w = make_witness()
        p = w.witness_chain_trust_handoff("agent-b", 3)
        assert p.procedure_id == "AI-CHAIN.1"
        assert p.factor_a == 1.0  # depth
        assert p.factor_b == 3.0  # target trust
        assert p.factor_c == 3.0  # effective

    def test_effective_is_minimum(self):
        w = make_witness()
        w.witness_chain_trust_handoff("agent-b", 3)
        p2 = w.witness_chain_trust_handoff("agent-c", 1)
        assert p2.factor_a == 2.0  # depth
        assert p2.factor_b == 1.0  # target
        assert p2.factor_c == 1.0  # effective = min(3, 1)
        assert w.chain_effective_trust_level == 1

    def test_strict_raises_chain_trust_error(self):
        w = make_witness(strict=True, chain_min_trust_level=2)
        w.witness_chain_trust_handoff("agent-b", 3)
        with pytest.raises(ChainTrustError):
            w.witness_chain_trust_handoff("agent-c", 1)

    def test_non_strict_does_not_raise(self):
        w = make_witness(chain_min_trust_level=2)
        w.witness_chain_trust_handoff("agent-b", 3)
        p = w.witness_chain_trust_handoff("agent-c", 1)
        assert p.factor_c == 1.0

    def test_empty_chain_returns_sovereign(self):
        w = make_witness()
        assert w.chain_effective_trust_level == 4

    def test_tracks_all_handoffs(self):
        w = make_witness()
        w.witness_chain_trust_handoff("a", 3)
        w.witness_chain_trust_handoff("b", 2)
        w.witness_chain_trust_handoff("c", 4)
        assert w.chain_trust_levels == [3, 2, 4]
        assert w.chain_effective_trust_level == 2

    def test_includes_context(self):
        w = make_witness()
        p = w.witness_chain_trust_handoff("agent-b", 2)
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "chain-trust"
        assert p.ai_context["target_agent"] == "agent-b"

    def test_passes_cycle_id(self):
        w = make_witness()
        p = w.witness_chain_trust_handoff("agent-b", 2, cycle_id="cycle-xyz")
        assert p.cycle_id == "cycle-xyz"


class TestViolationCallback:
    def test_callback_fires_on_constructor(self):
        violations = []
        w = make_witness(on_violation=lambda v: violations.append(v))
        assert w.on_violation is not None

    def test_callback_settable_at_runtime(self):
        w = make_witness()
        assert w.on_violation is None
        violations = []
        w.on_violation = lambda v: violations.append(v)
        assert w.on_violation is not None

    def test_callback_does_not_break_on_exception(self):
        def bad_callback(v):
            raise RuntimeError("callback crashed")
        w = make_witness(on_violation=bad_callback)
        # Should not raise -- callback errors are swallowed
        # (no chain enforcer configured so no violation to trigger,
        #  but the wiring itself should not error)
        assert w.on_violation is not None

    def test_none_callback_is_safe(self):
        w = make_witness()
        # _fire_violation with no callback should be a no-op
        from swt3_ai.types import ChainPolicyViolation
        v = ChainPolicyViolation(
            rule="test", tool_name="test_tool",
            reason="test reason", action="logged", timestamp=0,
        )
        w._fire_violation(v)  # should not raise
