"""Tests for AI-REDTEAM.1 Adversarial Test Campaign Witnessing."""

from unittest.mock import MagicMock
from swt3_ai.witness import Witness, REDTEAM_CATEGORY_CODES


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


class TestWitnessRedTeam:
    def test_mints_correct_procedure_and_factors(self):
        w = _make_witness()
        p = w.witness_red_team(100, 95, "prompt_injection")
        assert p.procedure_id == "AI-REDTEAM.1"
        assert p.factor_a == 100.0
        assert p.factor_b == 95.0
        assert p.factor_c == 0.0  # prompt_injection
        assert p.anchor_fingerprint
        w._buffer.enqueue_many.assert_called_once()

    def test_maps_all_category_codes(self):
        w = _make_witness()
        for cat, code in REDTEAM_CATEGORY_CODES.items():
            p = w.witness_red_team(10, 8, cat)
            assert p.factor_c == float(code), f"Failed for {cat}"

    def test_unknown_category_defaults_to_ten(self):
        w = _make_witness()
        p = w.witness_red_team(50, 45, "novel_attack_vector")
        assert p.factor_c == 10.0

    def test_context_with_framework_and_campaign(self):
        w = _make_witness()
        p = w.witness_red_team(
            200, 190, "jailbreak",
            framework="OWASP-LLM-Top10",
            campaign_id="rt-2026-05-29",
            model_under_test="gpt-4.1",
            attack_taxonomy="MITRE-ATLAS-v4",
            pass_rate=0.95,
            duration_seconds=3600,
        )
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "red-team"
        assert p.ai_context["coverage_category"] == "jailbreak"
        assert p.ai_context["framework"] == "OWASP-LLM-Top10"
        assert p.ai_context["campaign_id"] == "rt-2026-05-29"
        assert p.ai_context["model_under_test"] == "gpt-4.1"
        assert p.ai_context["attack_taxonomy"] == "MITRE-ATLAS-v4"
        assert p.ai_context["pass_rate"] == 0.95
        assert p.ai_context["duration_seconds"] == 3600
        assert p.ai_model_id == "redteam-jailbreak"

    def test_handles_zero_tests(self):
        w = _make_witness()
        p = w.witness_red_team(0, 0, "data_poisoning")
        assert p.factor_a == 0.0
        assert p.factor_b == 0.0
        assert p.factor_c == 2.0  # data_poisoning

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_red_team(
            100, 95, "supply_chain", framework="NIST-AI-100-2",
        )
        assert p.ai_context is None
        assert p.factor_a == 100.0
        assert p.factor_b == 95.0
        assert p.factor_c == 6.0  # supply_chain

    def test_context_stripped_at_clearing_level_3(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_red_team(50, 48, "comprehensive")
        assert p.ai_context is None
        assert p.factor_c == 10.0

    def test_propagates_agent_id(self):
        w = _make_witness(agent_id="red-team-agent")
        p = w.witness_red_team(10, 9, "model_extraction")
        assert p.agent_id == "red-team-agent"

    def test_valid_fingerprint(self):
        w = _make_witness()
        p = w.witness_red_team(1, 1, "prompt_injection")
        assert len(p.anchor_fingerprint) == 12
        int(p.anchor_fingerprint, 16)
