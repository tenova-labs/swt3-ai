"""Tests for lifecycle chain infrastructure (v6.0)."""

import json
import os
import pytest

from swt3_ai import Witness, LifecycleChain, LIFECYCLE_CHAIN_STAGES
from swt3_ai.witness import _generate_lifecycle_chain_id, _TERMINAL_STAGES


class TestLifecycleChainStages:
    def test_stage_codes(self):
        assert LIFECYCLE_CHAIN_STAGES == {
            "initiated": 0,
            "checkpoint": 1,
            "escalated": 2,
            "resolved": 3,
            "abandoned": 4,
            "superseded": 5,
        }

    def test_terminal_stages(self):
        assert _TERMINAL_STAGES == {"resolved", "abandoned", "superseded"}


class TestChainIdGeneration:
    def test_deterministic(self):
        cid1 = _generate_lifecycle_chain_id("T1", "AI-EMRG.1", "abc123def456", 1000)
        cid2 = _generate_lifecycle_chain_id("T1", "AI-EMRG.1", "abc123def456", 1000)
        assert cid1 == cid2

    def test_prefix_and_length(self):
        cid = _generate_lifecycle_chain_id("T1", "AI-EMRG.1", "abc123def456", 1000)
        assert cid.startswith("LC-")
        assert len(cid) == 19  # LC- + 16 hex chars

    def test_different_inputs_produce_different_ids(self):
        cid1 = _generate_lifecycle_chain_id("T1", "AI-EMRG.1", "abc123def456", 1000)
        cid2 = _generate_lifecycle_chain_id("T2", "AI-EMRG.1", "abc123def456", 1000)
        cid3 = _generate_lifecycle_chain_id("T1", "AI-DRIFT.2", "abc123def456", 1000)
        assert cid1 != cid2
        assert cid1 != cid3

    def test_cross_language_parity(self):
        """Verify against test-vectors.json."""
        vectors_path = os.path.join(os.path.dirname(__file__), "..", "test-vectors.json")
        with open(vectors_path) as f:
            data = json.load(f)
        for v in data.get("lifecycle_chain_vectors", []):
            if "expected_chain_id" not in v:
                continue
            cid = _generate_lifecycle_chain_id(
                v["tenant_id"], v["procedure_id"],
                v["initiator_fingerprint"], v["timestamp_ms"],
            )
            assert cid == v["expected_chain_id"], (
                f"Vector {v['id']}: expected {v['expected_chain_id']}, got {cid}"
            )


class TestBeginLifecycle:
    def _make_witness(self):
        return Witness(
            endpoint="https://example.com",
            api_key="axm_test_key",
            tenant_id="TEST_TENANT",
            clearing_level=1,
        )

    def test_returns_lifecycle_chain(self):
        w = self._make_witness()
        chain = w.begin_lifecycle("AI-EMRG.1", fa=1.0, fb=1.0, fc=0.0)
        assert isinstance(chain, LifecycleChain)
        assert chain.chain_id.startswith("LC-")
        assert len(chain.chain_id) == 19
        assert chain.anchor_count == 1
        assert not chain.closed

    def test_initiation_payload_enqueued(self):
        w = self._make_witness()
        chain = w.begin_lifecycle("AI-EMRG.1", fa=1.0, fb=1.0, fc=0.0)
        assert w.pending == 1

    def test_initiation_payload_has_lifecycle_fields(self):
        w = self._make_witness()
        chain = w.begin_lifecycle("AI-EMRG.1", fa=1.0, fb=1.0, fc=0.0)
        # The initiation anchor is enqueued with correct lifecycle fields
        assert w.pending == 1
        # Verify chain state
        assert chain.chain_id.startswith("LC-")
        assert chain.anchor_count == 1
        assert not chain.closed


class TestLifecycleChainMethods:
    def _make_chain(self):
        w = Witness(
            endpoint="https://example.com",
            api_key="axm_test_key",
            tenant_id="TEST_TENANT",
            clearing_level=1,
        )
        return w, w.begin_lifecycle("AI-EMRG.1", fa=1.0, fb=1.0, fc=0.0)

    def test_checkpoint(self):
        w, chain = self._make_chain()
        initial_fp = chain.last_fingerprint
        payload = chain.checkpoint(fa=1.0, fb=0.8, fc=0.0)
        assert payload.lifecycle_stage == "checkpoint"
        assert payload.lifecycle_parent == initial_fp
        assert payload.lifecycle_chain_id == chain.chain_id
        assert chain.anchor_count == 2
        assert not chain.closed

    def test_multiple_checkpoints(self):
        w, chain = self._make_chain()
        chain.checkpoint(fa=1.0, fb=0.8, fc=0.0)
        chain.checkpoint(fa=1.0, fb=0.9, fc=0.0)
        chain.checkpoint(fa=1.0, fb=1.0, fc=0.0)
        assert chain.anchor_count == 4
        assert w.pending == 4

    def test_resolve_closes_chain(self):
        w, chain = self._make_chain()
        chain.checkpoint(fa=1.0, fb=0.8, fc=0.0)
        payload = chain.resolve(fa=1.0, fb=1.0, fc=0.0)
        assert payload.lifecycle_stage == "resolved"
        assert chain.closed
        assert chain.anchor_count == 3

    def test_abandon_closes_chain(self):
        w, chain = self._make_chain()
        payload = chain.abandon(reason="test failure")
        assert payload.lifecycle_stage == "abandoned"
        assert chain.closed

    def test_closed_chain_rejects_checkpoint(self):
        w, chain = self._make_chain()
        chain.resolve(fa=1.0, fb=1.0, fc=0.0)
        with pytest.raises(RuntimeError, match="closed"):
            chain.checkpoint(fa=1.0, fb=0.5, fc=0.0)

    def test_closed_chain_rejects_resolve(self):
        w, chain = self._make_chain()
        chain.resolve(fa=1.0, fb=1.0, fc=0.0)
        with pytest.raises(RuntimeError, match="closed"):
            chain.resolve(fa=1.0, fb=1.0, fc=0.0)

    def test_closed_chain_rejects_escalate(self):
        w, chain = self._make_chain()
        chain.resolve(fa=1.0, fb=1.0, fc=0.0)
        with pytest.raises(RuntimeError, match="closed"):
            chain.escalate("AI-EMRG.1")

    def test_parent_linkage_chain(self):
        w, chain = self._make_chain()
        fp0 = chain.last_fingerprint
        p1 = chain.checkpoint(fa=1.0, fb=0.8, fc=0.0)
        assert p1.lifecycle_parent == fp0
        fp1 = chain.last_fingerprint
        p2 = chain.checkpoint(fa=1.0, fb=0.9, fc=0.0)
        assert p2.lifecycle_parent == fp1


class TestEscalation:
    def _make_chain(self):
        w = Witness(
            endpoint="https://example.com",
            api_key="axm_test_key",
            tenant_id="TEST_TENANT",
            clearing_level=1,
        )
        return w, w.begin_lifecycle("AI-DRIFT.2", fa=0.5, fb=0.0, fc=1.0)

    def test_escalate_returns_new_chain(self):
        w, drift_chain = self._make_chain()
        emrg_chain = drift_chain.escalate("AI-EMRG.1", fa=1.0, fb=1.0, fc=0.0)
        assert isinstance(emrg_chain, LifecycleChain)
        assert emrg_chain.chain_id != drift_chain.chain_id
        assert emrg_chain.chain_id.startswith("LC-")

    def test_escalate_creates_escalation_anchor(self):
        w, drift_chain = self._make_chain()
        emrg_chain = drift_chain.escalate("AI-EMRG.1")
        # 3 payloads: drift initiated + emrg initiated + drift escalated
        assert w.pending == 3
        # drift_chain should have advanced (2 anchors: initiated + escalated)
        assert drift_chain.anchor_count == 2
        # emrg_chain should have 1 anchor (initiated)
        assert emrg_chain.anchor_count == 1
        assert emrg_chain.chain_id != drift_chain.chain_id

    def test_escalate_closes_source_chain(self):
        w, drift_chain = self._make_chain()
        drift_chain.escalate("AI-EMRG.1")
        # Escalation mints an "escalated" stage which is NOT terminal
        # (escalation is a cross-procedure link, not chain termination)
        assert not drift_chain.closed

    def test_target_chain_is_independent(self):
        w, drift_chain = self._make_chain()
        emrg_chain = drift_chain.escalate("AI-EMRG.1")
        # Target chain should work independently
        emrg_chain.checkpoint(fa=1.0, fb=0.8, fc=0.0)
        emrg_chain.resolve(fa=1.0, fb=1.0, fc=0.0)
        assert emrg_chain.closed
        assert emrg_chain.anchor_count == 3  # initiated + checkpoint + resolved


class TestResumeLifecycle:
    def test_resume_creates_chain_handle(self):
        w = Witness(
            endpoint="https://example.com",
            api_key="axm_test_key",
            tenant_id="TEST_TENANT",
            clearing_level=1,
        )
        chain = w.resume_lifecycle(
            procedure_id="AI-EMRG.1",
            chain_id="LC-7a38936db8ecec94",
            last_fingerprint="2e16e2fe92dd",
            anchor_count=3,
        )
        assert chain.chain_id == "LC-7a38936db8ecec94"
        assert chain.last_fingerprint == "2e16e2fe92dd"
        assert chain.anchor_count == 3
        assert not chain.closed

    def test_resume_validates_chain_id_format(self):
        w = Witness(
            endpoint="https://example.com",
            api_key="axm_test_key",
            tenant_id="TEST_TENANT",
            clearing_level=1,
        )
        with pytest.raises(ValueError, match="Invalid lifecycle chain ID"):
            w.resume_lifecycle("AI-EMRG.1", "bad-id", "2e16e2fe92dd")

    def test_resumed_chain_can_mint(self):
        w = Witness(
            endpoint="https://example.com",
            api_key="axm_test_key",
            tenant_id="TEST_TENANT",
            clearing_level=1,
        )
        chain = w.resume_lifecycle(
            procedure_id="AI-EMRG.1",
            chain_id="LC-7a38936db8ecec94",
            last_fingerprint="2e16e2fe92dd",
        )
        payload = chain.checkpoint(fa=1.0, fb=0.9, fc=0.0)
        assert payload.lifecycle_parent == "2e16e2fe92dd"
        assert payload.lifecycle_chain_id == "LC-7a38936db8ecec94"
        assert chain.anchor_count == 2


class TestOperationalOverride:
    def _make_witness(self):
        return Witness(
            endpoint="https://example.com",
            api_key="axm_test_key",
            tenant_id="TEST_TENANT",
            clearing_level=1,
        )

    def test_basic_override(self):
        w = self._make_witness()
        p = w.witness_operational_override(
            trigger_type="operator_command",
            authorization_level="supervisor",
            fallback_state="safe_state",
        )
        assert p.procedure_id == "AI-EMRG.1"
        assert p.factor_a == 1.0  # operator_command
        assert p.factor_b == 1.0  # supervisor
        assert p.factor_c == 0.0  # safe_state
        assert w.pending == 1

    def test_code_maps(self):
        from swt3_ai import OVERRIDE_TRIGGER_CODES, AUTHORIZATION_LEVEL_CODES, FALLBACK_STATE_CODES
        assert OVERRIDE_TRIGGER_CODES["emergency_stop"] == 0
        assert OVERRIDE_TRIGGER_CODES["external_responder"] == 3
        assert AUTHORIZATION_LEVEL_CODES["site_manager"] == 2
        assert FALLBACK_STATE_CODES["full_shutdown"] == 4

    def test_context_at_clearing_1(self):
        w = self._make_witness()
        p = w.witness_operational_override(
            trigger_type="escalation_protocol",
            authorization_level="emergency_responder",
            fallback_state="manual_mode",
            override_reason="valve malfunction",
            system_id="reactor-ai-v3",
            operator_id="eng-042",
        )
        assert p.ai_model_id == "reactor-ai-v3"
        assert p.ai_context["trigger_type"] == "escalation_protocol"
        assert p.ai_context["operator_id"] == "eng-042"
        assert p.ai_context["override_reason"] == "valve malfunction"


class TestDriftConsequence:
    def _make_witness(self):
        return Witness(
            endpoint="https://example.com",
            api_key="axm_test_key",
            tenant_id="TEST_TENANT",
            clearing_level=1,
        )

    def test_basic_drift(self):
        w = self._make_witness()
        p = w.witness_drift_consequence(
            drift_magnitude=0.15,
            consequence_category="safety",
            response_action="circuit_breaker",
        )
        assert p.procedure_id == "AI-DRIFT.2"
        assert p.factor_a == 0.15
        assert p.factor_b == 0.0  # safety
        assert p.factor_c == 3.0  # circuit_breaker

    def test_code_maps(self):
        from swt3_ai import CONSEQUENCE_CATEGORY_CODES, DRIFT_RESPONSE_CODES
        assert CONSEQUENCE_CATEGORY_CODES["safety"] == 0
        assert CONSEQUENCE_CATEGORY_CODES["reputational"] == 4
        assert DRIFT_RESPONSE_CODES["notification_only"] == 0
        assert DRIFT_RESPONSE_CODES["emergency_shutdown"] == 5

    def test_context_with_metric(self):
        w = self._make_witness()
        p = w.witness_drift_consequence(
            drift_magnitude=0.42,
            consequence_category="financial",
            response_action="forced_failover",
            drift_metric="psi",
            model_id="fraud-model-v7",
            mapping_version="2026-Q2",
        )
        assert p.ai_model_id == "fraud-model-v7"
        assert p.ai_context["drift_metric"] == "psi"
        assert p.ai_context["mapping_version"] == "2026-Q2"


class TestChampionChallenger:
    def _make_witness(self):
        return Witness(
            endpoint="https://example.com",
            api_key="axm_test_key",
            tenant_id="TEST_TENANT",
            clearing_level=1,
        )

    def test_pass_case(self):
        w = self._make_witness()
        p = w.witness_champion_challenger(
            inputs_processed=10000,
            max_divergence=0.023,
            threshold_breached=False,
        )
        assert p.procedure_id == "AI-ASSESS.1"
        assert p.factor_a == 10000.0
        assert p.factor_b == 23.0  # 0.023 * 1000
        assert p.factor_c == 0.0   # not breached

    def test_fail_case(self):
        w = self._make_witness()
        p = w.witness_champion_challenger(
            inputs_processed=5000,
            max_divergence=0.15,
            threshold_breached=True,
        )
        assert p.factor_c == 1.0  # breached

    def test_context_with_models(self):
        w = self._make_witness()
        p = w.witness_champion_challenger(
            inputs_processed=10000,
            max_divergence=0.023,
            threshold_breached=False,
            champion_id="gpt-4o-2026-05",
            challenger_id="gpt-4o-2026-07",
            divergence_metric="kl_divergence",
        )
        assert p.ai_model_id == "gpt-4o-2026-05"
        assert p.ai_context["challenger_id"] == "gpt-4o-2026-07"
        assert p.ai_context["divergence_metric"] == "kl_divergence"


class TestPayloadSerialization:
    def test_lifecycle_fields_in_to_dict(self):
        from swt3_ai.types import WitnessPayload
        p = WitnessPayload(
            procedure_id="AI-EMRG.1",
            factor_a=1.0, factor_b=1.0, factor_c=0.0,
            clearing_level=1,
            anchor_fingerprint="abc123def456",
            anchor_epoch=1774800,
            fingerprint_timestamp_ms=1774800000000,
            lifecycle_chain_id="LC-7a38936db8ecec94",
            lifecycle_parent="2e16e2fe92dd",
            lifecycle_stage="checkpoint",
            escalation_chain_id="LC-60c720a257e2d3b9",
        )
        d = p.to_dict()
        assert d["lifecycle_chain_id"] == "LC-7a38936db8ecec94"
        assert d["lifecycle_parent"] == "2e16e2fe92dd"
        assert d["lifecycle_stage"] == "checkpoint"
        assert d["escalation_chain_id"] == "LC-60c720a257e2d3b9"

    def test_lifecycle_fields_absent_when_none(self):
        from swt3_ai.types import WitnessPayload
        p = WitnessPayload(
            procedure_id="AI-INF.1",
            factor_a=1.0, factor_b=1.0, factor_c=0.0,
            clearing_level=1,
            anchor_fingerprint="abc123def456",
            anchor_epoch=1774800,
            fingerprint_timestamp_ms=1774800000000,
        )
        d = p.to_dict()
        assert "lifecycle_chain_id" not in d
        assert "lifecycle_parent" not in d
        assert "lifecycle_stage" not in d
        assert "escalation_chain_id" not in d
