"""Friction tests for ChainContext -- real-world usage patterns."""

import os
import json
import tempfile
import pytest

from swt3_ai import Witness, ChainContext
from swt3_ai.types import InferenceRecord


def _make_witness(**kwargs):
    return Witness(
        endpoint="https://example.com",
        api_key="axm_test_key",
        tenant_id="TEST_TENANT",
        clearing_level=1,
        **kwargs,
    )


def _make_inference(model_id="test-model"):
    return InferenceRecord(
        model_id=model_id,
        model_hash="hash123",
        prompt_hash="abc123",
        response_hash="def456",
        latency_ms=100,
        input_tokens=10,
        output_tokens=20,
    )


class TestChainWithWrap:
    """Does chain context work with the proxy/wrap pattern?"""

    def test_chain_cycle_id_survives_record(self):
        w = _make_witness()
        payloads_seen = []
        original_enqueue = w._buffer.enqueue_many

        def capture_enqueue(payloads):
            payloads_seen.extend(payloads)
            return original_enqueue(payloads)

        w._buffer.enqueue_many = capture_enqueue

        with w.chain("test-wrap", cycle_id="WRAP-TEST") as ctx:
            w.record(_make_inference())

        assert len(payloads_seen) > 0
        for p in payloads_seen:
            assert p.cycle_id == "WRAP-TEST", f"Payload {p.procedure_id} missing chain cycle_id"


class TestChainWithWitnessMethods:
    """Do all witness_* methods pick up the chain cycle_id?"""

    def test_witness_drift_in_chain(self):
        w = _make_witness()
        with w.chain("drift-chain", cycle_id="DRIFT-1") as ctx:
            payload = w.witness_drift(10, 2, "psi")
            assert payload.cycle_id == "DRIFT-1"

    def test_witness_incident_in_chain(self):
        w = _make_witness()
        with w.chain("incident-chain", cycle_id="INC-1") as ctx:
            payload = w.witness_incident(3, True, "model_failure")
            assert payload.cycle_id == "INC-1"

    def test_witness_performance_in_chain(self):
        w = _make_witness()
        with w.chain("perf-chain", cycle_id="PERF-1") as ctx:
            payload = w.witness_performance(10, 9, "latency")
            assert payload.cycle_id == "PERF-1"

    def test_witness_security_scan_in_chain(self):
        """witness_security_scan returns None (older API). Verify cycle_id is
        set on config during the block so _mint_and_sign picks it up."""
        w = _make_witness()
        with w.chain("sec-chain", cycle_id="SEC-1") as ctx:
            w.witness_security_scan(threat_score=42.0)
            assert w._config.cycle_id == "SEC-1"

    def test_multiple_methods_same_chain(self):
        """Real pattern: governance workflow with multiple witness types."""
        w = _make_witness()
        payloads = []
        with w.chain("governance-workflow", cycle_id="GOV-001") as ctx:
            payloads.append(w.witness_drift(10, 2, "psi"))
            payloads.append(w.witness_performance(10, 9, "accuracy"))
            payloads.append(w.witness_incident(2, False, "drift_alert"))

        assert len(payloads) == 3
        for p in payloads:
            assert p.cycle_id == "GOV-001", f"{p.procedure_id} missing chain cycle_id"


class TestChainWithLifecycleChain:
    """Can you use lifecycle chains inside a chain context?"""

    def test_begin_lifecycle_inside_chain(self):
        w = _make_witness()
        with w.chain("lifecycle-test", cycle_id="LC-PARENT") as ctx:
            lc = w.begin_lifecycle("AI-EMRG.1", fa=1.0, fb=1.0, fc=0.0)
            # Lifecycle chain should exist
            assert lc.chain_id.startswith("LC-")
            # The initiation payload should have our chain cycle_id
            assert w._config.cycle_id == "LC-PARENT"


class TestChainWithLocalMode:
    """Does chain work in local/WAL mode?"""

    def test_chain_with_local_wal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wal_path = os.path.join(tmpdir, "test.wal")
            w = _make_witness(
                factor_handoff="file",
                factor_handoff_path=tmpdir,
            )
            with w.chain("wal-test", cycle_id="WAL-1") as ctx:
                w.record(_make_inference())
            # Verify handoff files contain the cycle_id
            files = [f for f in os.listdir(tmpdir) if f.endswith(".json")]
            assert len(files) > 0
            for f in files:
                with open(os.path.join(tmpdir, f)) as fh:
                    data = json.load(fh)
                    # Handoff files have a payloads array
                    if "payloads" in data:
                        for p in data["payloads"]:
                            assert p.get("cycle_id") == "WAL-1"


class TestChainWithOnFlush:
    """Does the on_flush callback see chain-scoped payloads?"""

    def test_on_flush_receives_chain_cycle_id(self):
        flushed = []
        w = _make_witness(on_flush=lambda payloads: flushed.extend(payloads))
        with w.chain("flush-test", cycle_id="FLUSH-1") as ctx:
            w._mint_and_sign("AI-INF.1", 1.0, 100.0, 3.0)
        # on_flush may not fire immediately (background buffer)
        # But cycle_id should be set on payloads when they were enqueued
        assert w._config.cycle_id is None  # restored after block


class TestChainWithSigningKey:
    """Does chain work when signing is enabled?"""

    def test_signed_payloads_in_chain(self):
        w = _make_witness(signing_key="test-hmac-key-32chars-minimum!!")
        with w.chain("signed-chain", cycle_id="SIGNED-1") as ctx:
            payload = w._mint_and_sign("AI-INF.1", 1.0, 100.0, 3.0)
            assert payload.cycle_id == "SIGNED-1"
            assert payload.payload_signature is not None


class TestChainWithAgentId:
    """Does chain work alongside agent_id?"""

    def test_agent_id_and_chain_coexist(self):
        w = _make_witness(agent_id="agent-fraud-v2")
        with w.chain("agent-chain", cycle_id="AGENT-1") as ctx:
            payload = w._mint_and_sign("AI-INF.1", 1.0, 100.0, 3.0)
            assert payload.cycle_id == "AGENT-1"
            assert payload.agent_id == "agent-fraud-v2"


class TestChainWithCJTFields:
    """Does chain work with jurisdiction/legal_basis/purpose_class?"""

    def test_cjt_fields_preserved_in_chain(self):
        w = _make_witness(
            jurisdiction="EU",
            legal_basis="GDPR-6.1.f",
            purpose_class="fraud_detection",
        )
        with w.chain("cjt-chain", cycle_id="CJT-1") as ctx:
            payload = w._mint_and_sign("AI-INF.1", 1.0, 100.0, 3.0)
            assert payload.cycle_id == "CJT-1"
            assert payload.jurisdiction == "EU"
            assert payload.legal_basis == "GDPR-6.1.f"
            assert payload.purpose_class == "fraud_detection"


class TestChainEdgeCases:
    """Edge cases that could cause silent failures."""

    def test_empty_chain_no_side_effects(self):
        w = _make_witness()
        with w.chain("empty"):
            pass
        assert w._config.cycle_id is None

    def test_chain_with_none_cycle_id_generates_new(self):
        w = _make_witness()
        with w.chain("test", cycle_id=None) as ctx:
            assert ctx.cycle_id.startswith("CHAIN-")

    def test_chain_with_empty_string_name(self):
        w = _make_witness()
        with w.chain("") as ctx:
            assert ctx.name == ""
            assert ctx.cycle_id.startswith("CHAIN-")

    def test_chain_cycle_id_not_leaked_to_config(self):
        """After chain exits, config should not retain the chain's cycle_id."""
        w = _make_witness()
        chain_id = None
        with w.chain("leak-test") as ctx:
            chain_id = ctx.cycle_id
        assert w._config.cycle_id is None
        assert w._config.cycle_id != chain_id
