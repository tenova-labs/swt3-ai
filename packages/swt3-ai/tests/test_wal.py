"""SWT3 AI Witness SDK -- WAL (Write-Ahead Log) + Replay Protection Tests.

Tests crash-resilient buffer and replay protection.
"""

import json
import os
import tempfile

import pytest

from swt3_ai.wal import WriteAheadLog
from swt3_ai.types import WitnessPayload


def mk_payload(fingerprint: str, proc: str = "AI-INF.1") -> WitnessPayload:
    return WitnessPayload(
        procedure_id=proc,
        factor_a=1.0,
        factor_b=0.9,
        factor_c=0.8,
        clearing_level=1,
        anchor_fingerprint=fingerprint,
        anchor_epoch=1234567890,
        fingerprint_timestamp_ms=1700000000000,
        ai_model_id="gpt-4o",
    )


@pytest.fixture
def wal_dir():
    with tempfile.TemporaryDirectory(prefix="swt3-wal-test-") as d:
        yield d


class TestWriteAheadLog:
    def test_append_assigns_increasing_seq(self, wal_dir):
        wal = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        s1 = wal.append(mk_payload("fp_001"))
        s2 = wal.append(mk_payload("fp_002"))
        s3 = wal.append(mk_payload("fp_003"))
        assert s1 == 1
        assert s2 == 2
        assert s3 == 3
        assert wal.current_seq == 3

    def test_persists_to_jsonl(self, wal_dir):
        wal = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        wal.append(mk_payload("fp_persist"))
        wal_file = os.path.join(wal_dir, "test_tenant.wal")
        assert os.path.exists(wal_file)
        with open(wal_file) as f:
            lines = [l for l in f.read().strip().split("\n") if l]
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["seq"] == 1
        assert entry["fingerprint"] == "fp_persist"
        assert entry["payload"]["procedure_id"] == "AI-INF.1"

    def test_mark_flushed_updates_checkpoint(self, wal_dir):
        wal = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        wal.append(mk_payload("fp_flush_1"))
        wal.append(mk_payload("fp_flush_2"))
        wal.mark_flushed(2)
        assert wal.current_checkpoint == 2
        ckpt_file = os.path.join(wal_dir, "test_tenant.ckpt")
        assert open(ckpt_file).read() == "2"

    def test_recover_unflushed_after_crash(self, wal_dir):
        wal = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        wal.append(mk_payload("fp_crash_1"))
        wal.append(mk_payload("fp_crash_2"))
        wal.append(mk_payload("fp_crash_3"))
        wal.mark_flushed(1)  # Only first flushed

        # Simulate crash: new WAL from same directory
        wal2 = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        recovered = wal2.recover()
        assert len(recovered) == 2
        assert recovered[0].anchor_fingerprint == "fp_crash_2"
        assert recovered[1].anchor_fingerprint == "fp_crash_3"

    def test_no_recovery_when_all_flushed(self, wal_dir):
        wal = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        wal.append(mk_payload("fp_all"))
        wal.mark_flushed(1)
        wal2 = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        assert wal2.recover() == []


class TestReplayProtection:
    def test_rejects_duplicate_fingerprints(self, wal_dir):
        wal = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        s1 = wal.append(mk_payload("fp_dup"))
        s2 = wal.append(mk_payload("fp_dup"))
        assert s1 == 1
        assert s2 == -1  # Duplicate rejected
        assert wal.current_seq == 1

    def test_allows_different_fingerprints(self, wal_dir):
        wal = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        s1 = wal.append(mk_payload("fp_unique_1"))
        s2 = wal.append(mk_payload("fp_unique_2"))
        assert s1 == 1
        assert s2 == 2

    def test_is_duplicate(self, wal_dir):
        wal = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        wal.append(mk_payload("fp_check"))
        assert wal.is_duplicate("fp_check") is True
        assert wal.is_duplicate("fp_unseen") is False

    def test_replay_set_populated_on_startup(self, wal_dir):
        wal = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        wal.append(mk_payload("fp_startup_1"))
        wal.append(mk_payload("fp_startup_2"))

        # Restart
        wal2 = WriteAheadLog("test_tenant", wal_dir=wal_dir)
        assert wal2.is_duplicate("fp_startup_1") is True
        assert wal2.is_duplicate("fp_startup_2") is True
        assert wal2.is_duplicate("fp_new") is False

    def test_evicts_oldest_when_window_exceeded(self, wal_dir):
        wal = WriteAheadLog("test_evict", wal_dir=wal_dir, replay_window=3)
        wal.append(mk_payload("fp_evict_1"))
        wal.append(mk_payload("fp_evict_2"))
        wal.append(mk_payload("fp_evict_3"))
        assert wal.replay_set_size == 3

        wal.append(mk_payload("fp_evict_4"))  # Evicts fp_evict_1
        assert wal.replay_set_size == 3
        assert wal.is_duplicate("fp_evict_1") is False  # Evicted
        assert wal.is_duplicate("fp_evict_4") is True

    def test_can_disable_replay_protection(self, wal_dir):
        wal = WriteAheadLog("test_norep", wal_dir=wal_dir, replay_protection=False)
        s1 = wal.append(mk_payload("fp_norep"))
        s2 = wal.append(mk_payload("fp_norep"))
        assert s1 == 1
        assert s2 == 2  # Not rejected
        assert wal.is_duplicate("fp_norep") is False


class TestWALEdgeCases:
    def test_empty_wal(self, wal_dir):
        wal = WriteAheadLog("test_empty", wal_dir=wal_dir)
        assert wal.current_seq == 0
        assert wal.recover() == []

    def test_survives_corrupted_lines(self, wal_dir):
        wal = WriteAheadLog("test_corrupt", wal_dir=wal_dir)
        wal.append(mk_payload("fp_ok"))

        # Inject corruption
        wal_file = os.path.join(wal_dir, "test_corrupt.wal")
        with open(wal_file, "a") as f:
            f.write("this is not json\n")

        wal.append(mk_payload("fp_after_corrupt"))

        # New WAL should skip corrupted line
        wal2 = WriteAheadLog("test_corrupt", wal_dir=wal_dir)
        assert wal2.current_seq == 2

    def test_tenant_isolation(self, wal_dir):
        wal_a = WriteAheadLog("tenant_a", wal_dir=wal_dir)
        wal_b = WriteAheadLog("tenant_b", wal_dir=wal_dir)
        wal_a.append(mk_payload("fp_a"))
        wal_b.append(mk_payload("fp_b"))
        assert wal_a.is_duplicate("fp_b") is False
        assert wal_b.is_duplicate("fp_a") is False

    def test_destroy_removes_files(self, wal_dir):
        wal = WriteAheadLog("test_destroy", wal_dir=wal_dir)
        wal.append(mk_payload("fp_destroy"))
        wal.mark_flushed(1)
        wal.destroy()
        assert not os.path.exists(os.path.join(wal_dir, "test_destroy.wal"))
        assert not os.path.exists(os.path.join(wal_dir, "test_destroy.ckpt"))

    def test_recovered_payloads_have_all_fields(self, wal_dir):
        wal = WriteAheadLog("test_fields", wal_dir=wal_dir)
        payload = mk_payload("fp_fields", proc="AI-MDL.1")
        wal.append(payload)

        wal2 = WriteAheadLog("test_fields", wal_dir=wal_dir)
        recovered = wal2.recover()
        assert len(recovered) == 1
        r = recovered[0]
        assert r.procedure_id == "AI-MDL.1"
        assert r.factor_a == 1.0
        assert r.factor_b == 0.9
        assert r.factor_c == 0.8
        assert r.clearing_level == 1
        assert r.anchor_fingerprint == "fp_fields"
        assert r.ai_model_id == "gpt-4o"
