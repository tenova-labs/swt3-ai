"""Tests for the crosswalk resolver module."""

import pytest
from swt3_ai.crosswalk import (
    resolve,
    resolve_framework,
    frameworks,
    procedures,
    crosswalk_version,
)


class TestResolve:
    def test_known_procedure(self):
        result = resolve("AI-FAIR.1")
        assert isinstance(result, dict)
        assert len(result) > 0
        assert "EU-AI-ACT" in result

    def test_unknown_procedure(self):
        result = resolve("FAKE-PROC.99")
        assert result == {}

    def test_returns_copy(self):
        r1 = resolve("AI-FAIR.1")
        r1["INJECTED"] = "bad"
        r2 = resolve("AI-FAIR.1")
        assert "INJECTED" not in r2

    def test_all_values_are_strings(self):
        result = resolve("AI-FAIR.1")
        for fw, ref in result.items():
            assert isinstance(fw, str)
            assert isinstance(ref, str)

    def test_multiple_procedures(self):
        for proc_id in ["AI-INF.1", "AI-GOV.1", "AI-TRANS.1"]:
            result = resolve(proc_id)
            assert isinstance(result, dict)
            assert len(result) > 0, f"{proc_id} should map to at least one framework"


class TestResolveFramework:
    def test_known_framework(self):
        result = resolve_framework("EU-AI-ACT")
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_unknown_framework(self):
        result = resolve_framework("FAKE-FRAMEWORK")
        assert result == {}

    def test_values_are_lists(self):
        result = resolve_framework("EU-AI-ACT")
        for ref, procs in result.items():
            assert isinstance(procs, list)
            assert all(isinstance(p, str) for p in procs)

    def test_returns_copy(self):
        r1 = resolve_framework("EU-AI-ACT")
        first_key = next(iter(r1))
        r1[first_key].append("INJECTED")
        r2 = resolve_framework("EU-AI-ACT")
        assert "INJECTED" not in r2[first_key]


class TestMetadata:
    def test_frameworks_returns_dict(self):
        result = frameworks()
        assert isinstance(result, dict)
        assert len(result) > 10

    def test_procedures_returns_dict(self):
        result = procedures()
        assert isinstance(result, dict)
        assert len(result) > 50

    def test_crosswalk_version_is_timestamp(self):
        v = crosswalk_version()
        assert isinstance(v, str)
        assert "T" in v  # ISO timestamp


class TestBufferTracking:
    def test_witnessed_procedures_tracked(self):
        from swt3_ai.buffer import WitnessBuffer
        from swt3_ai.types import WitnessConfig, WitnessPayload

        config = WitnessConfig(
            endpoint="http://localhost:9999",
            api_key="axm_test",
            clearing_level=0,
            buffer_size=100,
            flush_interval=300,
        )
        buf = WitnessBuffer(config)
        assert len(buf.witnessed_procedures) == 0

        payload = WitnessPayload(
            procedure_id="AI-INF.1", factor_a="a", factor_b="b", factor_c="c",
            clearing_level=0, anchor_fingerprint="abc", anchor_epoch=0, fingerprint_timestamp_ms=0,
        )
        buf.enqueue(payload)
        assert "AI-INF.1" in buf.witnessed_procedures

        payload2 = WitnessPayload(
            procedure_id="AI-FAIR.1", factor_a="a", factor_b="b", factor_c="c",
            clearing_level=0, anchor_fingerprint="def", anchor_epoch=0, fingerprint_timestamp_ms=0,
        )
        buf.enqueue(payload2)
        assert len(buf.witnessed_procedures) == 2
        buf.stop()
