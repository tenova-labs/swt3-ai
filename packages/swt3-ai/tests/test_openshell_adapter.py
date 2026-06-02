"""Tests for the NVIDIA OpenShell OCSF event consumer adapter."""

import time
from unittest.mock import MagicMock, patch

import pytest

from swt3_ai.adapters.openshell import (
    OCSF_TO_PROCEDURE,
    OpenShellWitness,
    _get_procedure,
    _sha256_truncated,
)


# ── Sample OCSF Events ────────────────────────────────────────────────

def make_network_event(disposition="allow", hostname="api.openai.com"):
    return {
        "class_name": "network_activity",
        "disposition": disposition,
        "activity_name": "connect",
        "time": int(time.time() * 1000),
        "duration": 150,
        "dst_endpoint": {"hostname": hostname, "ip": "104.18.7.42", "port": 443},
        "request_uid": "req-12345",
        "response_uid": "resp-67890",
    }


def make_process_event(disposition="launch", name="python3"):
    return {
        "class_name": "process_activity",
        "disposition": disposition,
        "activity_name": disposition,
        "time": int(time.time() * 1000),
        "duration": 0,
        "process": {"name": name, "pid": 1234},
    }


def make_tool_event(tool_name="web_search"):
    return {
        "class_name": "process_activity",
        "disposition": "tool_call",
        "activity_name": "tool_call",
        "time": int(time.time() * 1000),
        "duration": 320,
        "process": {"name": tool_name, "pid": 5678},
    }


def make_file_event(disposition="allow", path="/data/training.csv"):
    return {
        "class_name": "file_activity",
        "disposition": disposition,
        "activity_name": "read",
        "time": int(time.time() * 1000),
        "duration": 5,
        "file": {"path": path, "size": 1024},
    }


def make_config_event():
    return {
        "class_name": "configuration_change",
        "disposition": "update",
        "activity_name": "policy_update",
        "time": int(time.time() * 1000),
        "duration": 0,
    }


def make_guardrail_event(disposition="guardrail_allow"):
    return {
        "class_name": "security_finding",
        "disposition": disposition,
        "activity_name": "guardrail_check",
        "time": int(time.time() * 1000),
        "duration": 12,
    }


def make_unknown_event():
    return {
        "class_name": "unknown_class_2027",
        "disposition": "something",
        "activity_name": "future_event",
        "time": int(time.time() * 1000),
    }


# ── Procedure Mapping Tests ───────────────────────────────────────────

class TestProcedureMapping:
    def test_network_allow_maps_to_inference(self):
        event = make_network_event("allow")
        assert _get_procedure(event) == "AI-INF.1"

    def test_network_deny_maps_to_security(self):
        event = make_network_event("deny")
        assert _get_procedure(event) == "AI-SEC.1"

    def test_network_route_maps_to_access(self):
        event = make_network_event("route")
        assert _get_procedure(event) == "AI-ACC.1"

    def test_process_launch_maps_to_identity(self):
        event = make_process_event("launch")
        assert _get_procedure(event) == "AI-ID.1"

    def test_process_terminate_maps_to_identity(self):
        event = make_process_event("terminate")
        assert _get_procedure(event) == "AI-ID.1"

    def test_tool_call_maps_to_tool(self):
        event = make_tool_event()
        assert _get_procedure(event) == "AI-TOOL.1"

    def test_file_allow_maps_to_data(self):
        event = make_file_event("allow")
        assert _get_procedure(event) == "AI-DATA.1"

    def test_file_deny_maps_to_security(self):
        event = make_file_event("deny")
        assert _get_procedure(event) == "AI-SEC.1"

    def test_config_change_maps_to_drift(self):
        event = make_config_event()
        assert _get_procedure(event) == "AI-MDL.2"

    def test_guardrail_allow_maps_to_guardrail(self):
        event = make_guardrail_event("guardrail_allow")
        assert _get_procedure(event) == "AI-GRD.1"

    def test_guardrail_deny_maps_to_guardrail(self):
        event = make_guardrail_event("guardrail_deny")
        assert _get_procedure(event) == "AI-GRD.1"

    def test_unknown_event_returns_none(self):
        event = make_unknown_event()
        assert _get_procedure(event) is None

    def test_integer_disposition_allowed(self):
        event = {"class_name": "network_activity", "disposition": 1}
        assert _get_procedure(event) == "AI-INF.1"

    def test_integer_disposition_denied(self):
        event = {"class_name": "network_activity", "disposition": 2}
        assert _get_procedure(event) == "AI-SEC.1"

    def test_integer_disposition_routed(self):
        event = {"class_name": "network_activity", "disposition": 6}
        assert _get_procedure(event) == "AI-ACC.1"

    def test_missing_class_name_returns_none(self):
        event = {"disposition": "allow"}
        assert _get_procedure(event) is None


# ── OpenShellWitness Tests ────────────────────────────────────────────

class TestOpenShellWitness:
    def _make_witness(self):
        """Create OpenShellWitness with a mock Witness."""
        mock_witness = MagicMock()
        osw = OpenShellWitness(witness=mock_witness)
        return osw, mock_witness

    def test_is_configured_with_witness(self):
        osw, _ = self._make_witness()
        assert osw.is_configured is True

    def test_not_configured_without_env(self):
        with patch.dict("os.environ", {}, clear=True):
            osw = OpenShellWitness()
            assert osw.is_configured is False

    def test_process_event_returns_procedure(self):
        osw, mock = self._make_witness()
        result = osw.process_event(make_network_event("allow"))
        assert result == "AI-INF.1"
        mock.record.assert_called_once()

    def test_process_event_skips_unknown(self):
        osw, mock = self._make_witness()
        result = osw.process_event(make_unknown_event())
        assert result is None
        mock.record.assert_not_called()

    def test_process_event_noop_when_unconfigured(self):
        with patch.dict("os.environ", {}, clear=True):
            osw = OpenShellWitness()
            result = osw.process_event(make_network_event())
            assert result is None

    def test_stats_tracking(self):
        osw, _ = self._make_witness()
        osw.process_event(make_network_event())
        osw.process_event(make_network_event())
        osw.process_event(make_unknown_event())
        assert osw.stats == {"processed": 2, "skipped": 1}

    def test_network_event_extracts_hostname_as_model(self):
        osw, mock = self._make_witness()
        osw.process_event(make_network_event("allow", "nim.internal.corp"))
        record = mock.record.call_args[0][0]
        assert record.model_id == "nim.internal.corp"

    def test_tool_event_sets_tool_name(self):
        osw, mock = self._make_witness()
        osw.process_event(make_tool_event("code_interpreter"))
        record = mock.record.call_args[0][0]
        assert record.tool_name == "code_interpreter"

    def test_file_event_sets_access_target(self):
        osw, mock = self._make_witness()
        osw.process_event(make_file_event("allow", "/secrets/key.pem"))
        record = mock.record.call_args[0][0]
        assert record.access_target == "/secrets/key.pem"
        assert record.access_granted is True

    def test_denied_event_sets_access_denied(self):
        osw, mock = self._make_witness()
        osw.process_event(make_file_event("deny", "/etc/shadow"))
        record = mock.record.call_args[0][0]
        assert record.access_target == "/etc/shadow"
        assert record.access_granted is False

    def test_provider_is_nvidia_openshell(self):
        osw, mock = self._make_witness()
        osw.process_event(make_network_event())
        record = mock.record.call_args[0][0]
        assert record.provider == "nvidia-openshell"

    def test_procedure_override_passed_to_record(self):
        osw, mock = self._make_witness()
        osw.process_event(make_network_event("deny"))
        _, kwargs = mock.record.call_args
        assert kwargs["procedures"] == ["AI-SEC.1"]

    def test_duration_maps_to_latency(self):
        osw, mock = self._make_witness()
        event = make_network_event()
        event["duration"] = 450
        osw.process_event(event)
        record = mock.record.call_args[0][0]
        assert record.latency_ms == 450

    def test_denied_network_sets_has_refusal(self):
        osw, mock = self._make_witness()
        osw.process_event(make_network_event("deny"))
        record = mock.record.call_args[0][0]
        assert record.has_refusal is True

    def test_guardrail_deny_sets_guardrail_failed(self):
        osw, mock = self._make_witness()
        osw.process_event(make_guardrail_event("guardrail_deny"))
        record = mock.record.call_args[0][0]
        assert record.guardrail_passed is False

    def test_guardrail_allow_sets_guardrail_passed(self):
        osw, mock = self._make_witness()
        osw.process_event(make_guardrail_event("guardrail_allow"))
        record = mock.record.call_args[0][0]
        assert record.guardrail_passed is True


# ── Hash Helper Tests ─────────────────────────────────────────────────

class TestHelpers:
    def test_sha256_truncated_deterministic(self):
        assert _sha256_truncated("hello") == _sha256_truncated("hello")

    def test_sha256_truncated_length(self):
        assert len(_sha256_truncated("test", 16)) == 16
        assert len(_sha256_truncated("test", 12)) == 12

    def test_sha256_truncated_different_inputs(self):
        assert _sha256_truncated("a") != _sha256_truncated("b")
