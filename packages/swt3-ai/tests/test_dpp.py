"""Tests for DPP (Digital Product Passport) governance witness methods."""
from unittest.mock import MagicMock
from swt3_ai.witness import (
    Witness, DPP_CHARGE_EVENT_CODES, DPP_DEGRADATION_TYPE_CODES,
    DPP_DISPOSITION_CODES,
)


def _make_witness(clearing_level=1, **kwargs):
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="test_tenant", clearing_level=clearing_level, **kwargs)
    w._buffer = MagicMock()
    return w


class TestWitnessBatterySoh:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_battery_soh(92.3, 450, 48.5)
        assert p.procedure_id == "DPP-SOH.1"
        assert p.factor_a == 9230.0
        assert p.factor_b == 450.0
        assert p.factor_c == 4850.0
        assert len(p.anchor_fingerprint) == 12

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_battery_soh(95.0, 100, 50.0)
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "dpp-governance"
        assert p.ai_context["soh_percent"] == 95.0
        assert p.ai_context["cycle_count"] == 100

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_battery_soh(80.0, 1000, 40.0)
        assert p.ai_context is None


class TestWitnessChargeCycle:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_charge_cycle("charge_start", 12.5, 28.0)
        assert p.procedure_id == "DPP-CHRG.1"
        assert p.factor_a == 1.0
        assert p.factor_b == 1250.0
        assert p.factor_c == 28.0

    def test_maps_all_event_types(self):
        w = _make_witness()
        for event, code in DPP_CHARGE_EVENT_CODES.items():
            p = w.witness_charge_cycle(event, 10.0, 25.0)
            assert p.factor_a == float(code)

    def test_unknown_event_defaults_zero(self):
        w = _make_witness()
        p = w.witness_charge_cycle("unknown", 10.0, 25.0)
        assert p.factor_a == 0.0


class TestWitnessDegradationEvent:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_degradation_event("thermal_stress", 0.5, 42.0)
        assert p.procedure_id == "DPP-DEGRAD.1"
        assert p.factor_a == 2.0
        assert p.factor_b == 50.0
        assert p.factor_c == 42.0

    def test_maps_all_degradation_types(self):
        w = _make_witness()
        for dtype, code in DPP_DEGRADATION_TYPE_CODES.items():
            p = w.witness_degradation_event(dtype, 1.0, 25.0)
            assert p.factor_a == float(code)


class TestWitnessEndOfLife:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_end_of_life("recycling", "GreenRecycle LLC", 45.0)
        assert p.procedure_id == "DPP-EOL.1"
        assert p.factor_a == 1.0
        assert p.factor_c == 4500.0

    def test_maps_all_disposition_types(self):
        w = _make_witness()
        for dtype, code in DPP_DISPOSITION_CODES.items():
            p = w.witness_end_of_life(dtype, "handler", 50.0)
            assert p.factor_a == float(code)

    def test_context_includes_handler_hash(self):
        w = _make_witness()
        p = w.witness_end_of_life("recycling", "handler-123", 30.0)
        assert "handler_hash" in p.ai_context

    def test_propagates_agent_id(self):
        w = _make_witness(agent_id="battery-agent")
        p = w.witness_end_of_life("recycling", "handler", 50.0)
        assert p.agent_id == "battery-agent"
