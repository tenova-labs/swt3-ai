"""Tests for ADR (Automated Demand Response) governance witness methods."""
from unittest.mock import MagicMock
from swt3_ai.witness import (
    Witness, ADR_EVENT_PHASE_CODES, ADR_BASELINE_METHOD_CODES,
    ADR_CREDIT_TYPE_CODES, ADR_SIGNAL_TYPE_CODES,
)


def _make_witness(clearing_level=1, **kwargs):
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="test_tenant", clearing_level=clearing_level, **kwargs)
    w._buffer = MagicMock()
    return w


class TestWitnessDemandResponse:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_demand_response("signal_received", 500.0, "PJM-ISO")
        assert p.procedure_id == "ADR-EVENT.1"
        assert p.factor_a == 1.0
        assert p.factor_b == 500.0
        assert len(p.anchor_fingerprint) == 12

    def test_maps_all_event_phases(self):
        w = _make_witness()
        for phase, code in ADR_EVENT_PHASE_CODES.items():
            p = w.witness_demand_response(phase, 100.0, "grid-op")
            assert p.factor_a == float(code)

    def test_context_includes_signal_hash(self):
        w = _make_witness()
        p = w.witness_demand_response("signal_received", 500.0, "PJM")
        assert "signal_source_hash" in p.ai_context

    def test_context_stripped_at_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_demand_response("signal_received", 500.0, "PJM")
        assert p.ai_context is None


class TestWitnessBaselineConsumption:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_baseline_consumption(2500.0, "metered_10day_avg", 950)
        assert p.procedure_id == "ADR-BASE.1"
        assert p.factor_a == 2500.0
        assert p.factor_b == 1.0
        assert p.factor_c == 950.0

    def test_maps_all_methods(self):
        w = _make_witness()
        for method, code in ADR_BASELINE_METHOD_CODES.items():
            p = w.witness_baseline_consumption(1000.0, method)
            assert p.factor_b == float(code)

    def test_default_confidence(self):
        w = _make_witness()
        p = w.witness_baseline_consumption(1000.0, "regression")
        assert p.factor_c == 950.0


class TestWitnessCurtailment:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_curtailment(480.0, 500.0, 960)
        assert p.procedure_id == "ADR-CURT.1"
        assert p.factor_a == 480.0
        assert p.factor_b == 500.0
        assert p.factor_c == 960.0

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_curtailment(100, 100, 1000)
        assert p.ai_context["compliance_ratio_x1000"] == 1000


class TestWitnessSettlement:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_settlement(125.5, 45.0, 3)
        assert p.procedure_id == "ADR-SETTLE.1"
        assert p.factor_a == 12550.0
        assert p.factor_b == 4500.0
        assert p.factor_c == 3.0

    def test_context_includes_event_count(self):
        w = _make_witness()
        p = w.witness_settlement(100.0, 50.0, 5)
        assert p.ai_context["event_count"] == 5


class TestWitnessCarbonCredit:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_carbon_credit("rec", 500.0, "M-RETS")
        assert p.procedure_id == "ADR-CARBON.1"
        assert p.factor_a == 1.0
        assert p.factor_b == 50000.0

    def test_maps_all_credit_types(self):
        w = _make_witness()
        for ctype, code in ADR_CREDIT_TYPE_CODES.items():
            p = w.witness_carbon_credit(ctype, 100.0, "registry")
            assert p.factor_a == float(code)

    def test_context_includes_registry_hash(self):
        w = _make_witness()
        p = w.witness_carbon_credit("rec", 100.0, "PJM-GATS")
        assert "registry_hash" in p.ai_context


class TestWitnessGridSignal:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_grid_signal("emergency", 250, "ERCOT")
        assert p.procedure_id == "ADR-GRID.1"
        assert p.factor_a == 1.0
        assert p.factor_b == 250.0

    def test_maps_all_signal_types(self):
        w = _make_witness()
        for stype, code in ADR_SIGNAL_TYPE_CODES.items():
            p = w.witness_grid_signal(stype, 100, "operator")
            assert p.factor_a == float(code)

    def test_context_includes_operator_hash(self):
        w = _make_witness()
        p = w.witness_grid_signal("economic", 500, "CAISO")
        assert "grid_operator_hash" in p.ai_context

    def test_propagates_agent_id(self):
        w = _make_witness(agent_id="grid-agent")
        p = w.witness_grid_signal("capacity", 100, "PJM")
        assert p.agent_id == "grid-agent"
