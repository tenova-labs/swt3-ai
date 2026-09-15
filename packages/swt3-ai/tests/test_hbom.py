"""Tests for HBOM (Hardware Bill of Materials) governance witness methods."""
from unittest.mock import MagicMock
from swt3_ai.witness import (
    Witness, HBOM_LIFECYCLE_EVENT_CODES, HBOM_WATER_SOURCE_CODES,
)


def _make_witness(clearing_level=1, **kwargs):
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="test_tenant", clearing_level=clearing_level, **kwargs)
    w._buffer = MagicMock()
    return w


class TestWitnessHardwareInventory:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_hardware_inventory(42, "a1b2c3d4e5f60011" * 2, 3)
        assert p.procedure_id == "HBOM-INV.1"
        assert p.factor_a == 42.0
        assert p.factor_c == 3.0
        assert len(p.anchor_fingerprint) == 12

    def test_context_at_clearing_level_1(self):
        w = _make_witness()
        p = w.witness_hardware_inventory(10, "abcdef0123456789", 0)
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "hbom-governance"
        assert p.ai_context["component_count"] == 10

    def test_context_stripped_at_clearing_level_3(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_hardware_inventory(10, "abcdef0123456789")
        assert p.ai_context is None


class TestWitnessComponentLifecycle:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_component_lifecycle("installed", "GPU-A100-SN123", 0)
        assert p.procedure_id == "HBOM-LIFE.1"
        assert p.factor_a == 1.0

    def test_maps_all_event_types(self):
        w = _make_witness()
        for event, code in HBOM_LIFECYCLE_EVENT_CODES.items():
            p = w.witness_component_lifecycle(event, "comp-1")
            assert p.factor_a == float(code)

    def test_age_days_recorded(self):
        w = _make_witness()
        p = w.witness_component_lifecycle("maintained", "comp-1", 365)
        assert p.factor_c == 365.0


class TestWitnessThermalProfile:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_thermal_profile(22.5, 65.3, False)
        assert p.procedure_id == "HBOM-THERM.1"
        assert p.factor_a == 22.5
        assert p.factor_b == 65.3
        assert p.factor_c == 0.0

    def test_threshold_exceeded(self):
        w = _make_witness()
        p = w.witness_thermal_profile(25.0, 85.0, True)
        assert p.factor_c == 1.0

    def test_context_includes_temps(self):
        w = _make_witness()
        p = w.witness_thermal_profile(20.0, 60.0)
        assert p.ai_context["ambient_temp_c"] == 20.0
        assert p.ai_context["component_temp_c"] == 60.0


class TestWitnessWaterConsumption:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_water_consumption(5000.0, 1200, "recycled")
        assert p.procedure_id == "HBOM-WATER.1"
        assert p.factor_a == 5000.0
        assert p.factor_b == 1200.0
        assert p.factor_c == 2.0

    def test_maps_all_source_types(self):
        w = _make_witness()
        for source, code in HBOM_WATER_SOURCE_CODES.items():
            p = w.witness_water_consumption(100, 800, source)
            assert p.factor_c == float(code)


class TestWitnessPowerUsage:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_power_usage(1000.0, 800.0, 1250)
        assert p.procedure_id == "HBOM-PUE.1"
        assert p.factor_a == 1000.0
        assert p.factor_b == 800.0
        assert p.factor_c == 1250.0

    def test_context_includes_pue(self):
        w = _make_witness()
        p = w.witness_power_usage(500, 400, 1250)
        assert p.ai_context["pue_x1000"] == 1250


class TestWitnessSupplyChainProvenance:
    def test_mints_correct_procedure(self):
        w = _make_witness()
        p = w.witness_supply_chain_provenance("Intel Corp", True, "US")
        assert p.procedure_id == "HBOM-SUPPLY.1"
        assert p.factor_b == 1.0

    def test_unverified_provenance(self):
        w = _make_witness()
        p = w.witness_supply_chain_provenance("Unknown Supplier", False, "CN")
        assert p.factor_b == 0.0

    def test_deterministic_hashing(self):
        w = _make_witness()
        p1 = w.witness_supply_chain_provenance("Intel", True, "US")
        p2 = w.witness_supply_chain_provenance("Intel", True, "US")
        assert p1.factor_a == p2.factor_a
        assert p1.factor_c == p2.factor_c
