"""Tests for AI-ENG.1-6 physical AI / LEM witness methods."""

import hashlib
import json
import os
import unittest
from unittest.mock import MagicMock
from swt3_ai.witness import (
    Witness, DESIGN_DOMAIN_CODES, SIMULATION_TYPE_CODES,
    APPROVAL_TYPE_CODES, MATERIAL_STANDARD_CODES, CHAIN_STATUS_CODES,
    RELEASE_TYPE_CODES,
)


def _w(clearing_level=1) -> Witness:
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="TEST", clearing_level=clearing_level)
    w._buffer = MagicMock()
    return w


class TestDesignProvenance(unittest.TestCase):
    def test_mints_correct_procedure_and_factors(self):
        w = _w()
        p = w.witness_design_provenance(12, 500, "mechanical")
        assert p.procedure_id == "AI-ENG.1"
        assert p.factor_a == 12
        assert p.factor_b == 500
        assert p.factor_c == DESIGN_DOMAIN_CODES["mechanical"]

    def test_maps_all_domain_codes(self):
        w = _w()
        for code_name, code_value in DESIGN_DOMAIN_CODES.items():
            p = w.witness_design_provenance(1, 1, code_name)
            assert p.factor_c == code_value

    def test_unknown_domain_defaults_to_custom(self):
        w = _w()
        p = w.witness_design_provenance(1, 1, "unknown_xyz")
        assert p.factor_c == 7

    def test_includes_context_at_clearing_level_1(self):
        w = _w()
        p = w.witness_design_provenance(5, 100, "semiconductor", design_hash="abc123")
        assert p.ai_context is not None
        assert p.ai_context["design_domain"] == "semiconductor"
        assert p.ai_context["design_hash"] == "abc123"

    def test_strips_context_at_clearing_level_2(self):
        w = _w(clearing_level=2)
        p = w.witness_design_provenance(5, 100, "mechanical")
        assert p.ai_context is None

    def test_mints_valid_fingerprint(self):
        w = _w()
        p = w.witness_design_provenance(1, 1, "mechanical")
        assert len(p.anchor_fingerprint) == 12
        assert all(c in "0123456789abcdef" for c in p.anchor_fingerprint)


class TestSimulationValidation(unittest.TestCase):
    def test_mints_correct_procedure_and_factors(self):
        w = _w()
        p = w.witness_simulation_validation(1000, 998, "fea")
        assert p.procedure_id == "AI-ENG.2"
        assert p.factor_a == 1000
        assert p.factor_b == 998
        assert p.factor_c == SIMULATION_TYPE_CODES["fea"]

    def test_maps_all_simulation_types(self):
        w = _w()
        for code_name, code_value in SIMULATION_TYPE_CODES.items():
            p = w.witness_simulation_validation(1, 1, code_name)
            assert p.factor_c == code_value

    def test_unknown_type_defaults_to_custom(self):
        w = _w()
        p = w.witness_simulation_validation(1, 1, "unknown_sim")
        assert p.factor_c == 6

    def test_includes_context(self):
        w = _w()
        p = w.witness_simulation_validation(50, 48, "cfd", acceptance_criteria="drag < 0.3")
        assert p.ai_context["simulation_type"] == "cfd"
        assert p.ai_context["acceptance_criteria"] == "drag < 0.3"


class TestSafetyReview(unittest.TestCase):
    def test_mints_correct_procedure_and_factors(self):
        w = _w()
        p = w.witness_safety_review(3, 3, "pe_stamp")
        assert p.procedure_id == "AI-ENG.3"
        assert p.factor_a == 3
        assert p.factor_b == 3
        assert p.factor_c == APPROVAL_TYPE_CODES["pe_stamp"]

    def test_maps_all_approval_types(self):
        w = _w()
        for code_name, code_value in APPROVAL_TYPE_CODES.items():
            p = w.witness_safety_review(1, 1, code_name)
            assert p.factor_c == code_value

    def test_pe_license_in_context(self):
        w = _w()
        p = w.witness_safety_review(1, 1, "pe_stamp", pe_license="PE-12345-TX")
        assert p.ai_context["pe_license"] == "PE-12345-TX"


class TestMaterialCompliance(unittest.TestCase):
    def test_mints_correct_procedure_and_factors(self):
        w = _w()
        p = w.witness_material_compliance(15, 15, "asme")
        assert p.procedure_id == "AI-ENG.4"
        assert p.factor_a == 15
        assert p.factor_b == 15
        assert p.factor_c == MATERIAL_STANDARD_CODES["asme"]

    def test_maps_all_standard_codes(self):
        w = _w()
        for code_name, code_value in MATERIAL_STANDARD_CODES.items():
            p = w.witness_material_compliance(1, 1, code_name)
            assert p.factor_c == code_value

    def test_unknown_standard_defaults_to_custom(self):
        w = _w()
        p = w.witness_material_compliance(1, 1, "unknown_std")
        assert p.factor_c == 6


class TestDesignChain(unittest.TestCase):
    def test_mints_correct_procedure_and_factors(self):
        w = _w()
        p = w.witness_design_chain(10, 7, "approved")
        assert p.procedure_id == "AI-ENG.5"
        assert p.factor_a == 10
        assert p.factor_b == 7
        assert p.factor_c == CHAIN_STATUS_CODES["approved"]

    def test_maps_all_chain_statuses(self):
        w = _w()
        for code_name, code_value in CHAIN_STATUS_CODES.items():
            p = w.witness_design_chain(1, 1, code_name)
            assert p.factor_c == code_value

    def test_ai_revision_ratio_in_context(self):
        w = _w()
        p = w.witness_design_chain(10, 7, "approved")
        assert p.ai_context["ai_revision_ratio"] == 0.7

    def test_zero_revisions_no_divide_by_zero(self):
        w = _w()
        p = w.witness_design_chain(0, 0, "in_progress")
        assert p.ai_context["ai_revision_ratio"] == 0.0

    def test_strips_context_at_clearing_level_2(self):
        w = _w(clearing_level=2)
        p = w.witness_design_chain(5, 3, "approved")
        assert p.ai_context is None


class TestFabricationRelease(unittest.TestCase):
    def test_mints_correct_procedure_and_factors(self):
        w = _w()
        p = w.witness_fabrication_release(True, 5, "mass_production")
        assert p.procedure_id == "AI-ENG.6"
        assert p.factor_a == 1
        assert p.factor_b == 5
        assert p.factor_c == RELEASE_TYPE_CODES["mass_production"]

    def test_hash_mismatch_sets_factor_a_zero(self):
        w = _w()
        p = w.witness_fabrication_release(False, 3, "prototype")
        assert p.factor_a == 0

    def test_maps_all_release_types(self):
        w = _w()
        for code_name, code_value in RELEASE_TYPE_CODES.items():
            p = w.witness_fabrication_release(True, 1, code_name)
            assert p.factor_c == code_value

    def test_includes_context(self):
        w = _w()
        p = w.witness_fabrication_release(True, 3, "mass_production", production_system_id="FAB-001", approved_design_hash="abc123")
        assert p.ai_context["production_system_id"] == "FAB-001"
        assert p.ai_context["approved_design_hash"] == "abc123"
        assert p.ai_context["design_hash_verified"] is True

    def test_strips_context_at_clearing_level_2(self):
        w = _w(clearing_level=2)
        p = w.witness_fabrication_release(True, 1, "prototype")
        assert p.ai_context is None


class TestEngVectors(unittest.TestCase):
    def test_fingerprint_vectors_match(self):
        vec_path = os.path.join(os.path.dirname(__file__), "..", "test-vectors.json")
        with open(vec_path) as f:
            tv = json.load(f)
        eng_vectors = [v for v in tv["fingerprint_vectors"] if v["procedure_id"].startswith("AI-ENG")]
        assert len(eng_vectors) == 6, f"Expected 6 AI-ENG vectors, got {len(eng_vectors)}"
        for v in eng_vectors:
            raw = f"WITNESS:{v['tenant_id']}:{v['procedure_id']}:{v['factor_a']}:{v['factor_b']}:{v['factor_c']}:{v['fingerprint_timestamp_ms']}"
            computed = hashlib.sha256(raw.encode()).hexdigest()[:12]
            assert computed == v["expected_fingerprint"], f"{v['procedure_id']}: expected {v['expected_fingerprint']}, got {computed}"
