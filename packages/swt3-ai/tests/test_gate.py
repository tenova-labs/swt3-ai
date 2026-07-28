"""Tests for .swt3-gate.yml parser and init generator (v0.6.2)."""

import os
import tempfile
import pytest

from swt3_ai.gate import (
    GateConfig, GateProcedure, GateGroup, FrameworkGate, GateDefaults,
    load_gate_config, parse_gate_dict, parse_max_age, find_gate_file,
    validate_procedures, all_procedures,
    generate_gate_yaml, list_frameworks,
)


COMPLETE_YAML = {
    "version": "1.0",
    "name": "Test Gate",
    "strict": False,
    "metadata": {
        "generated_at": "2026-07-24T14:00:00Z",
        "crosswalk_version": "1.0.0",
        "baseline_hash": "e4f5a6b7c8d9",
    },
    "models": {
        "credit-v3": {"risk": "high"},
        "chatbot-v1": {"risk": "low"},
    },
    "defaults": {
        "gates": [
            {"procedure": "AI-LOG.1", "required": True, "description": "Logging"},
        ]
    },
    "frameworks": {
        "eu-ai-act": {
            "risk_class": "high-risk",
            "crosswalk_hash": "a3b7c9d2e1f4",
            "gates": [
                {
                    "group": "Article 10: Data Governance",
                    "procedures": [
                        {
                            "procedure": "AI-FAIR.1",
                            "max_age": "7d",
                            "required": True,
                            "ref": "Art. 10(2)(f)",
                            "critical": True,
                            "description": "Bias testing",
                            "hint": "witness.witness_bias_detection()",
                        },
                    ],
                },
                {
                    "group": "Article 14: Human Oversight",
                    "procedures": [
                        {
                            "procedure": "AI-HITL.1",
                            "max_age": "24h",
                            "required": True,
                            "ref": "Art. 14",
                            "critical": True,
                        },
                    ],
                },
            ],
        },
        "sr-11-7": {
            "gates": [
                {
                    "group": "Model Validation",
                    "procedures": [
                        {"procedure": "AI-FAIR.1", "max_age": "30d", "required": True},
                    ],
                },
            ],
        },
    },
}


class TestParseGateDict:
    def test_complete_config(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        assert cfg.version == "1.0"
        assert cfg.name == "Test Gate"
        assert cfg.strict is False
        assert len(cfg.models) == 2
        assert cfg.models["credit-v3"].risk == "high"
        assert cfg.defaults is not None
        assert len(cfg.defaults.gates) == 1
        assert cfg.defaults.gates[0].procedure == "AI-LOG.1"
        assert len(cfg.frameworks) == 2
        assert "eu-ai-act" in cfg.frameworks
        assert "sr-11-7" in cfg.frameworks

    def test_minimal_config(self):
        cfg = parse_gate_dict({"version": "1.0"})
        assert cfg.version == "1.0"
        assert cfg.name is None
        assert cfg.strict is False
        assert cfg.models == {}
        assert cfg.defaults is None
        assert cfg.frameworks == {}
        assert len(cfg.warnings) == 0

    def test_missing_version_raises(self):
        with pytest.raises(ValueError, match="version"):
            parse_gate_dict({"name": "no version"})

    def test_strict_flag(self):
        cfg = parse_gate_dict({"version": "1.0", "strict": True})
        assert cfg.strict is True

    def test_metadata_passthrough(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        assert cfg.metadata["crosswalk_version"] == "1.0.0"
        assert cfg.metadata["baseline_hash"] == "e4f5a6b7c8d9"


class TestFrameworkParsing:
    def test_grouped_gates(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        eu = cfg.frameworks["eu-ai-act"]
        assert eu.risk_class == "high-risk"
        assert eu.crosswalk_hash == "a3b7c9d2e1f4"
        assert len(eu.gates) == 2
        assert eu.gates[0].group == "Article 10: Data Governance"
        assert eu.gates[0].procedures[0].procedure == "AI-FAIR.1"
        assert eu.gates[0].procedures[0].critical is True

    def test_flat_gates_wrapped_in_group(self):
        """Flat procedure list (no group wrapper) should be wrapped in unnamed group."""
        cfg = parse_gate_dict({
            "version": "1.0",
            "frameworks": {
                "test-fw": {
                    "gates": [
                        {"procedure": "AI-INF.1", "required": True},
                        {"procedure": "AI-GRD.1", "required": False},
                    ]
                }
            }
        })
        fw = cfg.frameworks["test-fw"]
        assert len(fw.gates) == 1
        assert fw.gates[0].group == ""
        assert len(fw.gates[0].procedures) == 2
        assert fw.gates[0].procedures[0].procedure == "AI-INF.1"

    def test_empty_framework_warning(self):
        cfg = parse_gate_dict({
            "version": "1.0",
            "frameworks": {"empty-fw": {}}
        })
        assert any("empty-fw" in w and "no gates" in w for w in cfg.warnings)

    def test_multi_framework(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        assert "eu-ai-act" in cfg.frameworks
        assert "sr-11-7" in cfg.frameworks
        sr = cfg.frameworks["sr-11-7"]
        assert len(sr.gates) == 1
        assert sr.gates[0].procedures[0].max_age == "30d"


class TestProcedureParsing:
    def test_all_fields(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        fair = cfg.frameworks["eu-ai-act"].gates[0].procedures[0]
        assert fair.procedure == "AI-FAIR.1"
        assert fair.required is True
        assert fair.max_age == "7d"
        assert fair.max_age_seconds == 604800
        assert fair.ref == "Art. 10(2)(f)"
        assert fair.critical is True
        assert fair.description == "Bias testing"
        assert fair.hint == "witness.witness_bias_detection()"

    def test_must_not_exist(self):
        cfg = parse_gate_dict({
            "version": "1.0",
            "frameworks": {
                "test": {
                    "gates": [
                        {"procedure": "AI-REV.1", "must_not_exist": True}
                    ]
                }
            }
        })
        proc = cfg.frameworks["test"].gates[0].procedures[0]
        assert proc.must_not_exist is True

    def test_missing_procedure_field_skipped(self):
        """Flat gate entry without 'procedure' field is silently skipped."""
        cfg = parse_gate_dict({
            "version": "1.0",
            "frameworks": {
                "test": {
                    "gates": [
                        {"required": True},  # no procedure field -- skipped
                        {"procedure": "AI-INF.1", "required": True},  # valid
                    ]
                }
            }
        })
        fw = cfg.frameworks["test"]
        assert len(fw.gates) == 1
        assert len(fw.gates[0].procedures) == 1
        assert fw.gates[0].procedures[0].procedure == "AI-INF.1"


class TestMaxAge:
    def test_days(self):
        assert parse_max_age("7d") == 604800
        assert parse_max_age("1d") == 86400
        assert parse_max_age("30d") == 2592000
        assert parse_max_age("90d") == 7776000

    def test_hours(self):
        assert parse_max_age("24h") == 86400
        assert parse_max_age("1h") == 3600

    def test_minutes(self):
        assert parse_max_age("30m") == 1800

    def test_case_insensitive(self):
        assert parse_max_age("7D") == 604800
        assert parse_max_age("24H") == 86400

    def test_whitespace(self):
        assert parse_max_age(" 7d ") == 604800

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="Invalid max_age"):
            parse_max_age("7 days")

    def test_invalid_unit(self):
        with pytest.raises(ValueError, match="Invalid max_age"):
            parse_max_age("7w")

    def test_no_number(self):
        with pytest.raises(ValueError, match="Invalid max_age"):
            parse_max_age("d")


class TestUnknownFields:
    def test_unknown_top_level_key_warning(self):
        cfg = parse_gate_dict({
            "version": "1.0",
            "unknown_field": "value",
            "another_unknown": 42,
        })
        assert len(cfg.warnings) == 2
        assert any("unknown_field" in w for w in cfg.warnings)
        assert any("another_unknown" in w for w in cfg.warnings)

    def test_valid_keys_no_warnings(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        assert len(cfg.warnings) == 0


class TestValidateProcedures:
    def test_known_procedures_no_warnings(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        known = {"AI-LOG.1", "AI-FAIR.1", "AI-HITL.1"}
        warnings = validate_procedures(cfg, known)
        assert len(warnings) == 0

    def test_unknown_procedure_warning(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        known = {"AI-LOG.1"}  # AI-FAIR.1 and AI-HITL.1 missing
        warnings = validate_procedures(cfg, known)
        assert len(warnings) > 0
        assert any("AI-FAIR.1" in w for w in warnings)

    def test_validates_defaults_and_frameworks(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        known = set()  # nothing known
        warnings = validate_procedures(cfg, known)
        # Should flag defaults (AI-LOG.1) + frameworks (AI-FAIR.1, AI-HITL.1)
        assert len(warnings) >= 3


class TestAllProcedures:
    def test_extracts_all(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        procs = all_procedures(cfg)
        proc_ids = [p.procedure for _, p in procs]
        assert "AI-LOG.1" in proc_ids  # from defaults
        assert "AI-FAIR.1" in proc_ids  # from eu-ai-act
        assert "AI-HITL.1" in proc_ids  # from eu-ai-act

    def test_includes_framework_context(self):
        cfg = parse_gate_dict(COMPLETE_YAML)
        procs = all_procedures(cfg)
        contexts = {fw for fw, _ in procs}
        assert "defaults" in contexts
        assert "eu-ai-act" in contexts
        assert "sr-11-7" in contexts


class TestFileDiscovery:
    def test_explicit_path(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            f.write("version: '1.0'\n")
            f.flush()
            result = find_gate_file(f.name)
            assert result is not None
            os.unlink(f.name)

    def test_nonexistent_path(self):
        result = find_gate_file("/nonexistent/path.yml")
        assert result is None


class TestLoadGateConfig:
    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            f.write('version: "1.0"\nname: "From File"\nstrict: true\n')
            f.flush()
            cfg = load_gate_config(f.name)
            assert cfg.version == "1.0"
            assert cfg.name == "From File"
            assert cfg.strict is True
            assert cfg.source_path is not None
            os.unlink(f.name)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_gate_config("/nonexistent/gate.yml")


# ── Gate Init Generator Tests ──

class TestGenerateGateYaml:
    def test_eu_ai_act_generates_valid_yaml(self):
        """Generated EU-AI-ACT YAML should parse back as valid GateConfig."""
        import yaml
        output = generate_gate_yaml("EU-AI-ACT")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        assert cfg.version == "1.0"
        assert "EU" in cfg.name or "Artificial" in cfg.name
        assert "eu-ai-act" in cfg.frameworks
        eu = cfg.frameworks["eu-ai-act"]
        assert eu.risk_class == "high-risk"
        # EU-AI-ACT has many procedures
        total = sum(len(g.procedures) for g in eu.gates)
        assert total >= 50

    def test_sr_11_7_generates_valid_yaml(self):
        import yaml
        output = generate_gate_yaml("SR-11-7")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        assert "sr-11-7" in cfg.frameworks
        sr = cfg.frameworks["sr-11-7"]
        assert sr.risk_class == "model-risk"
        total = sum(len(g.procedures) for g in sr.gates)
        assert total >= 15

    def test_nist_ai_rmf(self):
        import yaml
        output = generate_gate_yaml("NIST-AI-RMF")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        assert "nist-ai-rmf" in cfg.frameworks

    def test_custom_name(self):
        import yaml
        output = generate_gate_yaml("SR-11-7", name="ACME Corp Model Risk")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        assert cfg.name == "ACME Corp Model Risk"

    def test_strict_mode(self):
        import yaml
        output = generate_gate_yaml("SR-11-7", strict=True)
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        assert cfg.strict is True

    def test_unknown_framework_raises(self):
        with pytest.raises(ValueError, match="Unknown framework"):
            generate_gate_yaml("NONEXISTENT-FW")

    def test_generated_yaml_has_groups(self):
        """Procedures should be organized into named groups."""
        import yaml
        output = generate_gate_yaml("EU-AI-ACT")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        eu = cfg.frameworks["eu-ai-act"]
        # Should have multiple article groups
        assert len(eu.gates) > 5
        # At least some should have article labels
        group_names = [g.group for g in eu.gates]
        assert any("Article" in g for g in group_names)

    def test_generated_procedures_have_refs(self):
        """Each procedure should have a ref back to the regulatory article."""
        import yaml
        output = generate_gate_yaml("EU-AI-ACT")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        eu = cfg.frameworks["eu-ai-act"]
        for group in eu.gates:
            for proc in group.procedures:
                assert proc.ref is not None, f"{proc.procedure} missing ref"

    def test_generated_procedures_have_hints(self):
        """Critical procedures should have SDK method hints."""
        import yaml
        output = generate_gate_yaml("EU-AI-ACT")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        eu = cfg.frameworks["eu-ai-act"]
        hints_found = 0
        for group in eu.gates:
            for proc in group.procedures:
                if proc.hint:
                    hints_found += 1
        assert hints_found > 20

    def test_defaults_included(self):
        """Generated YAML should have AI-LOG.1 and AI-AUDIT.1 defaults."""
        import yaml
        output = generate_gate_yaml("SR-11-7")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        assert cfg.defaults is not None
        procs = [g.procedure for g in cfg.defaults.gates]
        assert "AI-LOG.1" in procs
        assert "AI-AUDIT.1" in procs

    def test_critical_procedures_marked(self):
        """AI-FAIR.1, AI-HITL.1, etc. should be marked critical."""
        import yaml
        output = generate_gate_yaml("EU-AI-ACT")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        eu = cfg.frameworks["eu-ai-act"]
        critical_procs = set()
        for group in eu.gates:
            for proc in group.procedures:
                if proc.critical:
                    critical_procs.add(proc.procedure)
        assert "AI-FAIR.1" in critical_procs
        assert "AI-HITL.1" in critical_procs
        assert "AI-GRD.1" in critical_procs

    def test_metadata_present(self):
        import yaml
        output = generate_gate_yaml("EU-AI-ACT")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        assert cfg.metadata is not None
        assert "generated_at" in cfg.metadata
        assert "crosswalk_version" in cfg.metadata
        assert cfg.metadata["framework"] == "EU-AI-ACT"

    def test_roundtrip_validates_clean(self):
        """Generated YAML should validate with zero unknown-procedure warnings."""
        import yaml
        from swt3_ai.crosswalk import procedures as cw_procs
        output = generate_gate_yaml("EU-AI-ACT")
        raw = yaml.safe_load(output)
        cfg = parse_gate_dict(raw)
        known = set(cw_procs().keys())
        warnings = validate_procedures(cfg, known)
        assert len(warnings) == 0, f"Unknown procedures: {warnings}"


class TestListFrameworks:
    def test_returns_frameworks(self):
        fws = list_frameworks()
        assert len(fws) >= 10
        ids = [f[0] for f in fws]
        assert "EU-AI-ACT" in ids
        assert "SR-11-7" in ids
        assert "NIST-AI-RMF" in ids

    def test_all_have_positive_counts(self):
        for fw_id, name, count in list_frameworks():
            assert count > 0, f"{fw_id} has 0 procedures"
            assert name, f"{fw_id} has no name"
