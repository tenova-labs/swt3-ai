"""Tests for declarative governance config (trust_mesh, hardware, density_policy, profiles)."""

import hashlib
import os
import tempfile
from pathlib import Path

import pytest

from swt3_ai.config import load_full_config, load_config, compute_config_hash


def _write_yaml(tmp_path: Path, content: str) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    p = tmp_path / "swt3.yaml"
    p.write_text(content, encoding="utf-8")
    return str(p)


# ── trust_mesh parsing ──────────────────────────────────────────────────


class TestTrustMesh:
    def test_parses_all_fields(self, tmp_path: Path) -> None:
        os.environ["TEST_PARTNER_KEY"] = "secret123"
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  mode: strict
  min_trust_level: 3
  require_signature: true
  freshness_window: 7200
  trusted_tenants:
    - PARTNER_A
    - PARTNER_B
  trusted_agents:
    - tenant: PARTNER_A
      agent: bot-1
  deny_agents:
    - bad-bot
  deny_tenants:
    - EVIL_CORP
  required_procedures:
    - AI-INF.1
    - AI-GRD.1
  signing_keys:
    - agent: bot-1
      key_env: TEST_PARTNER_KEY
""")
        loaded = load_full_config(path)
        tm = loaded.trust_mesh
        assert tm is not None
        assert tm.mode == "strict"
        assert tm.min_trust_level == 3
        assert tm.require_signature is True
        assert tm.freshness_window == 7200
        assert tm.trusted_tenants == ["PARTNER_A", "PARTNER_B"]
        assert tm.trusted_agents == [{"tenant": "PARTNER_A", "agent": "bot-1"}]
        assert tm.deny_agents == ["bad-bot"]
        assert tm.deny_tenants == ["EVIL_CORP"]
        assert tm.required_procedures == ["AI-INF.1", "AI-GRD.1"]
        assert tm.signing_keys == [{"agent": "bot-1", "key": "secret123"}]
        del os.environ["TEST_PARTNER_KEY"]

    def test_rejects_unknown_keys(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  mode: strict
  typo_field: true
""")
        with pytest.raises(ValueError, match="unknown key"):
            load_full_config(path)

    def test_rejects_invalid_mode(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  mode: aggressive
""")
        with pytest.raises(ValueError, match="must be strict, permissive, or monitor"):
            load_full_config(path)

    def test_throws_on_missing_signing_key_env(self, tmp_path: Path) -> None:
        os.environ.pop("NONEXISTENT_KEY", None)
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  signing_keys:
    - agent: bot-1
      key_env: NONEXISTENT_KEY
""")
        with pytest.raises(ValueError, match="NONEXISTENT_KEY"):
            load_full_config(path)

    def test_validates_trusted_agents_structure(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  trusted_agents:
    - tenant: PARTNER_A
""")
        with pytest.raises(ValueError, match="must have 'tenant' and 'agent' fields"):
            load_full_config(path)


# ── hardware parsing ────────────────────────────────────────────────────


class TestHardware:
    def test_parses_hardware_section(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
hardware:
  require_attestation: true
  attestation_freshness: 1800
  allowed_methods:
    - tpm_2.0
    - secure_enclave
""")
        loaded = load_full_config(path)
        hw = loaded.hardware
        assert hw is not None
        assert hw.require_attestation is True
        assert hw.attestation_freshness == 1800
        assert hw.allowed_methods == ["tpm_2.0", "secure_enclave"]

    def test_rejects_unknown_hardware_keys(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
hardware:
  require_attestation: true
  bogus_field: 42
""")
        with pytest.raises(ValueError, match="unknown key"):
            load_full_config(path)


# ── density_policy parsing ──────────────────────────────────────────────


class TestDensityPolicy:
    def test_parses_density_policy(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
density_policy:
  min_anchors_per_1000_tokens: 2
  required_providers:
    - vllm-native
  max_chain_gap_seconds: 30
  require_signing_key: true
  min_trust_level: 3
""")
        loaded = load_full_config(path)
        dp = loaded.density_policy
        assert dp is not None
        assert dp.min_anchors_per_1000_tokens == 2
        assert dp.required_providers == ["vllm-native"]
        assert dp.max_chain_gap_seconds == 30
        assert dp.require_signing_key is True
        assert dp.min_trust_level == 3


# ── profile loading ─────────────────────────────────────────────────────


class TestProfiles:
    def test_loads_profile_with_overrides(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
profile: minimal
endpoint: https://example.com
api_key: axm_live_test
tenant_id: OVERRIDE_TENANT
clearing_level: 2
""")
        loaded = load_full_config(path)
        assert loaded.witness_kwargs.get("clearing_level") == 2
        assert loaded.trust_mesh is not None
        assert loaded.trust_mesh.mode == "monitor"

    def test_rejects_unknown_profile(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
profile: nonexistent-profile
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
""")
        with pytest.raises(ValueError, match="Unknown profile"):
            load_full_config(path)

    def test_user_arrays_replace_profile_arrays(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
profile: eu-ai-act-high-risk
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
agent_id: my-agent
jurisdiction: DE
signing_key: test-key-123
trust_mesh:
  required_procedures:
    - AI-INF.1
""")
        loaded = load_full_config(path)
        assert loaded.trust_mesh is not None
        assert loaded.trust_mesh.required_procedures == ["AI-INF.1"]


# ── config hash ─────────────────────────────────────────────────────────


class TestConfigHash:
    def test_deterministic(self) -> None:
        content = "endpoint: https://example.com\napi_key: axm_live_test\n"
        h1 = compute_config_hash(content)
        h2 = compute_config_hash(content)
        assert h1 == h2
        assert len(h1) == 64

    def test_differs_for_different_content(self) -> None:
        h1 = compute_config_hash("clearing_level: 1")
        h2 = compute_config_hash("clearing_level: 2")
        assert h1 != h2

    def test_present_in_loaded_config(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
""")
        loaded = load_full_config(path)
        assert len(loaded.config_hash) == 64


# ── backward compatibility ──────────────────────────────────────────────


class TestBackwardCompat:
    def test_load_config_returns_dict_without_sections(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  mode: strict
""")
        opts = load_config(path)
        assert "trust_mesh" not in opts
        assert "config_hash" not in opts
        assert opts["endpoint"] == "https://example.com"
        assert opts["tenant_id"] == "TEST"


# ── mcp_policy ─────────────────────────────────────────────────────────


class TestMcpPolicy:
    def test_parses_all_fields(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_test
tenant_id: TEST
mcp_policy:
  witnessed_tools: ["write_*", "search_*"]
  exempt_tools: ["list_files"]
  require_trust_level: 3
  auto_witness: true
  block_on_failure: true
""")
        loaded = load_full_config(path)
        assert loaded.mcp_policy is not None
        assert loaded.mcp_policy.witnessed_tools == ["write_*", "search_*"]
        assert loaded.mcp_policy.exempt_tools == ["list_files"]
        assert loaded.mcp_policy.require_trust_level == 3
        assert loaded.mcp_policy.auto_witness is True
        assert loaded.mcp_policy.block_on_failure is True

    def test_rejects_unknown_keys(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_test
tenant_id: TEST
mcp_policy:
  witnessed_tools: ["*"]
  bogus_key: true
""")
        with pytest.raises(ValueError, match="unknown key"):
            load_full_config(path)

    def test_defaults_when_omitted(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_test
tenant_id: TEST
mcp_policy:
  witnessed_tools: ["*"]
""")
        loaded = load_full_config(path)
        assert loaded.mcp_policy.exempt_tools == []
        assert loaded.mcp_policy.require_trust_level == 0
        assert loaded.mcp_policy.auto_witness is True
        assert loaded.mcp_policy.block_on_failure is False

    def test_null_when_absent(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_test
tenant_id: TEST
""")
        loaded = load_full_config(path)
        assert loaded.mcp_policy is None

    def test_merges_from_profile(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
profile: eu-ai-act-high-risk
api_key: axm_test
tenant_id: TEST
agent_id: test-agent
jurisdiction: DE
signing_key: test-key-123
mcp_policy:
  block_on_failure: false
""")
        loaded = load_full_config(path)
        # Profile sets witnessed_tools: ["*"], user overrides block_on_failure
        assert loaded.mcp_policy.witnessed_tools == ["*"]
        assert loaded.mcp_policy.block_on_failure is False


# ── extends ────────────────────────────────────────────────────────────


class TestExtends:
    def test_single_file(self, tmp_path: Path) -> None:
        (tmp_path / "base.yaml").write_text(
            "endpoint: https://base.example.com\napi_key: axm_base\ntenant_id: BASE\nclearing_level: 2\n"
        )
        path = _write_yaml(tmp_path, "extends: base.yaml\ntenant_id: CHILD\n")
        loaded = load_full_config(path)
        assert loaded.witness_kwargs["endpoint"] == "https://base.example.com"
        assert loaded.witness_kwargs["tenant_id"] == "CHILD"
        assert loaded.witness_kwargs["clearing_level"] == 2

    def test_array_extends(self, tmp_path: Path) -> None:
        (tmp_path / "corp.yaml").write_text(
            "endpoint: https://corp.example.com\napi_key: axm_corp\ntenant_id: CORP\n"
        )
        (tmp_path / "team.yaml").write_text(
            "clearing_level: 2\nagent_id: team-agent\n"
        )
        path = _write_yaml(tmp_path, """
extends:
  - corp.yaml
  - team.yaml
tenant_id: PROJECT
""")
        loaded = load_full_config(path)
        assert loaded.witness_kwargs["endpoint"] == "https://corp.example.com"
        assert loaded.witness_kwargs["clearing_level"] == 2
        assert loaded.witness_kwargs["tenant_id"] == "PROJECT"

    def test_deep_merge_sections(self, tmp_path: Path) -> None:
        (tmp_path / "parent.yaml").write_text("""
endpoint: https://parent.example.com
api_key: axm_parent
tenant_id: PARENT
trust_mesh:
  mode: strict
  min_trust_level: 2
""")
        path = _write_yaml(tmp_path, """
extends: parent.yaml
trust_mesh:
  min_trust_level: 3
""")
        loaded = load_full_config(path)
        assert loaded.trust_mesh.mode == "strict"
        assert loaded.trust_mesh.min_trust_level == 3

    def test_circular_detection(self, tmp_path: Path) -> None:
        (tmp_path / "a.yaml").write_text("extends: b.yaml\napi_key: axm_a\n")
        (tmp_path / "b.yaml").write_text("extends: a.yaml\napi_key: axm_b\n")
        with pytest.raises(ValueError, match="Circular extends detected"):
            load_full_config(str(tmp_path / "a.yaml"))

    def test_depth_limit(self, tmp_path: Path) -> None:
        for i in range(11, 0, -1):
            content = (
                f"extends: chain{i + 1}.yaml\napi_key: axm_c{i}\n"
                if i < 11
                else "api_key: axm_leaf\ntenant_id: LEAF\n"
            )
            (tmp_path / f"chain{i}.yaml").write_text(content)
        path = _write_yaml(tmp_path, "extends: chain1.yaml\ntenant_id: ROOT\n")
        with pytest.raises(ValueError, match="Extends depth limit exceeded"):
            load_full_config(path)

    def test_relative_path_from_config_dir(self, tmp_path: Path) -> None:
        (tmp_path / "shared.yaml").write_text(
            "endpoint: https://shared.example.com\napi_key: axm_shared\ntenant_id: SHARED\n"
        )
        subdir = tmp_path / "sub"
        subdir.mkdir()
        child_path = subdir / "child.yaml"
        child_path.write_text("extends: ../shared.yaml\ntenant_id: CHILD_SUB\n")
        loaded = load_full_config(str(child_path))
        assert loaded.witness_kwargs["endpoint"] == "https://shared.example.com"
        assert loaded.witness_kwargs["tenant_id"] == "CHILD_SUB"

    def test_absolute_path(self, tmp_path: Path) -> None:
        abs_base = tmp_path / "abs-base.yaml"
        abs_base.write_text(
            "endpoint: https://abs.example.com\napi_key: axm_abs\ntenant_id: ABS\n"
        )
        path = _write_yaml(tmp_path, f"extends: {abs_base}\ntenant_id: CHILD_ABS\n")
        loaded = load_full_config(path)
        assert loaded.witness_kwargs["endpoint"] == "https://abs.example.com"
        assert loaded.witness_kwargs["tenant_id"] == "CHILD_ABS"

    def test_config_hash_includes_all_files(self, tmp_path: Path) -> None:
        (tmp_path / "hash-base.yaml").write_text(
            "endpoint: https://hash.example.com\napi_key: axm_hash\ntenant_id: HASH_BASE\n"
        )
        path = _write_yaml(tmp_path, "extends: hash-base.yaml\ntenant_id: HASH_CHILD\n")
        loaded = load_full_config(path)
        solo_path = _write_yaml(tmp_path / "solo", """
tenant_id: HASH_CHILD
api_key: axm_hash
endpoint: https://hash.example.com
""")
        solo = load_full_config(solo_path)
        assert loaded.config_hash != solo.config_hash
        assert len(loaded.config_hash) == 64


# ── all sections optional ──────────────────────────────────────────────


class TestMinimal:
    def test_bare_yaml_works(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
""")
        loaded = load_full_config(path)
        assert loaded.trust_mesh is None
        assert loaded.hardware is None
        assert loaded.density_policy is None
        assert loaded.mcp_policy is None
        assert loaded.witness_kwargs["endpoint"] == "https://example.com"
