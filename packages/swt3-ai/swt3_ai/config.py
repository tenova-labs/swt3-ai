"""SWT3 AI Witness SDK -- .swt3.yaml policy-as-code loader.

Load witnessing policy from a YAML config file instead of passing
25+ parameters in code. Secrets are resolved from environment variables
using the ``_env`` suffix convention -- they never appear in the YAML file.

Usage:
    from swt3_ai import Witness

    witness = Witness.from_config()              # auto-finds .swt3.yaml
    witness = Witness.from_config("prod.yaml")   # explicit path
    witness = Witness.from_config(clearing_level=3)  # override one field

Requires: ``pip install pyyaml`` (or ``pip install swt3-ai[yaml]``)
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .types import (
    TrustMeshConfig, HardwareConfig, DensityPolicyConfig, McpPolicyConfig, MerkleConfig, SkillCardConfig, LoadedConfig,
    ChainRule, RuntimeProfileConfig, SkillInfo,
)

# ── Typo Protection Sets ──────────────────────────────────────────────

_VALID_POLICY_KEYS = frozenset({
    "require_signing",
    "min_clearing_level",
    "required_procedures",
    "require_agent_id",
    "max_flush_interval",
    "require_jurisdiction",
})

_VALID_TRUST_MESH_KEYS = frozenset({
    "mode", "min_trust_level", "require_signature", "freshness_window",
    "trusted_tenants", "trusted_agents", "deny_agents", "deny_tenants",
    "required_procedures", "signing_keys",
})

_VALID_HARDWARE_KEYS = frozenset({
    "require_attestation", "attestation_freshness", "allowed_methods", "runtime_profile",
})

_VALID_DENSITY_POLICY_KEYS = frozenset({
    "min_anchors_per_1000_tokens", "required_providers",
    "max_chain_gap_seconds", "require_signing_key", "min_trust_level",
})

_VALID_MCP_POLICY_KEYS = frozenset({
    "witnessed_tools", "exempt_tools", "require_trust_level",
    "auto_witness", "block_on_failure",
    "max_velocity", "max_chain_depth", "tool_allowlist", "tool_blocklist",
    "fail_secure", "rules", "max_tokens_per_session",
})

_VALID_PROFILES = frozenset({
    "eu-ai-act-high-risk",
    "granite-sovereign",
    "mythos-defense",
    "nist-ai-rmf",
    "owasp-agentic-top10",
    "minimal",
})

_VALID_MERKLE_KEYS = frozenset({
    "enabled", "accumulator_interval",
})

_SECTION_KEYS = frozenset({
    "policy", "trust_mesh", "hardware", "density_policy", "mcp_policy", "merkle", "skill_card", "profile",
})


# ── File Discovery ────────────────────────────────────────────────────

def _find_config(path: Optional[str] = None) -> Path:
    """Locate the config file. Search order: explicit > swt3.yaml > .swt3.yaml."""
    if path:
        p = Path(path)
        if p.is_file():
            return p
        raise FileNotFoundError(f"SWT3 config file not found: {path}")

    for name in ("swt3.yaml", ".swt3.yaml"):
        p = Path(name)
        if p.is_file():
            return p

    raise FileNotFoundError(
        "No SWT3 config file found. Create swt3.yaml or .swt3.yaml, "
        "or pass an explicit path to load_config()."
    )


# ── Extends / Composition ─────────────────────────────────────────────

_MAX_EXTENDS_DEPTH = 10


def _process_extends(
    raw: Dict[str, Any],
    config_dir: Path,
    *,
    visited: Optional[set] = None,
    depth: int = 0,
    root_dir: Optional[Path] = None,
) -> tuple:
    """Process extends: field recursively. Returns (merged_dict, extended_contents_list)."""
    if visited is None:
        visited = set()

    extends_val = raw.pop("extends", None)
    if extends_val is None:
        return raw, []

    if depth >= _MAX_EXTENDS_DEPTH:
        raise ValueError(f"Extends depth limit exceeded (max {_MAX_EXTENDS_DEPTH})")

    # The root directory is the top-level config file's parent -- set on first call
    boundary = root_dir or config_dir

    files = extends_val if isinstance(extends_val, list) else [extends_val]
    base: Dict[str, Any] = {}
    all_contents: list = []

    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML is required for extends support.")

    for file in files:
        is_absolute = Path(file).is_absolute()
        resolved = Path(file) if is_absolute else config_dir / file

        if not resolved.is_file():
            raise FileNotFoundError(f"Extends file not found: {file} (resolved: {resolved})")

        real = resolved.resolve()

        # Path containment: relative paths must resolve within the root config directory tree
        if not is_absolute:
            real_boundary = boundary.resolve()
            try:
                real.relative_to(real_boundary)
            except ValueError:
                raise ValueError(
                    f"Extends path escapes config directory: {file} (resolved: {real}). "
                    f"Use an absolute path if this is intentional."
                )

        if str(real) in visited:
            raise ValueError(f"Circular extends detected: {file} (resolved: {real})")

        visited.add(str(real))
        content = resolved.read_text(encoding="utf-8")
        all_contents.append(content)

        parent_raw = yaml.safe_load(content)
        if not isinstance(parent_raw, dict):
            raise ValueError(f"Invalid extends file: {file} (expected a YAML mapping)")

        parent_dir = resolved.parent
        parent_raw, parent_contents = _process_extends(
            parent_raw, parent_dir, visited=visited, depth=depth + 1, root_dir=boundary,
        )
        all_contents = parent_contents + all_contents

        base = _deep_merge(base, parent_raw)

    return _deep_merge(base, raw), all_contents


# ── Section Helpers ───────────────────────────────────────────────────

def _validate_keys(
    section: Dict[str, Any],
    valid_keys: frozenset,
    section_name: str,
) -> None:
    unknown = set(section.keys()) - valid_keys
    if unknown:
        raise ValueError(f"Unknown {section_name} keys: {', '.join(sorted(unknown))}")


def _resolve_env(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve ``_env`` fields from environment variables."""
    config = dict(raw)

    env_fields = {
        "api_key_env": "api_key",
        "signing_key_env": "signing_key",
    }

    for env_key, target_key in env_fields.items():
        if env_key in config:
            var_name = config.pop(env_key)
            value = os.environ.get(var_name)
            if not value:
                raise ValueError(
                    f"Environment variable '{var_name}' (from {env_key}) is not set"
                )
            config[target_key] = value

    return config


def _extract_policy(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract and remove the policy section from config."""
    policy = config.pop("policy", None)
    if policy is None:
        return None
    if not isinstance(policy, dict):
        raise ValueError("'policy' must be a YAML mapping")
    _validate_keys(policy, _VALID_POLICY_KEYS, "policy")
    return policy


def _extract_trust_mesh(config: Dict[str, Any]) -> Optional[TrustMeshConfig]:
    """Extract and remove the trust_mesh section from config."""
    section = config.pop("trust_mesh", None)
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ValueError("'trust_mesh' must be a YAML mapping")
    _validate_keys(section, _VALID_TRUST_MESH_KEYS, "trust_mesh")

    mode = section.get("mode", "permissive")
    if mode not in ("strict", "permissive", "monitor"):
        raise ValueError(f"trust_mesh.mode must be strict, permissive, or monitor (got: {mode})")

    # Resolve signing_keys _env references
    raw_keys: List[Dict[str, str]] = section.get("signing_keys", [])
    resolved_keys: List[Dict[str, str]] = []
    for entry in raw_keys:
        if not entry.get("agent"):
            raise ValueError("trust_mesh.signing_keys[].agent is required")
        if not entry.get("key_env"):
            raise ValueError("trust_mesh.signing_keys[].key_env is required")
        value = os.environ.get(entry["key_env"])
        if not value:
            raise ValueError(
                f"Environment variable '{entry['key_env']}' "
                f"(from trust_mesh.signing_keys) is not set"
            )
        resolved_keys.append({"agent": entry["agent"], "key": value})

    # Validate trusted_agents structure
    trusted_agents: List[Dict[str, str]] = section.get("trusted_agents", [])
    for ta in trusted_agents:
        if not ta.get("tenant") or not ta.get("agent"):
            raise ValueError(
                "trust_mesh.trusted_agents entries must have 'tenant' and 'agent' fields"
            )

    return TrustMeshConfig(
        mode=mode,
        min_trust_level=section.get("min_trust_level", 1),
        require_signature=section.get("require_signature", False),
        freshness_window=section.get("freshness_window", 86400),
        trusted_tenants=section.get("trusted_tenants", []),
        trusted_agents=trusted_agents,
        deny_agents=section.get("deny_agents", []),
        deny_tenants=section.get("deny_tenants", []),
        required_procedures=section.get("required_procedures", []),
        signing_keys=resolved_keys,
    )


def _extract_hardware(config: Dict[str, Any]) -> Optional[HardwareConfig]:
    """Extract and remove the hardware section from config."""
    section = config.pop("hardware", None)
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ValueError("'hardware' must be a YAML mapping")

    # Extract runtime_profile before validateKeys (nested object, not flat key)
    rp = section.pop("runtime_profile", None)

    _validate_keys(section, _VALID_HARDWARE_KEYS, "hardware")

    runtime_profile: Optional[RuntimeProfileConfig] = None
    if isinstance(rp, dict):
        runtime_profile = RuntimeProfileConfig(
            expected_topology=rp.get("expected_topology"),
            min_gpu_count=rp.get("min_gpu_count"),
            min_memory_mb=rp.get("min_memory_mb"),
            expected_accelerator=rp.get("expected_accelerator"),
            max_temperature_celsius=rp.get("max_temperature_celsius"),
            max_power_watts=rp.get("max_power_watts"),
        )

    return HardwareConfig(
        require_attestation=section.get("require_attestation", False),
        attestation_freshness=section.get("attestation_freshness", 3600),
        allowed_methods=section.get("allowed_methods", []),
        runtime_profile=runtime_profile,
    )


def _extract_density_policy(config: Dict[str, Any]) -> Optional[DensityPolicyConfig]:
    """Extract and remove the density_policy section from config."""
    section = config.pop("density_policy", None)
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ValueError("'density_policy' must be a YAML mapping")
    _validate_keys(section, _VALID_DENSITY_POLICY_KEYS, "density_policy")

    return DensityPolicyConfig(
        min_anchors_per_1000_tokens=section.get("min_anchors_per_1000_tokens", 1),
        required_providers=section.get("required_providers", []),
        max_chain_gap_seconds=section.get("max_chain_gap_seconds", 60),
        require_signing_key=section.get("require_signing_key", False),
        min_trust_level=section.get("min_trust_level", 1),
    )


def _extract_mcp_policy(config: Dict[str, Any]) -> Optional[McpPolicyConfig]:
    """Extract and remove the mcp_policy section from config."""
    section = config.pop("mcp_policy", None)
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ValueError("'mcp_policy' must be a YAML mapping")
    _validate_keys(section, _VALID_MCP_POLICY_KEYS, "mcp_policy")

    raw_rules = section.get("rules", [])
    rules = [
        ChainRule(
            match=r.get("match", "*"),
            action=r.get("action", "block"),
            reason=r.get("reason", ""),
            params=r.get("params", {}),
        )
        for r in raw_rules
        if isinstance(r, dict)
    ]

    return McpPolicyConfig(
        witnessed_tools=section.get("witnessed_tools", []),
        exempt_tools=section.get("exempt_tools", []),
        require_trust_level=section.get("require_trust_level", 0),
        auto_witness=section.get("auto_witness", True),
        block_on_failure=section.get("block_on_failure", False),
        max_velocity=section.get("max_velocity"),
        max_chain_depth=section.get("max_chain_depth"),
        tool_allowlist=section.get("tool_allowlist", []),
        tool_blocklist=section.get("tool_blocklist", []),
        fail_secure=section.get("fail_secure", True),
        rules=rules,
        max_tokens_per_session=section.get("max_tokens_per_session"),
    )


def _extract_merkle(config: Dict[str, Any]) -> Optional[MerkleConfig]:
    """Extract and remove the merkle section from config."""
    section = config.pop("merkle", None)
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ValueError("'merkle' must be a YAML mapping")
    _validate_keys(section, _VALID_MERKLE_KEYS, "merkle")

    return MerkleConfig(
        enabled=section.get("enabled", True),
        accumulator_interval=section.get("accumulator_interval", 0),
    )


_VALID_SKILL_CARD_KEYS = frozenset({"skills", "expected_manifest_hash"})


def _extract_skill_card(config: Dict[str, Any]) -> Optional[SkillCardConfig]:
    """Extract and remove the skill_card section from config."""
    section = config.pop("skill_card", None)
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ValueError("'skill_card' must be a YAML mapping")
    _validate_keys(section, _VALID_SKILL_CARD_KEYS, "skill_card")

    raw_skills = section.get("skills", [])
    if not isinstance(raw_skills, list) or len(raw_skills) == 0:
        return None

    skills: list = []
    for s in raw_skills:
        if isinstance(s, str):
            skills.append(s)
        elif isinstance(s, dict):
            skills.append(SkillInfo(
                name=s.get("name", ""),
                version=s.get("version"),
                skill_hash=s.get("skill_hash"),
            ))
        else:
            skills.append(str(s))

    return SkillCardConfig(
        skills=skills,
        expected_manifest_hash=section.get("expected_manifest_hash"),
    )


# ── Profile / Template System ─────────────────────────────────────────

def _deep_merge(
    base: Dict[str, Any],
    override: Dict[str, Any],
) -> Dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if (
            isinstance(value, dict)
            and key in result
            and isinstance(result[key], dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_profile(profile_name: str) -> Dict[str, Any]:
    if profile_name not in _VALID_PROFILES:
        raise ValueError(
            f"Unknown profile: '{profile_name}'. "
            f"Valid profiles: {', '.join(sorted(_VALID_PROFILES))}"
        )
    templates_dir = Path(__file__).parent / "templates"
    template_path = templates_dir / f"{profile_name}.yaml"
    if not template_path.is_file():
        raise FileNotFoundError(f"Profile template not found: {template_path}")

    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML is required for profile support.")

    with open(template_path, "r") as f:
        tmpl = yaml.safe_load(f)
    if not isinstance(tmpl, dict):
        raise ValueError(f"Invalid profile template: {profile_name}")
    return tmpl


# ── Policy Validation ─────────────────────────────────────────────────

def validate_policy(config: Dict[str, Any], policy: Dict[str, Any]) -> None:
    """Validate config against policy rules. Raises ValueError on violation."""
    if policy.get("require_signing") and not config.get("signing_key"):
        raise ValueError(
            "Policy violation: require_signing is true but no signing_key configured"
        )

    min_level = policy.get("min_clearing_level")
    if min_level is not None:
        actual = config.get("clearing_level", 1)
        if actual < min_level:
            raise ValueError(
                f"Policy violation: clearing_level {actual} is below "
                f"min_clearing_level {min_level}"
            )

    if policy.get("require_agent_id") and not config.get("agent_id"):
        raise ValueError(
            "Policy violation: require_agent_id is true but no agent_id configured"
        )

    if policy.get("require_jurisdiction") and not config.get("jurisdiction"):
        raise ValueError(
            "Policy violation: require_jurisdiction is true but no jurisdiction configured"
        )

    max_flush = policy.get("max_flush_interval")
    if max_flush is not None:
        actual = config.get("flush_interval", 5.0)
        if actual > max_flush:
            raise ValueError(
                f"Policy violation: flush_interval {actual}s exceeds "
                f"max_flush_interval {max_flush}s"
            )

    required_procs = policy.get("required_procedures")
    if required_procs:
        configured = config.get("procedures")
        if configured is not None:
            missing = set(required_procs) - set(configured)
            if missing:
                raise ValueError(
                    f"Policy violation: required_procedures {sorted(missing)} "
                    f"not in configured procedures list"
                )


# ── Config Hash ───────────────────────────────────────────────────────

def compute_config_hash(content: str) -> str:
    """SHA-256 hash of the raw config file content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ── Public API ────────────────────────────────────────────────────────

def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load a .swt3.yaml config file and return a dict for Witness().

    Backward-compatible: returns witness kwargs only.

    Args:
        path: Explicit path to YAML file. If None, searches for
              swt3.yaml or .swt3.yaml in the current directory.

    Returns:
        Dict compatible with ``Witness(**config)``.
    """
    return load_full_config(path).witness_kwargs


def load_full_config(path: Optional[str] = None) -> LoadedConfig:
    """Load a .swt3.yaml config file and return the full parsed config.

    Returns LoadedConfig with witness_kwargs, trust_mesh, hardware,
    density_policy, and config_hash.
    """
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for .swt3.yaml support. "
            "Install it with: pip install pyyaml  "
            "(or: pip install swt3-ai[yaml])"
        )

    config_path = _find_config(path)

    with open(config_path, "r") as f:
        content = f.read()

    raw = yaml.safe_load(content)

    if not isinstance(raw, dict):
        raise ValueError(
            f"Invalid config file: expected a YAML mapping, got {type(raw).__name__}"
        )

    # Extends: load parent files and deep-merge (extends < profile < user config)
    config_dir = Path(config_path).resolve().parent
    real_path = str(Path(config_path).resolve())
    # Containment boundary: one level above config dir (allows ../shared.yaml but blocks ../../etc/passwd)
    extends_root_dir = config_dir.parent
    raw, extended_contents = _process_extends(
        raw, config_dir, visited={real_path}, root_dir=extends_root_dir,
    )

    # Config hash: includes all extended files + main file
    all_contents = "\n".join(extended_contents + [content])
    config_hash = compute_config_hash(all_contents)

    # Profile: load base template and deep-merge user config on top
    profile_name = raw.pop("profile", None)
    if profile_name:
        template = _load_profile(profile_name)
        raw = _deep_merge(template, raw)

    # Schema validation: catch typos and unknown keys before they silently pass through
    from .schema import validate_schema as _run_schema_validation
    schema_result = _run_schema_validation(raw)
    if not schema_result.valid:
        msgs = [f"{e.path}: {e.message}" for e in schema_result.errors]
        raise ValueError(f"SWT3 config validation failed:\n  " + "\n  ".join(msgs))

    # Extract governance sections before env resolution
    policy = _extract_policy(raw)
    trust_mesh = _extract_trust_mesh(raw)
    hardware = _extract_hardware(raw)
    skill_card = _extract_skill_card(raw)
    density_policy = _extract_density_policy(raw)
    mcp_policy = _extract_mcp_policy(raw)
    merkle = _extract_merkle(raw)

    # Remove any remaining section keys
    for key in list(raw.keys()):
        if key in _SECTION_KEYS:
            del raw[key]

    config = _resolve_env(raw)

    # Validate policy after config is fully resolved
    if policy:
        validate_policy(config, policy)

    return LoadedConfig(
        witness_kwargs=config,
        trust_mesh=trust_mesh,
        hardware=hardware,
        skill_card=skill_card,
        density_policy=density_policy,
        mcp_policy=mcp_policy,
        merkle=merkle,
        policy=policy,
        config_hash=config_hash,
    )
