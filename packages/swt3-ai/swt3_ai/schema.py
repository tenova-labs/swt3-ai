"""SWT3 YAML schema validator.

Validates a raw parsed YAML config against the SWT3 schema.
Used by ``swt3 doctor`` and available as a public API for CI/CD.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

_VELOCITY_RE = re.compile(r"^\d+/\d+s$")


def _re_velocity(value: str) -> bool:
    return bool(_VELOCITY_RE.match(value))


@dataclass
class ValidationError:
    path: str
    message: str
    severity: str  # "error" | "warning"


@dataclass
class ValidationResult:
    valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationError] = field(default_factory=list)


_KNOWN_TOP_LEVEL: Set[str] = {
    "api_key", "api_key_env", "tenant_id", "clearing_level", "endpoint",
    "buffer_size", "flush_interval", "max_retries", "latency_threshold_ms",
    "guardrails_required", "guardrail_names", "factor_handoff", "factor_handoff_path",
    "agent_id", "signing_key", "signing_key_env", "signing_key_id", "signing_key_version",
    "cycle_id", "policy_version", "jurisdiction", "legal_basis", "purpose_class",
    "on_flush", "gateway_mode", "wal_path", "replay_window",
    "token_budget", "procedures", "strict",
    "policy", "trust_mesh", "hardware", "density_policy", "mcp_policy",
    "merkle", "skill_card", "digest_algorithm", "profile", "extends",
}

_VALID_ATTESTATION_METHODS: Set[str] = {
    "tpm_2.0", "secure_enclave", "sgx", "sev", "trustzone", "nitro", "cerebras_wse3",
}

_VALID_RUNTIME_PROFILE_KEYS: Set[str] = {
    "expected_topology", "min_gpu_count", "min_memory_mb",
    "expected_accelerator", "max_temperature_celsius", "max_power_watts",
}

_VALID_SKILL_CARD_KEYS: Set[str] = {"skills", "expected_manifest_hash"}

_SECTION_SCHEMAS: Dict[str, Set[str]] = {
    "policy": {
        "require_signing", "min_clearing_level", "required_procedures",
        "require_agent_id", "max_flush_interval", "require_jurisdiction",
    },
    "trust_mesh": {
        "mode", "min_trust_level", "require_signature", "freshness_window",
        "trusted_tenants", "trusted_agents", "deny_agents", "deny_tenants",
        "required_procedures", "signing_keys",
    },
    "hardware": {
        "require_attestation", "attestation_freshness", "allowed_methods", "runtime_profile",
    },
    "density_policy": {
        "min_anchors_per_1000_tokens", "required_providers",
        "max_chain_gap_seconds", "require_signing_key", "min_trust_level",
    },
    "mcp_policy": {
        "witnessed_tools", "exempt_tools", "require_trust_level",
        "auto_witness", "block_on_failure",
        "max_velocity", "max_chain_depth", "tool_allowlist", "tool_blocklist",
        "fail_secure", "rules", "max_tokens_per_session",
    },
    "merkle": {"enabled", "accumulator_interval"},
    "skill_card": _VALID_SKILL_CARD_KEYS,
}


def _check_type(
    value: Any,
    expected: str,
    path: str,
    errors: List[ValidationError],
) -> bool:
    if expected == "number" and not isinstance(value, (int, float)):
        errors.append(ValidationError(path, f"expected number, got {type(value).__name__}", "error"))
        return False
    if expected == "boolean" and not isinstance(value, bool):
        errors.append(ValidationError(path, f"expected boolean, got {type(value).__name__}", "error"))
        return False
    if expected == "string" and not isinstance(value, str):
        errors.append(ValidationError(path, f"expected string, got {type(value).__name__}", "error"))
        return False
    if expected == "string[]":
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            errors.append(ValidationError(path, "expected string array", "error"))
            return False
    return True


def _edit_distance(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            dp[i][j] = (dp[i - 1][j - 1] if a[i - 1] == b[j - 1]
                        else 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]))
    return dp[m][n]


def _suggest_key(key: str, valid_keys: Set[str]) -> str:
    best, best_dist = "", 3
    for v in valid_keys:
        d = _edit_distance(key, v)
        if d < best_dist:
            best_dist = d
            best = v
    return best


def validate_schema(raw: Dict[str, Any]) -> ValidationResult:
    errors: List[ValidationError] = []
    warnings: List[ValidationError] = []

    # Top-level key check with did-you-mean suggestions
    for key in raw:
        if key not in _KNOWN_TOP_LEVEL:
            suggestion = _suggest_key(key, _KNOWN_TOP_LEVEL)
            msg = (f'unknown top-level key (did you mean "{suggestion}"?)'
                   if suggestion else "unknown top-level key")
            errors.append(ValidationError(key, msg, "error"))

    # clearing_level
    if "clearing_level" in raw:
        cl = raw["clearing_level"]
        if not isinstance(cl, int) or cl not in (0, 1, 2, 3):
            errors.append(ValidationError("clearing_level", "must be 0, 1, 2, or 3", "error"))

    # digest_algorithm: only sha256 in this version
    if "digest_algorithm" in raw:
        da = raw["digest_algorithm"]
        if not isinstance(da, str):
            errors.append(ValidationError("digest_algorithm", "expected string", "error"))
        elif da != "sha256":
            errors.append(ValidationError("digest_algorithm", 'only "sha256" is supported in this version', "error"))

    # trust_mesh.mode enum
    tm = raw.get("trust_mesh")
    if isinstance(tm, dict):
        if "mode" in tm and tm["mode"] not in ("strict", "permissive", "monitor"):
            errors.append(ValidationError("trust_mesh.mode", "must be strict, permissive, or monitor", "error"))
        if "min_trust_level" in tm:
            _check_type(tm["min_trust_level"], "number", "trust_mesh.min_trust_level", errors)
        if "require_signature" in tm:
            _check_type(tm["require_signature"], "boolean", "trust_mesh.require_signature", errors)
        if "freshness_window" in tm:
            _check_type(tm["freshness_window"], "number", "trust_mesh.freshness_window", errors)
        if "trusted_tenants" in tm:
            _check_type(tm["trusted_tenants"], "string[]", "trust_mesh.trusted_tenants", errors)
        if "deny_agents" in tm:
            _check_type(tm["deny_agents"], "string[]", "trust_mesh.deny_agents", errors)

    # hardware.allowed_methods enum validation
    hw = raw.get("hardware")
    if isinstance(hw, dict) and "allowed_methods" in hw and isinstance(hw["allowed_methods"], list):
        for method in hw["allowed_methods"]:
            if isinstance(method, str) and method not in _VALID_ATTESTATION_METHODS:
                valid = ", ".join(sorted(_VALID_ATTESTATION_METHODS))
                errors.append(ValidationError(
                    "hardware.allowed_methods",
                    f'unknown attestation method "{method}". Valid: {valid}',
                    "error",
                ))
    # hardware.runtime_profile nested validation
    if isinstance(hw, dict) and "runtime_profile" in hw:
        rp = hw["runtime_profile"]
        if isinstance(rp, dict):
            for key in rp:
                if key not in _VALID_RUNTIME_PROFILE_KEYS:
                    suggestion = _suggest_key(key, _VALID_RUNTIME_PROFILE_KEYS)
                    msg = (f'unknown key (did you mean "{suggestion}"?)'
                           if suggestion else "unknown key")
                    errors.append(ValidationError(f"hardware.runtime_profile.{key}", msg, "error"))
            if "min_gpu_count" in rp:
                _check_type(rp["min_gpu_count"], "number", "hardware.runtime_profile.min_gpu_count", errors)
            if "min_memory_mb" in rp:
                _check_type(rp["min_memory_mb"], "number", "hardware.runtime_profile.min_memory_mb", errors)
            if "max_temperature_celsius" in rp:
                _check_type(rp["max_temperature_celsius"], "number", "hardware.runtime_profile.max_temperature_celsius", errors)
            if "max_power_watts" in rp:
                _check_type(rp["max_power_watts"], "number", "hardware.runtime_profile.max_power_watts", errors)
            if "expected_topology" in rp:
                _check_type(rp["expected_topology"], "string", "hardware.runtime_profile.expected_topology", errors)
            if "expected_accelerator" in rp:
                _check_type(rp["expected_accelerator"], "string", "hardware.runtime_profile.expected_accelerator", errors)
        elif rp is not None:
            errors.append(ValidationError("hardware.runtime_profile", "must be a YAML mapping", "error"))

    # Section key validation
    for section, valid_keys in _SECTION_SCHEMAS.items():
        sec = raw.get(section)
        if isinstance(sec, dict):
            for key in sec:
                if key not in valid_keys:
                    errors.append(ValidationError(f"{section}.{key}", "unknown key", "error"))

    # MCP policy chain density validation
    mcp = raw.get("mcp_policy")
    if isinstance(mcp, dict):
        if "max_velocity" in mcp:
            if not isinstance(mcp["max_velocity"], str):
                errors.append(ValidationError("mcp_policy.max_velocity", "expected string", "error"))
            elif not _re_velocity(mcp["max_velocity"]):
                errors.append(ValidationError("mcp_policy.max_velocity", 'must match "N/Xs" format (e.g., "4/30s")', "error"))
        if "max_chain_depth" in mcp:
            if not isinstance(mcp["max_chain_depth"], (int, float)):
                errors.append(ValidationError("mcp_policy.max_chain_depth", "expected number", "error"))
            elif mcp["max_chain_depth"] < 1:
                errors.append(ValidationError("mcp_policy.max_chain_depth", "must be >= 1", "error"))
        if "max_tokens_per_session" in mcp:
            if not isinstance(mcp["max_tokens_per_session"], (int, float)):
                errors.append(ValidationError("mcp_policy.max_tokens_per_session", "expected number", "error"))
            elif mcp["max_tokens_per_session"] < 1:
                errors.append(ValidationError("mcp_policy.max_tokens_per_session", "must be >= 1", "error"))
        if "tool_allowlist" in mcp:
            _check_type(mcp["tool_allowlist"], "string[]", "mcp_policy.tool_allowlist", errors)
        if "tool_blocklist" in mcp:
            _check_type(mcp["tool_blocklist"], "string[]", "mcp_policy.tool_blocklist", errors)
        if "fail_secure" in mcp:
            _check_type(mcp["fail_secure"], "boolean", "mcp_policy.fail_secure", errors)
        if "rules" in mcp:
            if not isinstance(mcp["rules"], list):
                errors.append(ValidationError("mcp_policy.rules", "expected array", "error"))
            else:
                for i, rule in enumerate(mcp["rules"]):
                    prefix = f"mcp_policy.rules[{i}]"
                    if not isinstance(rule, dict):
                        errors.append(ValidationError(prefix, "expected object", "error"))
                        continue
                    if not isinstance(rule.get("match"), str):
                        errors.append(ValidationError(f"{prefix}.match", "required string", "error"))
                    if rule.get("action") not in ("block", "log"):
                        errors.append(ValidationError(f"{prefix}.action", 'must be "block" or "log"', "error"))
                    if not isinstance(rule.get("reason"), str):
                        errors.append(ValidationError(f"{prefix}.reason", "required string", "error"))

    # Policy type checks
    pol = raw.get("policy")
    if isinstance(pol, dict):
        if "require_signing" in pol:
            _check_type(pol["require_signing"], "boolean", "policy.require_signing", errors)
        if "min_clearing_level" in pol:
            _check_type(pol["min_clearing_level"], "number", "policy.min_clearing_level", errors)
        if "require_agent_id" in pol:
            _check_type(pol["require_agent_id"], "boolean", "policy.require_agent_id", errors)

    # Numeric range validation
    if "buffer_size" in raw and isinstance(raw["buffer_size"], (int, float)) and raw["buffer_size"] < 1:
        errors.append(ValidationError("buffer_size", "must be >= 1", "error"))
    if "flush_interval" in raw and isinstance(raw["flush_interval"], (int, float)) and raw["flush_interval"] < 0.1:
        errors.append(ValidationError("flush_interval", "must be >= 0.1", "error"))
    if "max_retries" in raw and isinstance(raw["max_retries"], (int, float)) and raw["max_retries"] < 0:
        errors.append(ValidationError("max_retries", "must be >= 0", "error"))
    if isinstance(tm, dict):
        if "min_trust_level" in tm and isinstance(tm["min_trust_level"], (int, float)):
            if tm["min_trust_level"] < 0 or tm["min_trust_level"] > 4:
                errors.append(ValidationError("trust_mesh.min_trust_level", "must be 0-4", "error"))
        if "freshness_window" in tm and isinstance(tm["freshness_window"], (int, float)):
            if tm["freshness_window"] < 1:
                errors.append(ValidationError("trust_mesh.freshness_window", "must be >= 1", "error"))

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )
