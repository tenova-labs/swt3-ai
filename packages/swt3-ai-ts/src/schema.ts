/**
 * SWT3 YAML schema validator.
 *
 * Validates a raw parsed YAML config against the SWT3 schema.
 * Used by `swt3 doctor` and available as a public API for CI/CD.
 */

export interface ValidationError {
  path: string;
  message: string;
  severity: "error" | "warning";
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationError[];
}

const KNOWN_TOP_LEVEL = new Set([
  "api_key", "api_key_env", "tenant_id", "clearing_level", "endpoint",
  "buffer_size", "flush_interval", "max_retries", "latency_threshold_ms",
  "guardrails_required", "guardrail_names", "factor_handoff", "factor_handoff_path",
  "agent_id", "signing_key", "signing_key_env", "signing_key_id", "signing_key_version",
  "cycle_id", "policy_version", "jurisdiction", "legal_basis", "purpose_class",
  "on_flush", "gateway_mode", "wal_path", "replay_window",
  "token_budget", "procedures", "strict",
  "policy", "trust_mesh", "hardware", "density_policy", "mcp_policy",
  "merkle", "skill_card", "digest_algorithm", "profile", "extends",
]);

const VALID_POLICY_KEYS = new Set([
  "require_signing", "min_clearing_level", "required_procedures",
  "require_agent_id", "max_flush_interval", "require_jurisdiction",
]);

const VALID_TRUST_MESH_KEYS = new Set([
  "mode", "min_trust_level", "require_signature", "freshness_window",
  "trusted_tenants", "trusted_agents", "deny_agents", "deny_tenants",
  "required_procedures", "signing_keys",
]);

const VALID_HARDWARE_KEYS = new Set([
  "require_attestation", "attestation_freshness", "allowed_methods", "runtime_profile",
]);

const VALID_RUNTIME_PROFILE_KEYS = new Set([
  "expected_topology", "min_gpu_count", "min_memory_mb",
  "expected_accelerator", "max_temperature_celsius", "max_power_watts",
]);

const VALID_ATTESTATION_METHODS = new Set([
  "tpm_2.0", "secure_enclave", "sgx", "sev", "trustzone", "nitro", "cerebras_wse3",
]);

const VALID_DENSITY_POLICY_KEYS = new Set([
  "min_anchors_per_1000_tokens", "required_providers",
  "max_chain_gap_seconds", "require_signing_key", "min_trust_level",
]);

const VALID_MCP_POLICY_KEYS = new Set([
  "witnessed_tools", "exempt_tools", "require_trust_level",
  "auto_witness", "block_on_failure",
  "max_velocity", "max_chain_depth", "tool_allowlist", "tool_blocklist",
  "fail_secure", "rules", "max_tokens_per_session",
]);

const VALID_MERKLE_KEYS = new Set(["enabled", "accumulator_interval"]);

const VALID_SKILL_CARD_KEYS = new Set(["skills", "expected_manifest_hash"]);

const SECTION_SCHEMAS: Record<string, Set<string>> = {
  policy: VALID_POLICY_KEYS,
  trust_mesh: VALID_TRUST_MESH_KEYS,
  hardware: VALID_HARDWARE_KEYS,
  density_policy: VALID_DENSITY_POLICY_KEYS,
  mcp_policy: VALID_MCP_POLICY_KEYS,
  merkle: VALID_MERKLE_KEYS,
  skill_card: VALID_SKILL_CARD_KEYS,
};

function checkType(value: unknown, expected: string, path: string, errors: ValidationError[]): boolean {
  if (expected === "number" && typeof value !== "number") {
    errors.push({ path, message: `expected number, got ${typeof value}`, severity: "error" });
    return false;
  }
  if (expected === "boolean" && typeof value !== "boolean") {
    errors.push({ path, message: `expected boolean, got ${typeof value}`, severity: "error" });
    return false;
  }
  if (expected === "string" && typeof value !== "string") {
    errors.push({ path, message: `expected string, got ${typeof value}`, severity: "error" });
    return false;
  }
  if (expected === "string[]" && (!Array.isArray(value) || !value.every((v) => typeof v === "string"))) {
    errors.push({ path, message: `expected string array`, severity: "error" });
    return false;
  }
  return true;
}

function editDistance(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function suggestKey(key: string, validKeys: Set<string>): string | null {
  let best: string | null = null;
  let bestDist = 3; // max distance to suggest
  for (const valid of validKeys) {
    const d = editDistance(key, valid);
    if (d < bestDist) { bestDist = d; best = valid; }
  }
  return best;
}

export function validateSchema(raw: Record<string, unknown>): ValidationResult {
  const errors: ValidationError[] = [];
  const warnings: ValidationError[] = [];

  // Top-level key check with did-you-mean suggestions
  for (const key of Object.keys(raw)) {
    if (!KNOWN_TOP_LEVEL.has(key)) {
      const suggestion = suggestKey(key, KNOWN_TOP_LEVEL);
      const msg = suggestion
        ? `unknown top-level key (did you mean "${suggestion}"?)`
        : `unknown top-level key`;
      errors.push({ path: key, message: msg, severity: "error" });
    }
  }

  // clearing_level: must be 0-3
  if ("clearing_level" in raw) {
    const cl = raw.clearing_level;
    if (typeof cl !== "number" || ![0, 1, 2, 3].includes(cl)) {
      errors.push({ path: "clearing_level", message: "must be 0, 1, 2, or 3", severity: "error" });
    }
  }

  // digest_algorithm: only sha256 in this version
  if ("digest_algorithm" in raw) {
    const da = raw.digest_algorithm;
    if (typeof da !== "string") {
      errors.push({ path: "digest_algorithm", message: "expected string", severity: "error" });
    } else if (da !== "sha256") {
      errors.push({ path: "digest_algorithm", message: `only "sha256" is supported in this version`, severity: "error" });
    }
  }

  // trust_mesh.mode enum
  const tm = raw.trust_mesh as Record<string, unknown> | undefined;
  if (tm && typeof tm === "object") {
    if ("mode" in tm && !["strict", "permissive", "monitor"].includes(tm.mode as string)) {
      errors.push({ path: "trust_mesh.mode", message: "must be strict, permissive, or monitor", severity: "error" });
    }
    if ("min_trust_level" in tm) checkType(tm.min_trust_level, "number", "trust_mesh.min_trust_level", errors);
    if ("require_signature" in tm) checkType(tm.require_signature, "boolean", "trust_mesh.require_signature", errors);
    if ("freshness_window" in tm) checkType(tm.freshness_window, "number", "trust_mesh.freshness_window", errors);
    if ("trusted_tenants" in tm) checkType(tm.trusted_tenants, "string[]", "trust_mesh.trusted_tenants", errors);
    if ("deny_agents" in tm) checkType(tm.deny_agents, "string[]", "trust_mesh.deny_agents", errors);
  }

  // hardware.allowed_methods enum validation
  const hw = raw.hardware as Record<string, unknown> | undefined;
  if (hw && typeof hw === "object") {
    if ("allowed_methods" in hw && Array.isArray(hw.allowed_methods)) {
      for (const method of hw.allowed_methods) {
        if (typeof method === "string" && !VALID_ATTESTATION_METHODS.has(method)) {
          const valid = [...VALID_ATTESTATION_METHODS].sort().join(", ");
          errors.push({
            path: "hardware.allowed_methods",
            message: `unknown attestation method "${method}". Valid: ${valid}`,
            severity: "error",
          });
        }
      }
    }
    // hardware.runtime_profile nested validation
    if ("runtime_profile" in hw) {
      const rp = hw.runtime_profile as Record<string, unknown> | undefined;
      if (rp && typeof rp === "object" && !Array.isArray(rp)) {
        for (const key of Object.keys(rp)) {
          if (!VALID_RUNTIME_PROFILE_KEYS.has(key)) {
            const suggestion = suggestKey(key, VALID_RUNTIME_PROFILE_KEYS);
            const msg = suggestion
              ? `unknown key (did you mean "${suggestion}"?)`
              : "unknown key";
            errors.push({ path: `hardware.runtime_profile.${key}`, message: msg, severity: "error" });
          }
        }
        if ("min_gpu_count" in rp) checkType(rp.min_gpu_count, "number", "hardware.runtime_profile.min_gpu_count", errors);
        if ("min_memory_mb" in rp) checkType(rp.min_memory_mb, "number", "hardware.runtime_profile.min_memory_mb", errors);
        if ("max_temperature_celsius" in rp) checkType(rp.max_temperature_celsius, "number", "hardware.runtime_profile.max_temperature_celsius", errors);
        if ("max_power_watts" in rp) checkType(rp.max_power_watts, "number", "hardware.runtime_profile.max_power_watts", errors);
        if ("expected_topology" in rp) checkType(rp.expected_topology, "string", "hardware.runtime_profile.expected_topology", errors);
        if ("expected_accelerator" in rp) checkType(rp.expected_accelerator, "string", "hardware.runtime_profile.expected_accelerator", errors);
      } else if (rp !== undefined) {
        errors.push({ path: "hardware.runtime_profile", message: "must be a YAML mapping", severity: "error" });
      }
    }
  }

  // Section key validation
  for (const [section, validKeys] of Object.entries(SECTION_SCHEMAS)) {
    const sec = raw[section] as Record<string, unknown> | undefined;
    if (sec && typeof sec === "object" && !Array.isArray(sec)) {
      for (const key of Object.keys(sec)) {
        if (!validKeys.has(key)) {
          errors.push({ path: `${section}.${key}`, message: "unknown key", severity: "error" });
        }
      }
    }
  }

  // MCP policy chain density validation
  const mcp = raw.mcp_policy as Record<string, unknown> | undefined;
  if (mcp && typeof mcp === "object") {
    if ("max_velocity" in mcp) {
      if (typeof mcp.max_velocity !== "string") {
        errors.push({ path: "mcp_policy.max_velocity", message: "expected string", severity: "error" });
      } else if (!/^\d+\/\d+s$/.test(mcp.max_velocity)) {
        errors.push({ path: "mcp_policy.max_velocity", message: 'must match "N/Xs" format (e.g., "4/30s")', severity: "error" });
      }
    }
    if ("max_chain_depth" in mcp) {
      if (typeof mcp.max_chain_depth !== "number") {
        errors.push({ path: "mcp_policy.max_chain_depth", message: "expected number", severity: "error" });
      } else if (mcp.max_chain_depth < 1) {
        errors.push({ path: "mcp_policy.max_chain_depth", message: "must be >= 1", severity: "error" });
      }
    }
    if ("max_tokens_per_session" in mcp) {
      if (typeof mcp.max_tokens_per_session !== "number") {
        errors.push({ path: "mcp_policy.max_tokens_per_session", message: "expected number", severity: "error" });
      } else if (mcp.max_tokens_per_session < 1) {
        errors.push({ path: "mcp_policy.max_tokens_per_session", message: "must be >= 1", severity: "error" });
      }
    }
    if ("tool_allowlist" in mcp) checkType(mcp.tool_allowlist, "string[]", "mcp_policy.tool_allowlist", errors);
    if ("tool_blocklist" in mcp) checkType(mcp.tool_blocklist, "string[]", "mcp_policy.tool_blocklist", errors);
    if ("fail_secure" in mcp) checkType(mcp.fail_secure, "boolean", "mcp_policy.fail_secure", errors);
    if ("rules" in mcp) {
      if (!Array.isArray(mcp.rules)) {
        errors.push({ path: "mcp_policy.rules", message: "expected array", severity: "error" });
      } else {
        for (let i = 0; i < mcp.rules.length; i++) {
          const rule = mcp.rules[i] as Record<string, unknown>;
          const prefix = `mcp_policy.rules[${i}]`;
          if (!rule || typeof rule !== "object") {
            errors.push({ path: prefix, message: "expected object", severity: "error" });
            continue;
          }
          if (typeof rule.match !== "string") {
            errors.push({ path: `${prefix}.match`, message: "required string", severity: "error" });
          }
          if (typeof rule.action !== "string" || !["block", "log"].includes(rule.action)) {
            errors.push({ path: `${prefix}.action`, message: 'must be "block" or "log"', severity: "error" });
          }
          if (typeof rule.reason !== "string") {
            errors.push({ path: `${prefix}.reason`, message: "required string", severity: "error" });
          }
        }
      }
    }
  }

  // Policy type checks
  const pol = raw.policy as Record<string, unknown> | undefined;
  if (pol && typeof pol === "object") {
    if ("require_signing" in pol) checkType(pol.require_signing, "boolean", "policy.require_signing", errors);
    if ("min_clearing_level" in pol) checkType(pol.min_clearing_level, "number", "policy.min_clearing_level", errors);
    if ("require_agent_id" in pol) checkType(pol.require_agent_id, "boolean", "policy.require_agent_id", errors);
  }

  // Numeric range validation
  if ("buffer_size" in raw && typeof raw.buffer_size === "number" && raw.buffer_size < 1) {
    errors.push({ path: "buffer_size", message: "must be >= 1", severity: "error" });
  }
  if ("flush_interval" in raw && typeof raw.flush_interval === "number" && raw.flush_interval < 0.1) {
    errors.push({ path: "flush_interval", message: "must be >= 0.1", severity: "error" });
  }
  if ("max_retries" in raw && typeof raw.max_retries === "number" && raw.max_retries < 0) {
    errors.push({ path: "max_retries", message: "must be >= 0", severity: "error" });
  }
  if (tm && typeof tm === "object") {
    if ("min_trust_level" in tm && typeof tm.min_trust_level === "number" && (tm.min_trust_level < 0 || tm.min_trust_level > 4)) {
      errors.push({ path: "trust_mesh.min_trust_level", message: "must be 0-4", severity: "error" });
    }
    if ("freshness_window" in tm && typeof tm.freshness_window === "number" && tm.freshness_window < 1) {
      errors.push({ path: "trust_mesh.freshness_window", message: "must be >= 1", severity: "error" });
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
