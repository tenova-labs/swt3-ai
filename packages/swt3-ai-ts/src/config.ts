/**
 * SWT3 AI Witness SDK -- .swt3.yaml policy-as-code loader.
 *
 * Load witnessing policy from a YAML config file instead of passing
 * 25+ parameters in code. Secrets are resolved from environment variables
 * using the `_env` suffix convention -- they never appear in the YAML file.
 *
 * Usage:
 *   import { Witness } from "@tenova/swt3-ai";
 *
 *   const witness = Witness.fromConfig();              // auto-finds .swt3.yaml
 *   const witness = Witness.fromConfig("prod.yaml");   // explicit path
 *   const witness = Witness.fromConfig(undefined, { clearingLevel: 3 });
 *
 * Requires: `npm install yaml`
 */

import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validateSchema as runSchemaValidation } from "./schema.js";
import type { WitnessOptions } from "./witness.js";
import type {
  TrustMeshConfig, HardwareConfig, DensityPolicyConfig, McpPolicyConfig, MerkleConfig, PolicyConfig, LoadedConfig,
} from "./types.js";

/** Snake_case to camelCase key mapping for YAML -> WitnessOptions. */
const KEY_MAP: Record<string, string> = {
  api_key: "apiKey",
  tenant_id: "tenantId",
  clearing_level: "clearingLevel",
  buffer_size: "bufferSize",
  flush_interval: "flushInterval",
  max_retries: "maxRetries",
  latency_threshold_ms: "latencyThresholdMs",
  guardrails_required: "guardrailsRequired",
  guardrail_names: "guardrailNames",
  factor_handoff: "factorHandoff",
  factor_handoff_path: "factorHandoffPath",
  agent_id: "agentId",
  signing_key: "signingKey",
  signing_key_id: "signingKeyId",
  signing_key_version: "signingKeyVersion",
  signing_algorithm: "signingAlgorithm",
  cycle_id: "cycleId",
  policy_version: "policyVersion",
  legal_basis: "legalBasis",
  purpose_class: "purposeClass",
  on_flush: "onFlush",
  gateway_mode: "gatewayMode",
  wal_path: "walPath",
  replay_window: "replayWindow",
  token_budget: "tokenBudget",
  digest_algorithm: "digestAlgorithm",
};

/** Env-suffix fields that resolve from process.env. */
const ENV_FIELDS: Record<string, string> = {
  api_key_env: "apiKey",
  signing_key_env: "signingKey",
};

/** Top-level sections extracted before key mapping. */
const SECTION_KEYS = new Set(["policy", "trust_mesh", "hardware", "density_policy", "mcp_policy", "merkle", "skill_card", "profile"]);

// ── Typo Protection Sets ──────────────────────────────────────────────

const VALID_POLICY_KEYS = new Set([
  "require_signing",
  "min_clearing_level",
  "required_procedures",
  "require_agent_id",
  "max_flush_interval",
  "require_jurisdiction",
]);

const VALID_TRUST_MESH_KEYS = new Set([
  "mode", "min_trust_level", "require_signature", "freshness_window",
  "require_intra_tenant_signing", "verify_boolean_claims",
  "rate_limit_max_failures", "rate_limit_window_seconds", "per_level_freshness",
  "trusted_tenants", "trusted_agents", "deny_agents", "deny_tenants",
  "required_procedures", "signing_keys",
]);

const VALID_HARDWARE_KEYS = new Set([
  "require_attestation", "attestation_freshness", "allowed_methods", "runtime_profile",
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

const VALID_MERKLE_KEYS = new Set([
  "enabled", "accumulator_interval",
]);

const VALID_PROFILES = new Set([
  "cost-conscious",
  "eu-ai-act-high-risk",
  "granite-sovereign",
  "mythos-defense",
  "nist-ai-rmf",
  "owasp-agentic-top10",
  "telecom-compliance",
  "healthcare-clinical",
  "fintech-model-risk",
  "defense-govcon",
  "autonomous-systems",
  "insurance-underwriting",
  "content-platform",
  "microsoft-foundry",
  "minimal",
  "multi-silicon",
]);

// ── YAML Parsing ──────────────────────────────────────────────────────

function getYamlParser(): (input: string) => unknown {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yamlMod = require("yaml");
    return yamlMod.parse;
  } catch {
    throw new Error(
      "The 'yaml' package is required for .swt3.yaml support. " +
      "Install it with: npm install yaml",
    );
  }
}

function findConfig(path?: string): string {
  if (path) {
    if (!existsSync(path)) {
      throw new Error(`SWT3 config file not found: ${path}`);
    }
    return path;
  }
  for (const name of ["swt3.yaml", ".swt3.yaml"]) {
    if (existsSync(name)) return name;
  }
  throw new Error(
    "No SWT3 config file found. Create swt3.yaml or .swt3.yaml, " +
    "or pass an explicit path to loadConfig().",
  );
}

// ── Extends / Composition ─────────────────────────────────────────────

const MAX_EXTENDS_DEPTH = 10;

function processExtends(
  raw: Record<string, unknown>,
  configDir: string,
  parse: (input: string) => unknown,
  visited: Set<string> = new Set(),
  depth: number = 0,
  rootDir?: string,
): { merged: Record<string, unknown>; extendedContents: string[] } {
  const extendsVal = raw.extends as string | string[] | undefined;
  if (!extendsVal) return { merged: raw, extendedContents: [] };
  delete raw.extends;

  if (depth >= MAX_EXTENDS_DEPTH) {
    throw new Error(`Extends depth limit exceeded (max ${MAX_EXTENDS_DEPTH})`);
  }

  // The root directory is the top-level config file's parent -- set on first call
  const boundary = rootDir ?? configDir;

  const files = Array.isArray(extendsVal) ? extendsVal : [extendsVal];
  let base: Record<string, unknown> = {};
  const allContents: string[] = [];

  for (const file of files) {
    const isAbsolute = file.startsWith("/");
    const resolved = isAbsolute
      ? file
      : join(configDir, file);

    if (!existsSync(resolved)) {
      throw new Error(`Extends file not found: ${file} (resolved: ${resolved})`);
    }

    const real = require("node:fs").realpathSync(resolved);

    // Path containment: relative paths must resolve within the root config directory tree
    if (!isAbsolute) {
      const realBoundary = require("node:fs").realpathSync(boundary);
      if (!real.startsWith(realBoundary + "/") && real !== realBoundary) {
        throw new Error(
          `Extends path escapes config directory: ${file} (resolved: ${real}). ` +
          `Use an absolute path if this is intentional.`
        );
      }
    }

    if (visited.has(real)) {
      throw new Error(`Circular extends detected: ${file} (resolved: ${real})`);
    }

    visited.add(real);
    const content = readFileSync(resolved, "utf-8");
    allContents.push(content);

    let parentRaw = parse(content) as Record<string, unknown>;
    if (!parentRaw || typeof parentRaw !== "object") {
      throw new Error(`Invalid extends file: ${file} (expected a YAML mapping)`);
    }

    const parentDir = dirname(resolved);
    const parentResult = processExtends(parentRaw, parentDir, parse, visited, depth + 1, boundary);
    allContents.unshift(...parentResult.extendedContents);
    parentRaw = parentResult.merged;

    base = deepMerge(base, parentRaw);
  }

  return { merged: deepMerge(base, raw), extendedContents: allContents };
}

// ── Section Helpers ───────────────────────────────────────────────────

function validateKeys(section: Record<string, unknown>, validKeys: Set<string>, sectionName: string): void {
  const unknown = Object.keys(section).filter((k) => !validKeys.has(k));
  if (unknown.length > 0) {
    throw new Error(`Unknown ${sectionName} keys: ${unknown.sort().join(", ")}`);
  }
}

interface Policy {
  require_signing?: boolean;
  min_clearing_level?: number;
  required_procedures?: string[];
  require_agent_id?: boolean;
  max_flush_interval?: number;
  require_jurisdiction?: boolean;
}

function extractPolicy(raw: Record<string, unknown>): Policy | null {
  const policy = raw.policy as Record<string, unknown> | undefined;
  if (!policy) return null;
  delete raw.policy;

  if (typeof policy !== "object" || Array.isArray(policy)) {
    throw new Error("'policy' must be a YAML mapping");
  }

  validateKeys(policy, VALID_POLICY_KEYS, "policy");
  return policy as Policy;
}

function extractTrustMesh(raw: Record<string, unknown>): TrustMeshConfig | null {
  const section = raw.trust_mesh as Record<string, unknown> | undefined;
  if (!section) return null;
  delete raw.trust_mesh;

  if (typeof section !== "object" || Array.isArray(section)) {
    throw new Error("'trust_mesh' must be a YAML mapping");
  }

  validateKeys(section, VALID_TRUST_MESH_KEYS, "trust_mesh");

  const mode = (section.mode as string) ?? "permissive";
  if (!["strict", "permissive", "monitor"].includes(mode)) {
    throw new Error(`trust_mesh.mode must be strict, permissive, or monitor (got: ${mode})`);
  }

  // Resolve signing_keys _env references
  const rawKeys = (section.signing_keys as Array<{ agent: string; key_env: string }>) ?? [];
  const resolvedKeys = rawKeys.map((entry) => {
    if (!entry.agent) throw new Error("trust_mesh.signing_keys[].agent is required");
    if (!entry.key_env) throw new Error("trust_mesh.signing_keys[].key_env is required");
    const value = process.env[entry.key_env];
    if (!value) {
      throw new Error(`Environment variable '${entry.key_env}' (from trust_mesh.signing_keys) is not set`);
    }
    return { agent: entry.agent, key: value };
  });

  // Validate trusted_agents structure
  const trustedAgents = (section.trusted_agents as Array<{ tenant: string; agent: string }>) ?? [];
  for (const ta of trustedAgents) {
    if (!ta.tenant || !ta.agent) {
      throw new Error("trust_mesh.trusted_agents entries must have 'tenant' and 'agent' fields");
    }
  }

  return {
    mode: mode as "strict" | "permissive" | "monitor",
    minTrustLevel: (section.min_trust_level as number) ?? 1,
    requireSignature: (section.require_signature as boolean) ?? false,
    freshnessWindow: (section.freshness_window as number) ?? 86400,
    requireIntraTenantSigning: (section.require_intra_tenant_signing as boolean) ?? false,
    verifyBooleanClaims: (section.verify_boolean_claims as boolean) ?? false,
    rateLimitMaxFailures: (section.rate_limit_max_failures as number) ?? 0,
    rateLimitWindowSeconds: (section.rate_limit_window_seconds as number) ?? 60,
    perLevelFreshness: (section.per_level_freshness as Record<string, number>) ?? null,
    trustedTenants: (section.trusted_tenants as string[]) ?? [],
    trustedAgents,
    denyAgents: (section.deny_agents as string[]) ?? [],
    denyTenants: (section.deny_tenants as string[]) ?? [],
    requiredProcedures: (section.required_procedures as string[]) ?? [],
    signingKeys: resolvedKeys,
  };
}

function extractHardware(raw: Record<string, unknown>): HardwareConfig | null {
  const section = raw.hardware as Record<string, unknown> | undefined;
  if (!section) return null;
  delete raw.hardware;

  if (typeof section !== "object" || Array.isArray(section)) {
    throw new Error("'hardware' must be a YAML mapping");
  }

  // Extract runtime_profile before validateKeys (it's a nested object, not a flat key)
  const rp = section.runtime_profile as Record<string, unknown> | undefined;
  delete section.runtime_profile;

  validateKeys(section, VALID_HARDWARE_KEYS, "hardware");

  let runtimeProfile: import("./types.js").RuntimeProfileConfig | undefined;
  if (rp && typeof rp === "object" && !Array.isArray(rp)) {
    runtimeProfile = {
      expectedTopology: rp.expected_topology as string | undefined,
      minGpuCount: rp.min_gpu_count as number | undefined,
      minMemoryMb: rp.min_memory_mb as number | undefined,
      expectedAccelerator: rp.expected_accelerator as string | undefined,
      expectedSiliconVendor: rp.expected_silicon_vendor as string | undefined,
      maxTemperatureCelsius: rp.max_temperature_celsius as number | undefined,
      maxPowerWatts: rp.max_power_watts as number | undefined,
    };
  }

  return {
    requireAttestation: (section.require_attestation as boolean) ?? false,
    attestationFreshness: (section.attestation_freshness as number) ?? 3600,
    allowedMethods: (section.allowed_methods as string[]) ?? [],
    runtimeProfile,
  };
}

function extractDensityPolicy(raw: Record<string, unknown>): DensityPolicyConfig | null {
  const section = raw.density_policy as Record<string, unknown> | undefined;
  if (!section) return null;
  delete raw.density_policy;

  if (typeof section !== "object" || Array.isArray(section)) {
    throw new Error("'density_policy' must be a YAML mapping");
  }

  validateKeys(section, VALID_DENSITY_POLICY_KEYS, "density_policy");

  return {
    minAnchorsPerThousandTokens: (section.min_anchors_per_1000_tokens as number) ?? 1,
    requiredProviders: (section.required_providers as string[]) ?? [],
    maxChainGapSeconds: (section.max_chain_gap_seconds as number) ?? 60,
    requireSigningKey: (section.require_signing_key as boolean) ?? false,
    minTrustLevel: (section.min_trust_level as number) ?? 1,
  };
}

function extractMcpPolicy(raw: Record<string, unknown>): McpPolicyConfig | null {
  const section = raw.mcp_policy as Record<string, unknown> | undefined;
  if (!section) return null;
  delete raw.mcp_policy;

  if (typeof section !== "object" || Array.isArray(section)) {
    throw new Error("'mcp_policy' must be a YAML mapping");
  }

  validateKeys(section, VALID_MCP_POLICY_KEYS, "mcp_policy");

  const rawRules = (section.rules as Array<Record<string, unknown>>) ?? [];
  const rules = rawRules.map((r) => ({
    match: (r.match as string) ?? "*",
    action: (r.action as "block" | "log") ?? "block",
    reason: (r.reason as string) ?? "",
    ...(r.params ? { params: r.params as Record<string, unknown> } : {}),
  }));

  return {
    witnessedTools: (section.witnessed_tools as string[]) ?? [],
    exemptTools: (section.exempt_tools as string[]) ?? [],
    requireTrustLevel: (section.require_trust_level as number) ?? 0,
    autoWitness: (section.auto_witness as boolean) ?? true,
    blockOnFailure: (section.block_on_failure as boolean) ?? false,
    maxVelocity: section.max_velocity as string | undefined,
    maxChainDepth: section.max_chain_depth as number | undefined,
    toolAllowlist: (section.tool_allowlist as string[]) ?? [],
    toolBlocklist: (section.tool_blocklist as string[]) ?? [],
    failSecure: (section.fail_secure as boolean) ?? true,
    rules,
    maxTokensPerSession: section.max_tokens_per_session as number | undefined,
  };
}

function extractMerkle(raw: Record<string, unknown>): MerkleConfig | null {
  const section = raw.merkle as Record<string, unknown> | undefined;
  if (!section) return null;
  delete raw.merkle;

  if (typeof section !== "object" || Array.isArray(section)) {
    throw new Error("'merkle' must be a YAML mapping");
  }

  validateKeys(section, VALID_MERKLE_KEYS, "merkle");

  return {
    enabled: (section.enabled as boolean) ?? true,
    accumulatorInterval: (section.accumulator_interval as number) ?? 0,
  };
}

const VALID_SKILL_CARD_KEYS = new Set(["skills", "expected_manifest_hash"]);

function extractSkillCard(raw: Record<string, unknown>): import("./types.js").SkillCardConfig | null {
  const section = raw.skill_card as Record<string, unknown> | undefined;
  if (!section) return null;
  delete raw.skill_card;

  if (typeof section !== "object" || Array.isArray(section)) {
    throw new Error("'skill_card' must be a YAML mapping");
  }

  validateKeys(section, VALID_SKILL_CARD_KEYS, "skill_card");

  const rawSkills = section.skills as unknown[] | undefined;
  if (!rawSkills || !Array.isArray(rawSkills) || rawSkills.length === 0) {
    return null;
  }

  const skills = rawSkills.map((s) => {
    if (typeof s === "string") return s;
    if (typeof s === "object" && s !== null) {
      const obj = s as Record<string, unknown>;
      return {
        name: obj.name as string,
        version: obj.version as string | undefined,
        skillHash: (obj.skill_hash ?? obj.skillHash) as string | undefined,
      };
    }
    return String(s);
  });

  return {
    skills,
    expectedManifestHash: section.expected_manifest_hash as string | undefined,
  };
}

// ── Profile / Template System ─────────────────────────────────────────

function deepMerge(
  base: Record<string, unknown>,
  override: Record<string, unknown>,
): Record<string, unknown> {
  const result = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (
      value && typeof value === "object" && !Array.isArray(value) &&
      result[key] && typeof result[key] === "object" && !Array.isArray(result[key])
    ) {
      result[key] = deepMerge(
        result[key] as Record<string, unknown>,
        value as Record<string, unknown>,
      );
    } else {
      result[key] = value;
    }
  }
  return result;
}

function loadProfile(profileName: string, parse: (input: string) => unknown): Record<string, unknown> {
  if (!VALID_PROFILES.has(profileName)) {
    throw new Error(
      `Unknown profile: '${profileName}'. Valid profiles: ${[...VALID_PROFILES].sort().join(", ")}`,
    );
  }
  let templatesDir: string;
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    templatesDir = join(__dirname, "..", "templates");
  } catch {
    templatesDir = join(__dirname, "..", "templates");
  }
  const templatePath = join(templatesDir, `${profileName}.yaml`);
  if (!existsSync(templatePath)) {
    throw new Error(`Profile template not found: ${templatePath}`);
  }
  const content = readFileSync(templatePath, "utf-8");
  const tmpl = parse(content) as Record<string, unknown>;
  if (!tmpl || typeof tmpl !== "object") {
    throw new Error(`Invalid profile template: ${profileName}`);
  }
  return tmpl;
}

// ── Policy Validation ─────────────────────────────────────────────────

export function validatePolicy(config: Record<string, unknown>, policy: Policy): void {
  if (policy.require_signing && !config.signingKey) {
    throw new Error(
      "Policy violation: require_signing is true but no signing_key configured",
    );
  }

  if (policy.min_clearing_level !== undefined) {
    const actual = (config.clearingLevel as number) ?? 1;
    if (actual < policy.min_clearing_level) {
      throw new Error(
        `Policy violation: clearing_level ${actual} is below min_clearing_level ${policy.min_clearing_level}`,
      );
    }
  }

  if (policy.require_agent_id && !config.agentId) {
    throw new Error(
      "Policy violation: require_agent_id is true but no agent_id configured",
    );
  }

  if (policy.require_jurisdiction && !config.jurisdiction) {
    throw new Error(
      "Policy violation: require_jurisdiction is true but no jurisdiction configured",
    );
  }

  if (policy.max_flush_interval !== undefined) {
    const actual = (config.flushInterval as number) ?? 5;
    if (actual > policy.max_flush_interval) {
      throw new Error(
        `Policy violation: flush_interval ${actual}s exceeds max_flush_interval ${policy.max_flush_interval}s`,
      );
    }
  }

  if (policy.required_procedures) {
    const configured = config.procedures as string[] | undefined;
    if (configured !== undefined) {
      const configuredSet = new Set(configured);
      const missing = policy.required_procedures.filter((p) => !configuredSet.has(p));
      if (missing.length > 0) {
        throw new Error(
          `Policy violation: required_procedures [${missing.sort().join(", ")}] not in configured procedures list`,
        );
      }
    }
  }
}

// ── Config Hash ───────────────────────────────────────────────────────

export function computeConfigHash(content: string): string {
  return createHash("sha256").update(content, "utf-8").digest("hex");
}

// ── Public API ────────────────────────────────────────────────────────

/**
 * Load a .swt3.yaml config file and return a WitnessOptions object.
 * Backward-compatible: returns WitnessOptions only (no trust_mesh, hardware, etc.).
 */
export function loadConfig(path?: string): WitnessOptions {
  return loadFullConfig(path).witnessOptions as unknown as WitnessOptions;
}

/**
 * Load a .swt3.yaml config file and return the full parsed config
 * including trust_mesh, hardware, density_policy, and config hash.
 */
export function loadFullConfig(path?: string): LoadedConfig {
  const parse = getYamlParser();

  const configPath = findConfig(path);
  const content = readFileSync(configPath, "utf-8");

  let raw = parse(content) as Record<string, unknown>;

  if (!raw || typeof raw !== "object") {
    throw new Error("Invalid config file: expected a YAML mapping");
  }

  // Extends: load parent files and deep-merge (extends < profile < user config)
  const configDir = dirname(require("node:path").resolve(configPath));
  const realPath = require("node:fs").realpathSync(require("node:path").resolve(configPath));
  // Containment boundary: one level above config dir (allows ../shared.yaml but blocks ../../etc/passwd)
  const extendsRootDir = dirname(configDir);
  const extendsResult = processExtends(raw, configDir, parse, new Set([realPath]), 0, extendsRootDir);
  raw = extendsResult.merged;

  // Config hash: includes all extended files + main file
  const allContents = [...extendsResult.extendedContents, content].join("\n");
  const configHash = computeConfigHash(allContents);

  // Profile: load base template and deep-merge user config on top
  const profileName = raw.profile as string | undefined;
  if (profileName) {
    delete raw.profile;
    const template = loadProfile(profileName, parse);
    raw = deepMerge(template, raw);
  }

  // Schema validation: catch typos and unknown keys before they silently pass through
  const schemaResult = runSchemaValidation(raw);
  if (!schemaResult.valid) {
    const msgs = schemaResult.errors.map((e) => `${e.path}: ${e.message}`);
    throw new Error(`SWT3 config validation failed:\n  ${msgs.join("\n  ")}`);
  }

  // Extract governance sections before key mapping
  const policy = extractPolicy(raw);
  const trustMesh = extractTrustMesh(raw);
  const hardware = extractHardware(raw);
  const skillCard = extractSkillCard(raw);
  const densityPolicy = extractDensityPolicy(raw);
  const mcpPolicy = extractMcpPolicy(raw);
  const merkle = extractMerkle(raw);

  const result: Record<string, unknown> = {};

  // Resolve _env fields from environment
  for (const [envKey, targetKey] of Object.entries(ENV_FIELDS)) {
    if (envKey in raw) {
      const varName = raw[envKey] as string;
      const value = process.env[varName];
      if (!value) {
        throw new Error(
          `Environment variable '${varName}' (from ${envKey}) is not set`,
        );
      }
      result[targetKey] = value;
      delete raw[envKey];
    }
  }

  // Map remaining keys from snake_case to camelCase
  for (const [key, value] of Object.entries(raw)) {
    if (key in ENV_FIELDS) continue;
    if (SECTION_KEYS.has(key)) continue;
    const camelKey = KEY_MAP[key] || key;
    result[camelKey] = value;
  }

  // Validate policy after config is fully resolved
  if (policy) {
    validatePolicy(result, policy);
  }

  // Convert internal Policy to public PolicyConfig (camelCase)
  const policyConfig: PolicyConfig | null = policy ? {
    requireSigning: policy.require_signing,
    minClearingLevel: policy.min_clearing_level,
    requiredProcedures: policy.required_procedures,
    requireAgentId: policy.require_agent_id,
    maxFlushInterval: policy.max_flush_interval,
    requireJurisdiction: policy.require_jurisdiction,
  } : null;

  return {
    witnessOptions: result,
    trustMesh,
    hardware,
    skillCard,
    densityPolicy,
    mcpPolicy,
    merkle,
    policy: policyConfig,
    configHash,
  };
}
