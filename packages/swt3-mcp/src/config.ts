/**
 * SWT3 MCP Server -- Configuration.
 *
 * Priority: env vars > YAML file > defaults
 *
 * Four modes:
 *   1. Demo mode (no env vars, no YAML) -- local-only anchors, no account needed
 *   2. YAML config (SWT3_CONFIG_FILE) -- one file governs MCP + SDK
 *   3. API key only -- tenant auto-resolved from first API call
 *   4. Full config -- API key + explicit tenant ID
 */

import { readFileSync, existsSync } from "node:fs";
import type { DensityPolicy } from "./density-policy.js";

export interface McpConfig {
  endpoint: string;
  apiKey: string;
  tenantId: string;
  clearingLevel: 0 | 1 | 2 | 3;
  agentId?: string;
  signingKey?: string;
  demo: boolean;
  /** Enable chain verification gatekeeper before tool execution. */
  chainVerify: boolean;
  /** Redis URL for stream reader (chain verification fast path). */
  redisUrl: string;
  /** Redis stream name for anchor consumption. */
  redisStream: string;
  /** Maximum seconds between consecutive anchors in a chain. */
  maxChainGapSeconds: number;
  /** SHA-256 hash of the config file (if loaded from YAML). */
  configHash?: string;
}

export interface YamlTrustMesh {
  trustedTenants: string[];
  deniedAgents: string[];
  deniedTenants: string[];
}

export interface McpToolPolicy {
  /** Glob patterns for tools that MUST be witnessed. */
  witnessedTools: string[];
  /** Glob patterns for tools exempt from witnessing. */
  exemptTools: string[];
  /** Minimum trust level required before executing any MCP tool. */
  requireTrustLevel: number;
  /** Auto-witness all MCP tool calls without explicit wrapping. */
  autoWitness: boolean;
  /** Block tool execution if witnessing fails (true) or log-only (false). */
  blockOnFailure: boolean;
  /** Rate limit: "N/Xs" format (e.g., "4/30s"). */
  maxVelocity?: string;
  /** Maximum sequential dependent tool calls. */
  maxChainDepth?: number;
  /** Only these tools are permitted. Empty = all. */
  toolAllowlist?: string[];
  /** These tools are always blocked. */
  toolBlocklist?: string[];
  /** On enforcement error: true = block, false = log. Default true. */
  failSecure?: boolean;
}

export interface McpConfigBundle {
  config: McpConfig;
  densityPolicy: DensityPolicy | null;
  trustMesh: YamlTrustMesh | null;
  mcpPolicy: McpToolPolicy | null;
}

function parseYaml(content: string): unknown {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yamlMod = require("yaml");
    return yamlMod.parse(content);
  } catch {
    throw new Error(
      "The 'yaml' package is required for YAML config. Install it with: npm install yaml",
    );
  }
}

/**
 * Load config from YAML file + env var overrides.
 * Returns the full bundle: McpConfig + DensityPolicy + TrustMesh.
 */
function loadFromYaml(yamlPath: string): McpConfigBundle {
  if (!existsSync(yamlPath)) {
    throw new Error(`SWT3 config file not found: ${yamlPath}`);
  }

  const content = readFileSync(yamlPath, "utf-8");
  const { createHash } = require("node:crypto");
  const configHash = createHash("sha256").update(content, "utf-8").digest("hex");

  const raw = parseYaml(content) as Record<string, unknown>;
  if (!raw || typeof raw !== "object") {
    throw new Error("Invalid config file: expected a YAML mapping");
  }

  // Resolve _env fields
  let apiKey = (raw.api_key as string) || "";
  if (raw.api_key_env) {
    apiKey = process.env[raw.api_key_env as string] || "";
  }
  let signingKey = (raw.signing_key as string) || undefined;
  if (raw.signing_key_env) {
    signingKey = process.env[raw.signing_key_env as string] || undefined;
  }

  // Extract sections
  const trustMeshRaw = raw.trust_mesh as Record<string, unknown> | undefined;
  const densityRaw = raw.density_policy as Record<string, unknown> | undefined;
  const mcpPolicyRaw = raw.mcp_policy as Record<string, unknown> | undefined;

  // Build McpConfig (env vars override YAML)
  const endpoint = process.env.SWT3_ENDPOINT || (raw.endpoint as string) || "https://sovereign.tenova.io";
  apiKey = process.env.SWT3_API_KEY || apiKey;
  const tenantId = process.env.SWT3_TENANT_ID || (raw.tenant_id as string) || "";
  const agentId = process.env.SWT3_AGENT_ID || (raw.agent_id as string) || undefined;
  signingKey = process.env.SWT3_SIGNING_KEY || signingKey;
  const demo = !apiKey;

  if (apiKey && !apiKey.startsWith("axm_")) {
    throw new Error("API key must start with 'axm_'");
  }

  const rawLevel = process.env.SWT3_CLEARING_LEVEL ?? String(raw.clearing_level ?? 1);
  let clearingLevel: 0 | 1 | 2 | 3 = 1;
  const parsed = parseInt(rawLevel, 10);
  if ([0, 1, 2, 3].includes(parsed)) {
    clearingLevel = parsed as 0 | 1 | 2 | 3;
  }

  // Chain verify: env > trust_mesh.mode === "strict" > false
  const chainVerifyEnv = process.env.SWT3_CHAIN_VERIFY;
  const meshMode = trustMeshRaw?.mode as string | undefined;
  const chainVerify = chainVerifyEnv
    ? chainVerifyEnv === "true"
    : meshMode === "strict";

  const maxChainGapSeconds = parseInt(
    process.env.SWT3_MAX_CHAIN_GAP
    || String(densityRaw?.max_chain_gap_seconds ?? trustMeshRaw?.freshness_window ?? 60),
    10,
  );

  const config: McpConfig = {
    endpoint: endpoint.replace(/\/+$/, ""),
    apiKey: demo ? "axm_demo_local" : apiKey,
    tenantId: demo ? "DEMO_LOCAL" : tenantId,
    clearingLevel,
    agentId,
    signingKey,
    demo,
    chainVerify: demo ? false : chainVerify,
    redisUrl: process.env.SWT3_REDIS_URL || "redis://localhost:6379",
    redisStream: process.env.SWT3_REDIS_STREAM || "swt3:anchors",
    maxChainGapSeconds,
    configHash,
  };

  // Density policy from YAML
  let densityPolicy: DensityPolicy | null = null;
  if (densityRaw) {
    densityPolicy = {
      min_anchors_per_1000_tokens: (densityRaw.min_anchors_per_1000_tokens as number) ?? 1,
      required_providers: (densityRaw.required_providers as string[]) ?? [],
      max_chain_gap_seconds: (densityRaw.max_chain_gap_seconds as number) ?? 60,
      require_signing_key: (densityRaw.require_signing_key as boolean) ?? false,
      min_trust_level: (densityRaw.min_trust_level as number) ?? 1,
    };
  }

  // Trust mesh from YAML
  let trustMesh: YamlTrustMesh | null = null;
  if (trustMeshRaw) {
    trustMesh = {
      trustedTenants: (trustMeshRaw.trusted_tenants as string[]) ?? [],
      deniedAgents: (trustMeshRaw.deny_agents as string[]) ?? [],
      deniedTenants: (trustMeshRaw.deny_tenants as string[]) ?? [],
    };
  }

  // MCP policy from YAML
  let mcpPolicy: McpToolPolicy | null = null;
  if (mcpPolicyRaw) {
    mcpPolicy = {
      witnessedTools: (mcpPolicyRaw.witnessed_tools as string[]) ?? [],
      exemptTools: (mcpPolicyRaw.exempt_tools as string[]) ?? [],
      requireTrustLevel: (mcpPolicyRaw.require_trust_level as number) ?? 0,
      autoWitness: (mcpPolicyRaw.auto_witness as boolean) ?? true,
      blockOnFailure: (mcpPolicyRaw.block_on_failure as boolean) ?? false,
      maxVelocity: mcpPolicyRaw.max_velocity as string | undefined,
      maxChainDepth: mcpPolicyRaw.max_chain_depth as number | undefined,
      toolAllowlist: (mcpPolicyRaw.tool_allowlist as string[]) ?? [],
      toolBlocklist: (mcpPolicyRaw.tool_blocklist as string[]) ?? [],
      failSecure: (mcpPolicyRaw.fail_secure as boolean) ?? true,
    };
  }

  return { config, densityPolicy, trustMesh, mcpPolicy };
}

/**
 * Load configuration. Checks SWT3_CONFIG_FILE first, falls back to env vars.
 */
export function loadConfig(): McpConfigBundle {
  const yamlPath = process.env.SWT3_CONFIG_FILE;
  if (yamlPath) {
    return loadFromYaml(yamlPath);
  }

  // Legacy env-var-only path
  const endpoint = process.env.SWT3_ENDPOINT || "https://sovereign.tenova.io";
  const apiKey = process.env.SWT3_API_KEY || "";
  const tenantId = process.env.SWT3_TENANT_ID || "";
  const rawLevel = process.env.SWT3_CLEARING_LEVEL;
  const agentId = process.env.SWT3_AGENT_ID || undefined;
  const signingKey = process.env.SWT3_SIGNING_KEY || undefined;
  const chainVerify = process.env.SWT3_CHAIN_VERIFY === "true";
  const redisUrl = process.env.SWT3_REDIS_URL || "redis://localhost:6379";
  const redisStream = process.env.SWT3_REDIS_STREAM || "swt3:anchors";
  const maxChainGapSeconds = parseInt(process.env.SWT3_MAX_CHAIN_GAP || "60", 10);

  const demo = !apiKey;

  if (apiKey && !apiKey.startsWith("axm_")) {
    throw new Error("SWT3_API_KEY must start with 'axm_'");
  }

  let clearingLevel: 0 | 1 | 2 | 3 = 1;
  if (rawLevel !== undefined) {
    const parsed = parseInt(rawLevel, 10);
    if (![0, 1, 2, 3].includes(parsed)) {
      throw new Error("SWT3_CLEARING_LEVEL must be 0, 1, 2, or 3");
    }
    clearingLevel = parsed as 0 | 1 | 2 | 3;
  }

  return {
    config: {
      endpoint: endpoint.replace(/\/+$/, ""),
      apiKey: demo ? "axm_demo_local" : apiKey,
      tenantId: demo ? "DEMO_LOCAL" : tenantId,
      clearingLevel,
      agentId,
      signingKey,
      demo,
      chainVerify: demo ? false : chainVerify,
      redisUrl,
      redisStream,
      maxChainGapSeconds,
    },
    densityPolicy: null,
    trustMesh: null,
    mcpPolicy: null,
  };
}
