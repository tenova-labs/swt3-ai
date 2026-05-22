/**
 * SWT3 MCP Server: Anchor Density Policy Engine.
 *
 * Configurable rules that enforce minimum anchor frequency, provider
 * requirements, chain gap limits, and signing enforcement. Agents that
 * fail policy checks are denied tool execution by the chain verifier.
 *
 * Patent pending.
 */

import { readFileSync } from "node:fs";

// ── Types ─────────────────────────────────────────────────────────────

export interface DensityPolicy {
  /** Minimum anchors per 1,000 tokens generated. Default: 1 */
  min_anchors_per_1000_tokens: number;
  /** Required anchor providers (e.g. ["vllm-native", "nvidia-triton"]). Default: [] */
  required_providers: string[];
  /** Maximum seconds between consecutive anchors in a chain. Default: 60 */
  max_chain_gap_seconds: number;
  /** Require all anchors to have payload_signature. Default: false */
  require_signing_key: boolean;
  /** Minimum trust level for the presenting agent. Default: 1 */
  min_trust_level: number;
}

export interface PolicyViolation {
  rule: string;
  message: string;
  actual?: number | string;
  required?: number | string;
}

export interface PolicyResult {
  compliant: boolean;
  violations: PolicyViolation[];
}

/** Minimal anchor shape needed for policy evaluation. */
export interface ChainAnchor {
  anchor_epoch: number;
  provider?: string;
  payload_signature?: string;
  ai_input_tokens?: number;
  ai_output_tokens?: number;
  trust_level?: number;
}

// ── Defaults ──────────────────────────────────────────────────────────

const DEFAULT_POLICY: DensityPolicy = {
  min_anchors_per_1000_tokens: 1,
  required_providers: [],
  max_chain_gap_seconds: 60,
  require_signing_key: false,
  min_trust_level: 1,
};

// ── Load Policy ───────────────────────────────────────────────────────

/**
 * Load density policy from environment.
 * Priority: SWT3_DENSITY_POLICY (inline JSON) > SWT3_DENSITY_POLICY_FILE (path) > defaults
 */
export function loadDensityPolicy(yamlPolicy?: DensityPolicy): DensityPolicy {
  // YAML-provided policy has second priority (after inline env var)
  if (yamlPolicy && !process.env.SWT3_DENSITY_POLICY) {
    return { ...DEFAULT_POLICY, ...yamlPolicy };
  }
  const inline = process.env.SWT3_DENSITY_POLICY;
  if (inline) {
    try {
      return { ...DEFAULT_POLICY, ...JSON.parse(inline) };
    } catch {
      // Fall through to file or defaults
    }
  }

  const filePath = process.env.SWT3_DENSITY_POLICY_FILE;
  if (filePath) {
    try {
      const raw = readFileSync(filePath, "utf8");
      return { ...DEFAULT_POLICY, ...JSON.parse(raw) };
    } catch {
      // Fall through to defaults
    }
  }

  return { ...DEFAULT_POLICY };
}

// ── Evaluate Policy ───────────────────────────────────────────────────

/**
 * Evaluate an anchor chain against the density policy.
 *
 * @param policy - The active density policy
 * @param anchors - Chain anchors sorted by epoch ascending
 * @param agentTokenCount - Total tokens produced by the agent (optional, skips density check if absent)
 * @param agentTrustLevel - Trust level of the presenting agent (from verify_agent_trust)
 */
export function evaluatePolicy(
  policy: DensityPolicy,
  anchors: ChainAnchor[],
  agentTokenCount?: number,
  agentTrustLevel?: number,
): PolicyResult {
  const violations: PolicyViolation[] = [];

  // Rule 1: Anchor density (anchors per 1,000 tokens)
  if (agentTokenCount != null && agentTokenCount > 0 && policy.min_anchors_per_1000_tokens > 0) {
    const expectedAnchors = (agentTokenCount / 1000) * policy.min_anchors_per_1000_tokens;
    if (anchors.length < expectedAnchors) {
      violations.push({
        rule: "anchor_density",
        message: `Insufficient anchor density: ${anchors.length} anchors for ${agentTokenCount} tokens (need ${Math.ceil(expectedAnchors)})`,
        actual: anchors.length,
        required: Math.ceil(expectedAnchors),
      });
    }
  }

  // Rule 2: Required providers
  if (policy.required_providers.length > 0) {
    const presentProviders = new Set(anchors.map((a) => a.provider).filter(Boolean));
    for (const required of policy.required_providers) {
      if (!presentProviders.has(required)) {
        violations.push({
          rule: "required_provider",
          message: `Missing required provider: ${required}`,
          actual: [...presentProviders].join(", ") || "none",
          required,
        });
      }
    }
  }

  // Rule 3: Max chain gap
  if (policy.max_chain_gap_seconds > 0 && anchors.length >= 2) {
    for (let i = 1; i < anchors.length; i++) {
      const gap = anchors[i].anchor_epoch - anchors[i - 1].anchor_epoch;
      if (gap > policy.max_chain_gap_seconds) {
        violations.push({
          rule: "chain_gap",
          message: `Chain gap of ${gap}s exceeds maximum ${policy.max_chain_gap_seconds}s (between anchors ${i - 1} and ${i})`,
          actual: gap,
          required: policy.max_chain_gap_seconds,
        });
        break; // Report first gap only
      }
    }
  }

  // Rule 4: Signing requirement
  if (policy.require_signing_key) {
    const unsigned = anchors.filter((a) => !a.payload_signature);
    if (unsigned.length > 0) {
      violations.push({
        rule: "signing_required",
        message: `${unsigned.length} of ${anchors.length} anchors missing payload_signature`,
        actual: anchors.length - unsigned.length,
        required: anchors.length,
      });
    }
  }

  // Rule 5: Minimum trust level
  if (agentTrustLevel != null && agentTrustLevel < policy.min_trust_level) {
    violations.push({
      rule: "trust_level",
      message: `Agent trust level ${agentTrustLevel} below minimum ${policy.min_trust_level}`,
      actual: agentTrustLevel,
      required: policy.min_trust_level,
    });
  }

  return {
    compliant: violations.length === 0,
    violations,
  };
}
