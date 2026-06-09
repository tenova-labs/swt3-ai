/**
 * SWT3 MCP Server: Anchor-Chain Verifier.
 *
 * Validates an agent's anchor chain before tool execution. Queries
 * Redis reader (fast path) first, falls back to the persistent ledger (cold path).
 * Integrates with the density policy engine for enforcement.
 *
 * Flow:
 *   1. Query Redis in-memory index by agent_id / cycle_id
 *   2. If insufficient, query ledger via AxiomClient
 *   3. Check each anchor: not revoked, verdict=PASS, within gap limit
 *   4. Evaluate density policy
 *   5. Return structured result
 *
 * Patent pending.
 */

import type { McpConfig } from "./config.js";
import type { AxiomClient } from "./client.js";
import { queryAnchors, type AnchorEntry } from "./redis-reader.js";
import { signPayload } from "./fingerprint.js";
import {
  evaluatePolicy,
  type DensityPolicy,
  type ChainAnchor,
  type PolicyViolation,
} from "./density-policy.js";

// ── Types ─────────────────────────────────────────────────────────────

export interface ChainVerifyResult {
  valid: boolean;
  anchorCount: number;
  gaps: ChainGap[];
  revoked: string[];
  policyViolations: PolicyViolation[];
  source: "redis" | "ledger" | "none";
  reason?: string;
}

export interface ChainGap {
  fromEpoch: number;
  toEpoch: number;
  gapSeconds: number;
}

interface LedgerAnchor {
  procedure_id: string;
  anchor_fingerprint: string;
  anchor_epoch: number;
  agent_id?: string;
  cycle_id?: string;
  verdict: string;
  provider?: string;
  payload_signature?: string;
  ai_input_tokens?: number;
  ai_output_tokens?: number;
  observations?: Record<string, unknown>;
}

// ── Main Verification Function ────────────────────────────────────────

/**
 * Verify an agent's anchor chain. Called by the gatekeeper before tool execution.
 *
 * @param agentId - The presenting agent's ID
 * @param cycleId - The active chain's cycle_id (optional)
 * @param config - MCP config (for maxChainGapSeconds)
 * @param client - AxiomClient for ledger fallback
 * @param policy - Active density policy
 * @param agentTokenCount - Total tokens reported by agent (optional)
 * @param agentTrustLevel - Trust level from prior verify_agent_trust (optional)
 */
export async function verifyAnchorChain(
  agentId: string | undefined,
  cycleId: string | undefined,
  config: McpConfig,
  client: AxiomClient,
  policy: DensityPolicy,
  agentTokenCount?: number,
  agentTrustLevel?: number,
): Promise<ChainVerifyResult> {
  // No identity to verify against
  if (!agentId && !cycleId) {
    return {
      valid: false,
      anchorCount: 0,
      gaps: [],
      revoked: [],
      policyViolations: [],
      source: "none",
      reason: "no_agent_id_or_cycle_id",
    };
  }

  // Step 1: Try Redis in-memory index (fast path)
  const redisAnchors = queryAnchors(agentId, cycleId);

  if (redisAnchors.length > 0) {
    return evaluateChain(redisAnchors, "redis", config, policy, agentTokenCount, agentTrustLevel);
  }

  // Step 2: Fallback to ledger query
  try {
    const ledgerAnchors = await queryLedger(agentId, cycleId, config, client);
    if (ledgerAnchors.length > 0) {
      return evaluateChain(ledgerAnchors, "ledger", config, policy, agentTokenCount, agentTrustLevel);
    }
  } catch {
    // Ledger unavailable -- fail closed
  }

  // No anchors found anywhere
  return {
    valid: false,
    anchorCount: 0,
    gaps: [],
    revoked: [],
    policyViolations: [],
    source: "none",
    reason: "no_anchors_found",
  };
}

// ── Chain Evaluation ──────────────────────────────────────────────────

function evaluateChain(
  anchors: Array<AnchorEntry | LedgerAnchor>,
  source: "redis" | "ledger",
  config: McpConfig,
  policy: DensityPolicy,
  agentTokenCount?: number,
  agentTrustLevel?: number,
): ChainVerifyResult {
  // Sort by epoch ascending
  const sorted = [...anchors].sort((a, b) => a.anchor_epoch - b.anchor_epoch);

  // Check for revocations (AI-REV.1 anchors targeting chain members)
  const revoked: string[] = [];
  for (const anchor of sorted) {
    if (anchor.procedure_id === "AI-REV.1") {
      // This IS a revocation anchor -- extract target from observations or context
      const obs = (anchor as LedgerAnchor).observations;
      const target = obs?.revocation_target as string | undefined;
      if (target) revoked.push(target);
    }
  }

  // Check for FAIL verdicts
  const failAnchors = sorted.filter((a) => {
    const verdict = "verdict" in a ? a.verdict : undefined;
    return verdict === "FAIL" && a.procedure_id !== "AI-REV.1";
  });

  // Check chain gaps
  const maxGap = config.maxChainGapSeconds ?? 60;
  const gaps: ChainGap[] = [];
  for (let i = 1; i < sorted.length; i++) {
    const gap = sorted[i].anchor_epoch - sorted[i - 1].anchor_epoch;
    if (gap > maxGap) {
      gaps.push({
        fromEpoch: sorted[i - 1].anchor_epoch,
        toEpoch: sorted[i].anchor_epoch,
        gapSeconds: gap,
      });
    }
  }

  // Check anchor freshness (most recent anchor must be within maxGap of now)
  const nowEpoch = Math.floor(Date.now() / 1000);
  const newestAnchor = sorted[sorted.length - 1];
  const staleness = nowEpoch - newestAnchor.anchor_epoch;
  if (staleness > maxGap) {
    gaps.push({
      fromEpoch: newestAnchor.anchor_epoch,
      toEpoch: nowEpoch,
      gapSeconds: staleness,
    });
  }

  // Verify HMAC signatures when signing key is available and policy requires it
  let signatureFailures = 0;
  if (policy.require_signing_key && config.signingKey) {
    for (const anchor of sorted) {
      if (anchor.procedure_id === "AI-REV.1") continue;
      if (!anchor.payload_signature) {
        signatureFailures++;
        continue;
      }
      // Recompute HMAC and compare (same-tenant verification)
      const agentId = "agent_id" in anchor ? (anchor as AnchorEntry).agent_id : undefined;
      const expected = signPayload(config.signingKey, anchor.anchor_fingerprint, agentId);
      if (anchor.payload_signature !== expected) {
        signatureFailures++;
      }
    }
  }

  // Convert to ChainAnchor for policy evaluation
  const chainAnchors: ChainAnchor[] = sorted
    .filter((a) => a.procedure_id !== "AI-REV.1")
    .map((a) => ({
      anchor_epoch: a.anchor_epoch,
      provider: a.provider,
      payload_signature: a.payload_signature,
      ai_input_tokens: a.ai_input_tokens,
      ai_output_tokens: a.ai_output_tokens,
    }));

  // Evaluate density policy
  const policyResult = evaluatePolicy(policy, chainAnchors, agentTokenCount, agentTrustLevel);

  // Determine validity
  const valid =
    revoked.length === 0 &&
    failAnchors.length === 0 &&
    gaps.length === 0 &&
    signatureFailures === 0 &&
    policyResult.compliant;

  let reason: string | undefined;
  if (!valid) {
    if (revoked.length > 0) reason = "revoked_anchors";
    else if (failAnchors.length > 0) reason = "fail_verdicts_in_chain";
    else if (gaps.length > 0) reason = "chain_gap_exceeded";
    else if (signatureFailures > 0) reason = "signature_verification_failed";
    else if (!policyResult.compliant) reason = "density_policy_violation";
  }

  return {
    valid,
    anchorCount: sorted.length,
    gaps,
    revoked,
    policyViolations: policyResult.violations,
    source,
    reason,
  };
}

// ── Ledger Query (HTTP fallback) ──────────────────────────────────────
//
// OPEN CORE BOUNDARY: This function queries the Axiom Engine's
// proprietary chain verification endpoint. The endpoint performs
// authoritative verification against the sovereign witness ledger
// (multi-tenant, RLS-enforced, revocation-aware). This is the paywall:
// local Redis verification is best-effort; ledger verification is
// authoritative. Do NOT implement local ledger storage or self-contained
// verification that would bypass this boundary.
//

async function queryLedger(
  agentId: string | undefined,
  cycleId: string | undefined,
  config: McpConfig,
  client: AxiomClient,
): Promise<LedgerAnchor[]> {
  const params = new URLSearchParams();
  if (agentId) params.set("agent_id", agentId);
  if (cycleId) params.set("cycle_id", cycleId);
  params.set("limit", "100");
  params.set("recent", "true");

  const url = `/api/v1/ai-witness/chain?${params.toString()}`;

  try {
    const response = await fetch(`${config.endpoint}${url}`, {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.apiKey}`,
      },
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) return [];

    const data = (await response.json()) as { anchors?: LedgerAnchor[] };
    return data.anchors || [];
  } catch {
    return [];
  }
}
