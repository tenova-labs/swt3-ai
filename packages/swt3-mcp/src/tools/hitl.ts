/**
 * SWT3 MCP Server: witness_human_review tool (AI-HITL.1).
 *
 * Witnesses that human review occurred on AI-generated output.
 * Evidence only -- never blocks execution.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

const OUTCOME_CODES: Record<string, number> = {
  approved: 1,
  rejected: 0,
  modified: 2,
  escalated: 3,
};

interface HumanReviewArgs {
  review_outcome: string;
  reviewer_id_hash?: string;
  review_latency_ms?: number;
  items_reviewed?: number;
  modification_hash?: string;
  escalation_reason?: string;
  model_id?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessHumanReview(
  args: HumanReviewArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-HITL.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const itemsReviewed = args.items_reviewed ?? 1;
  const outcome = args.review_outcome;

  const factorA = itemsReviewed;
  const factorB = OUTCOME_CODES[outcome] ?? 0;
  const factorC = args.reviewer_id_hash ? 1 : 0;

  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(config.tenantId, procedureId, factorA, factorB, factorC, ts);

  const payload: WitnessPayload = {
    procedure_id: procedureId,
    factor_a: factorA,
    factor_b: factorB,
    factor_c: factorC,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
  };

  if (clearingLevel <= 1) {
    payload.ai_model_id = args.model_id ?? "human-review";
    const ctx: Record<string, unknown> = {
      provider: "human-review",
      review_outcome: outcome,
      items_reviewed: itemsReviewed,
    };
    if (args.reviewer_id_hash) ctx.reviewer_id_hash = args.reviewer_id_hash;
    if (args.review_latency_ms != null) ctx.review_latency_ms = args.review_latency_ms;
    if (args.modification_hash) ctx.modification_hash = args.modification_hash;
    if (args.escalation_reason) ctx.escalation_reason = args.escalation_reason;
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.model_id ?? "human-review";
    payload.ai_context = { provider_category: "human-review" };
  } else {
    payload.ai_model_id = sha256Truncated(args.model_id ?? "human-review");
  }

  if (clearingLevel <= 2 && args.review_latency_ms != null) {
    payload.ai_latency_ms = args.review_latency_ms;
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  const outcomeLabel = outcome.charAt(0).toUpperCase() + outcome.slice(1);

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIHITL1-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Human Review Witnessed (AI-HITL.1)`,
      `Verdict: PASS`,
      `Anchor: ${demoAnchor}`,
      `Outcome: ${outcomeLabel}`,
      `Items Reviewed: ${itemsReviewed}`,
      `Reviewer Bound: ${args.reviewer_id_hash ? "YES" : "NO"}`,
      `Model: ${args.model_id ?? "unknown"}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Human Review Witnessed (AI-HITL.1)`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Outcome: ${outcomeLabel}`,
    `Items Reviewed: ${itemsReviewed}`,
    `Reviewer Bound: ${args.reviewer_id_hash ? "YES" : "NO"}`,
    `Model: ${args.model_id ?? "unknown"}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
