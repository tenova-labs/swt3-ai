/**
 * SWT3 MCP Server: witness_output_filter tool (AI-GRD.2).
 *
 * Witnesses output content safety classification result.
 * Distinct from AI-GRD.1 (guardrail activation) -- this witnesses
 * the classification RESULT on the output side.
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

interface OutputFilterArgs {
  passed: boolean;
  filter_type?: string;
  confidence?: number;
  action_taken?: string;
  output_hash?: string;
  model_id?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessOutputFilter(
  args: OutputFilterArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-GRD.2";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const filterType = args.filter_type ?? "content-safety";
  const action = args.action_taken ?? (args.passed ? "allowed" : "blocked");

  const factorA = 1; // content safety required
  const factorB = args.passed ? 1 : 0;
  const factorC = 0; // reserved

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
    payload.ai_model_id = args.model_id ?? `output-${filterType}`;
    const ctx: Record<string, unknown> = {
      provider: "output-filter",
      filter_type: filterType,
      passed: args.passed,
      action_taken: action,
    };
    if (args.confidence != null) ctx.confidence = Math.round(args.confidence * 10000) / 10000;
    if (args.output_hash) ctx.output_hash = args.output_hash;
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.model_id ?? `output-${filterType}`;
    payload.ai_context = { provider_category: "output-filter" };
  } else {
    payload.ai_model_id = sha256Truncated(args.model_id ?? `output-${filterType}`);
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  const statusLabel = args.passed ? "CLEAN" : "TRIGGERED";

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIGRD2-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Output Filter Witnessed (AI-GRD.2)`,
      `Verdict: PASS`,
      `Anchor: ${demoAnchor}`,
      `Classification: ${statusLabel}`,
      `Filter Type: ${filterType}`,
      `Action: ${action}`,
      args.confidence != null ? `Confidence: ${(args.confidence * 100).toFixed(1)}%` : null,
      `Model: ${args.model_id ?? "unknown"}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].filter(Boolean).join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Output Filter Witnessed (AI-GRD.2)`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Classification: ${statusLabel}`,
    `Filter Type: ${filterType}`,
    `Action: ${action}`,
    args.confidence != null ? `Confidence: ${(args.confidence * 100).toFixed(1)}%` : null,
    `Model: ${args.model_id ?? "unknown"}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].filter(Boolean).join("\n");
}
