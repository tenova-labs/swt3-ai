/**
 * SWT3 MCP Server: witness_guardrail tool (AI-GRD.1).
 *
 * Witnesses guardrail implementation and activation state.
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

const ACTION_CODES: Record<string, number> = {
  blocked: 3,
  redacted: 2,
  flagged: 1,
  allowed: 0,
};

interface GuardrailArgs {
  guardrail_name: string;
  guardrail_version?: string;
  triggered: boolean;
  action_taken?: string;
  input_hash?: string;
  output_hash?: string;
  model_id?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessGuardrail(
  args: GuardrailArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-GRD.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const action = args.action_taken ?? (args.triggered ? "flagged" : "allowed");

  const factorA = 1; // guardrail present
  const factorB = args.triggered ? 1 : 0;
  const factorC = ACTION_CODES[action] ?? 0;

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
    payload.ai_model_id = args.model_id ?? "unknown-model";
    const ctx: Record<string, unknown> = {
      provider: "guardrail",
      guardrail_name: args.guardrail_name,
      triggered: args.triggered,
      action_taken: action,
    };
    if (args.guardrail_version) ctx.guardrail_version = args.guardrail_version;
    if (args.input_hash) ctx.input_hash = args.input_hash;
    if (args.output_hash) ctx.output_hash = args.output_hash;
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.model_id ?? "unknown-model";
    payload.ai_context = { provider_category: "guardrail" };
  } else {
    payload.ai_model_id = sha256Truncated(args.model_id ?? "unknown-model");
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIGRD1-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Guardrail Witnessed (AI-GRD.1)`,
      `Verdict: PASS`,
      `Anchor: ${demoAnchor}`,
      `Guardrail: ${args.guardrail_name}${args.guardrail_version ? ` v${args.guardrail_version}` : ""}`,
      `Triggered: ${args.triggered ? "YES" : "NO"}`,
      `Action: ${action}`,
      `Model: ${args.model_id ?? "unknown-model"}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Guardrail Witnessed (AI-GRD.1)`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Guardrail: ${args.guardrail_name}${args.guardrail_version ? ` v${args.guardrail_version}` : ""}`,
    `Triggered: ${args.triggered ? "YES" : "NO"}`,
    `Action: ${action}`,
    `Model: ${args.model_id ?? "unknown-model"}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
