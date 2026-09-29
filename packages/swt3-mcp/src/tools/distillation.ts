/**
 * SWT3 MCP Server: Knowledge Distillation Provenance tool (AI-DIST.1).
 *
 * Witnesses teacher-to-student model distillation events.
 * EU AI Act Art. 53 requires GPAI transparency including distillation provenance.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

const DISTILLATION_TYPE_CODES: Record<string, number> = {
  response: 0, logit: 1, feature: 2, attention: 3, progressive: 4,
};
const TOS_COMPLIANCE_CODES: Record<string, number> = {
  no: 0, yes: 1, unknown: 2,
};
const VALID_LINK_TYPES = new Set(["open", "commercial", "research", "unknown"]);

interface DistillationArgs {
  distillation_type: string;
  compression_ratio: number;
  tos_compliance?: string;
  teacher_model?: string;
  student_model?: string;
  dataset_hash?: string;
  link_type?: string;
  distillation_method?: string;
  clearing_level?: 0 | 1 | 2 | 3;
  agent_id?: string;
  cycle_id?: string;
}

export async function handleWitnessDistillation(
  args: DistillationArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-DIST.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const fa = DISTILLATION_TYPE_CODES[args.distillation_type] ?? 0;
  const fb = args.compression_ratio;
  const fc = TOS_COMPLIANCE_CODES[args.tos_compliance ?? "unknown"] ?? 2;

  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(config.tenantId, procedureId, fa, fb, fc, ts);

  const payload: WitnessPayload = {
    procedure_id: procedureId,
    factor_a: fa, factor_b: fb, factor_c: fc,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
  };

  if (clearingLevel <= 1) {
    payload.ai_model_id = `distillation-${args.distillation_type}`;
    const ctx: Record<string, unknown> = {
      provider: "distillation-provenance",
      distillation_type: args.distillation_type,
      compression_ratio: args.compression_ratio,
      tos_compliance: args.tos_compliance ?? "unknown",
    };
    if (args.teacher_model) ctx.teacher_model_hash = sha256Truncated(args.teacher_model, 12);
    if (args.student_model) ctx.student_model_hash = sha256Truncated(args.student_model, 12);
    if (args.dataset_hash) ctx.dataset_hash = sha256Truncated(args.dataset_hash, 12);
    if (args.link_type) ctx.link_type = VALID_LINK_TYPES.has(args.link_type) ? args.link_type : "unknown";
    if (args.distillation_method) ctx.distillation_method = args.distillation_method;
    payload.ai_context = ctx;
  } else {
    payload.ai_model_id = `distillation-${args.distillation_type}`;
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Knowledge Distillation Witnessed`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Type: ${args.distillation_type}`,
      `Compression: ${args.compression_ratio}x`,
      `ToS: ${args.tos_compliance ?? "unknown"}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt.tenant_id;
  }

  return [
    `Knowledge Distillation Witnessed`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Procedure: ${receipt.procedure_id}`,
    `Type: ${args.distillation_type}`,
    `Compression: ${args.compression_ratio}x`,
    `ToS: ${args.tos_compliance ?? "unknown"}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
