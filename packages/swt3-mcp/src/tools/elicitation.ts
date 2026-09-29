/**
 * SWT3 MCP Server: MCP Elicitation Consent tool (AI-MCP.6).
 *
 * Witnesses when a tool attempts information elicitation beyond declared scope.
 * OWASP MCP Top 10 requires elicitation attack detection.
 * EU AI Act Art. 13 requires transparency in AI interactions.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

const ELICITATION_TYPE_CODES: Record<string, number> = {
  direct_query: 0, indirect_probe: 1, social_engineering: 2, context_manipulation: 3, tool_chaining: 4,
};
const CONSENT_STATUS_CODES: Record<string, number> = {
  denied: 0, granted: 1, implicit: 2, not_requested: 3,
};
const SCOPE_VIOLATION_CODES: Record<string, number> = {
  within_scope: 0, minor_deviation: 1, major_deviation: 2, complete_violation: 3,
};
const VALID_DETECTION_METHODS = new Set(["heuristic", "ml_classifier", "rule_based", "behavioral", "manual", "unknown"]);

interface ElicitationArgs {
  elicitation_type: string;
  consent_status: string;
  scope_violation: string;
  tool_name?: string;
  requesting_agent?: string;
  declared_scope?: string;
  actual_scope?: string;
  detection_method?: string;
  clearing_level?: 0 | 1 | 2 | 3;
  agent_id?: string;
  cycle_id?: string;
}

export async function handleWitnessElicitation(
  args: ElicitationArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-MCP.6";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const fa = ELICITATION_TYPE_CODES[args.elicitation_type] ?? 0;
  const fb = CONSENT_STATUS_CODES[args.consent_status] ?? 3;
  const fc = SCOPE_VIOLATION_CODES[args.scope_violation] ?? 0;

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
    payload.ai_model_id = `mcp-elicitation-${args.elicitation_type}`;
    const ctx: Record<string, unknown> = {
      provider: "mcp-elicitation",
      elicitation_type: args.elicitation_type,
      consent_status: args.consent_status,
      scope_violation: args.scope_violation,
    };
    if (args.tool_name) ctx.tool_name_hash = sha256Truncated(args.tool_name, 12);
    if (args.requesting_agent) ctx.requesting_agent_hash = sha256Truncated(args.requesting_agent, 12);
    if (args.declared_scope) ctx.declared_scope_hash = sha256Truncated(args.declared_scope, 12);
    if (args.actual_scope) ctx.actual_scope_hash = sha256Truncated(args.actual_scope, 12);
    if (args.detection_method) {
      ctx.detection_method = VALID_DETECTION_METHODS.has(args.detection_method) ? args.detection_method : "unknown";
    }
    payload.ai_context = ctx;
  } else {
    payload.ai_model_id = `mcp-elicitation-${args.elicitation_type}`;
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
      `MCP Elicitation Consent Witnessed`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Type: ${args.elicitation_type}`,
      `Consent: ${args.consent_status}`,
      `Scope: ${args.scope_violation}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt.tenant_id;
  }

  return [
    `MCP Elicitation Consent Witnessed`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Procedure: ${receipt.procedure_id}`,
    `Type: ${args.elicitation_type}`,
    `Consent: ${args.consent_status}`,
    `Scope: ${args.scope_violation}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
