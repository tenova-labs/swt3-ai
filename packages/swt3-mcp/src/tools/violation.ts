/**
 * SWT3 MCP Server: report_violation tool.
 *
 * Voluntary self-attestation of a policy violation. The agent reports
 * its own violation. Always mints a FAIL anchor. Never blocks execution.
 * FAIL anchors trigger downstream alerts via the existing pipeline.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

const SEVERITY_SCORES: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

interface ViolationArgs {
  violation_type: string;
  description: string;
  severity?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleReportViolation(
  args: ViolationArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-VIO.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const severity = args.severity || "medium";
  const severityScore = SEVERITY_SCORES[severity.toLowerCase()] ?? 2;

  // AI-VIO.1 factors: violation reported (1), violation occurred (0 = fail), severity score
  const factorA = 1;
  const factorB = 0; // always FAIL
  const factorC = severityScore;

  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(
    config.tenantId,
    procedureId,
    factorA,
    factorB,
    factorC,
    ts,
  );

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

  // Apply clearing level
  if (clearingLevel <= 1) {
    payload.ai_model_id = args.violation_type;
    payload.ai_context = {
      provider: "self-report",
      violation_type: args.violation_type,
      description: args.description,
      severity,
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.violation_type;
  } else {
    payload.ai_model_id = sha256Truncated(args.violation_type);
  }

  payload.witness_source = "mcp";

  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  // Demo mode
  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-FAIL-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Violation Self-Reported`,
      `Verdict: FAIL`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Type: ${args.violation_type}`,
      `Severity: ${severity}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
      ``,
      `This anchor was minted locally. To persist anchors to the SWT3 ledger,`,
      `use the signup tool to create a free account, or set SWT3_API_KEY.`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);

  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt.tenant_id;
  }

  return [
    `Violation Self-Reported`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Procedure: ${receipt.procedure_id}`,
    `Type: ${args.violation_type}`,
    `Severity: ${severity}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
