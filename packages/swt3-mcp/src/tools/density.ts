/**
 * SWT3 MCP Server: witness_anchor_density tool (AI-DENSITY.1).
 *
 * Witnesses whether witnessing frequency is sufficient for the regulatory
 * requirement. EU AI Act Art. 9, NIST AI RMF MEASURE 2.6.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

const DENSITY_STATUS_CODES: Record<string, number> = {
  sufficient: 0, insufficient: 1, degraded: 2,
};

interface DensityArgs {
  expected_anchors: number;
  actual_anchors: number;
  density_status?: string;
  evaluation_window_seconds?: number;
  procedure_filter?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessAnchorDensity(
  args: DensityArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-DENSITY.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const status = args.density_status ??
    (args.actual_anchors >= args.expected_anchors ? "sufficient" : "insufficient");

  const factorA = args.expected_anchors;
  const factorB = args.actual_anchors;
  const factorC = DENSITY_STATUS_CODES[status] ?? 1;

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
    payload.ai_model_id = `density-${status}`;
    payload.ai_context = {
      provider: "density-attestation",
      density_status: status,
      evaluation_window_seconds: args.evaluation_window_seconds ?? 3600,
      ...(args.procedure_filter ? { procedure_filter: args.procedure_filter } : {}),
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = `density-${status}`;
    payload.ai_context = { provider_category: "density-attestation" };
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const verdict = factorC === 0 ? "PASS" : "FAIL";
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIDENSITY1-${verdict}-${epoch}-${fp}`;
    return [
      `Verdict: ${verdict}`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Expected Anchors: ${factorA}`,
      `Actual Anchors: ${factorB}`,
      `Density Status: ${status}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  const verdict = receipt.verdict ?? (factorC === 0 ? "PASS" : "FAIL");
  return [
    `Verdict: ${verdict}`,
    `Anchor: ${receipt.swt3_anchor ?? fp}`,
    `Procedure: ${procedureId}`,
    `Expected Anchors: ${factorA}`,
    `Actual Anchors: ${factorB}`,
    `Density Status: ${status}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
