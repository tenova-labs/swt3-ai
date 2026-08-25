/**
 * SWT3 MCP Server: witness_delegation_boundary tool (AI-DEL.2).
 *
 * Attests that a delegation boundary was evaluated. Does not enforce the
 * boundary. Your code must enforce depth limits; this method records the
 * evidence.
 *
 * NIST AI Agent Standards Initiative, Singapore IMDA, EU AI Act Art. 14.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

const BOUNDARY_ACTION_CODES: Record<string, number> = {
  blocked: 0, warned: 1, escalated: 2, allowed: 3,
};

interface DelegationBoundaryArgs {
  max_depth: number;
  actual_depth: number;
  boundary_action: string;
  delegator_id?: string;
  parent_grant_fingerprint?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessDelegationBoundary(
  args: DelegationBoundaryArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-DEL.2";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const action = args.boundary_action ?? "allowed";

  const factorA = args.max_depth;
  const factorB = args.actual_depth;
  const factorC = BOUNDARY_ACTION_CODES[action] ?? 3;

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
    payload.ai_model_id = `delegation-boundary-${action}`;
    payload.ai_context = {
      provider: "delegation-governance",
      boundary_action: action,
      depth_exceeded: args.actual_depth > args.max_depth,
      ...(args.delegator_id ? { delegator_id: args.delegator_id } : {}),
      ...(args.parent_grant_fingerprint ? { parent_grant_fingerprint: args.parent_grant_fingerprint } : {}),
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = `delegation-boundary-${action}`;
    payload.ai_context = { provider_category: "delegation-governance" };
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const verdict = (factorC !== 3 || factorB <= factorA) ? "PASS" : "FAIL";
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIDEL2-${verdict}-${epoch}-${fp}`;
    return [
      `Verdict: ${verdict}`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Max Depth: ${factorA}`,
      `Actual Depth: ${factorB}`,
      `Boundary Action: ${action}`,
      `Depth Exceeded: ${factorB > factorA}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  const verdict = receipt.verdict ?? ((factorC !== 3 || factorB <= factorA) ? "PASS" : "FAIL");
  return [
    `Verdict: ${verdict}`,
    `Anchor: ${receipt.swt3_anchor ?? fp}`,
    `Procedure: ${procedureId}`,
    `Max Depth: ${factorA}`,
    `Actual Depth: ${factorB}`,
    `Boundary Action: ${action}`,
    `Depth Exceeded: ${factorB > factorA}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
