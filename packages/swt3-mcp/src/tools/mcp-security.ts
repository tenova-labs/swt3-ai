/**
 * SWT3 MCP Server: witness_mcp_security tool (AI-MCP.1).
 *
 * Attests MCP server security posture based on observable checks.
 * NEVER reveals which specific checks failed -- only count and score.
 * Stdio transport cannot verify TLS; only 8 observable checks are used.
 *
 * NSA/CSA MCP Security Best Practices, NIST AI Agent Standards Initiative.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

interface McpSecurityArgs {
  checks_passed: number;
  total_checks?: number;
  score?: number;
  server_name?: string;
  transport_type?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessMcpSecurity(
  args: McpSecurityArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-MCP.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;

  const totalChecks = args.total_checks ?? 8;
  const checksPassed = args.checks_passed;
  const score = args.score ?? Math.round((checksPassed / Math.max(totalChecks, 1)) * 100);

  const factorA = totalChecks;
  const factorB = checksPassed;
  const factorC = score;

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
    payload.ai_model_id = `mcp-security-${args.transport_type ?? "stdio"}`;
    payload.ai_context = {
      provider: "mcp-security-posture",
      checks_total: totalChecks,
      checks_passed: checksPassed,
      posture_score: score,
      ...(args.server_name ? { server_name: args.server_name } : {}),
      ...(args.transport_type ? { transport_type: args.transport_type } : {}),
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = `mcp-security-${args.transport_type ?? "stdio"}`;
    payload.ai_context = { provider_category: "mcp-security-posture" };
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  const verdict = score >= 75 ? "PASS" : "FAIL";

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIMCP1-${verdict}-${epoch}-${fp}`;
    return [
      `Verdict: ${verdict}`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Checks Passed: ${checksPassed}/${totalChecks}`,
      `Posture Score: ${score}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Verdict: ${receipt.verdict ?? verdict}`,
    `Anchor: ${receipt.swt3_anchor ?? fp}`,
    `Procedure: ${procedureId}`,
    `Checks Passed: ${checksPassed}/${totalChecks}`,
    `Posture Score: ${score}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
