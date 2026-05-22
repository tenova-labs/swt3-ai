/**
 * SWT3 MCP Server: witness_authorization tool.
 *
 * Records an authorization decision as an AI-ACC.1 anchor. Never blocks
 * execution. FAIL anchors trigger alerts, not blocks.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

interface AuthorizeArgs {
  resource: string;
  scope?: string;
  granted: boolean;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleAuthorize(
  args: AuthorizeArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-ACC.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;

  // AI-ACC.1 factors: access attempt, granted/denied
  const factorA = 1;
  const factorB = args.granted ? 1 : 0;
  const factorC = args.granted ? 1 : 0;

  // Mint fingerprint
  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(
    config.tenantId,
    procedureId,
    factorA,
    factorB,
    factorC,
    ts,
  );

  // Build payload with clearing applied
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
    payload.ai_model_id = args.resource;
    payload.ai_context = {
      provider: "access",
      access_target: args.resource,
      access_scope: args.scope || "default",
      access_granted: args.granted,
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.resource;
  } else {
    // Level 3: hash resource name
    payload.ai_model_id = sha256Truncated(args.resource);
  }

  // Source identification
  payload.witness_source = "mcp";

  // Operational metadata (survives all clearing levels)
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  const verdict = args.granted ? "PASS" : "FAIL";

  // Demo mode: mint locally, no network call
  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-${verdict}-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Authorization ${args.granted ? "GRANTED" : "DENIED"}`,
      `Verdict: ${verdict}`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Resource: ${args.resource}`,
      `Scope: ${args.scope || "default"}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
      ``,
      `This anchor was minted locally. To persist anchors to the SWT3 ledger,`,
      `use the signup tool to create a free account, or set SWT3_API_KEY.`,
    ].join("\n");
  }

  // POST to witness endpoint
  const receipt = await client.postWitness(payload);

  // Auto-resolve tenant ID for future calls
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt.tenant_id;
  }

  return [
    `Authorization ${args.granted ? "GRANTED" : "DENIED"}`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Procedure: ${receipt.procedure_id}`,
    `Resource: ${args.resource}`,
    `Scope: ${args.scope || "default"}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
