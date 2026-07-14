/**
 * SWT3 MCP Server: witness_inference tool.
 *
 * Mints an SWT3 witness anchor for an AI inference. Accepts raw prompt/response
 * text (hashed locally, never sent to server) or pre-computed hashes.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

interface WitnessArgs {
  model_id: string;
  prompt?: string;
  prompt_hash?: string;
  response?: string;
  response_hash?: string;
  latency_ms?: number;
  input_tokens?: number;
  output_tokens?: number;
  clearing_level?: 0 | 1 | 2 | 3;
  procedure?: string;
  provider?: string;
  agent_id?: string;
  cycle_id?: string;
  jurisdiction?: string;
  legal_basis?: string;
  purpose_class?: string;
  lifecycle_chain_id?: string;
  lifecycle_parent?: string;
  lifecycle_stage?: string;
  escalation_chain_id?: string;
}

export async function handleWitness(
  args: WitnessArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = args.procedure || "AI-INF.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const latencyMs = args.latency_ms ?? 0;

  // Hash raw text locally if provided
  const promptHash =
    args.prompt_hash || (args.prompt ? sha256Truncated(args.prompt) : sha256Truncated(""));
  const responseHash =
    args.response_hash || (args.response ? sha256Truncated(args.response) : sha256Truncated(""));

  // Compute factors (AI-INF.1 pattern)
  const factorA = 1;
  const factorB = promptHash && responseHash ? 1 : 0;
  const factorC = 0;

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
  if (clearingLevel <= 2) {
    payload.ai_prompt_hash = promptHash;
    payload.ai_response_hash = responseHash;
    payload.ai_latency_ms = latencyMs;
    if (args.input_tokens !== undefined) payload.ai_input_tokens = args.input_tokens;
    if (args.output_tokens !== undefined) payload.ai_output_tokens = args.output_tokens;
  }

  if (clearingLevel <= 1) {
    payload.ai_model_id = args.model_id;
    payload.ai_context = {
      provider: args.provider || "unknown",
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.model_id;
  } else {
    // Level 3: hash model_id
    payload.ai_model_id = sha256Truncated(args.model_id);
  }

  // Source identification (allows server to distinguish SDK vs MCP traffic)
  payload.witness_source = "mcp";

  // Operational metadata (survives all clearing levels)
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (args.jurisdiction) payload.jurisdiction = args.jurisdiction;
  if (args.legal_basis) payload.legal_basis = args.legal_basis;
  if (args.purpose_class) payload.purpose_class = args.purpose_class;
  // Lifecycle chain fields (v6.0, survive all clearing levels)
  if (args.lifecycle_chain_id) payload.lifecycle_chain_id = args.lifecycle_chain_id;
  if (args.lifecycle_parent) payload.lifecycle_parent = args.lifecycle_parent;
  if (args.lifecycle_stage) payload.lifecycle_stage = args.lifecycle_stage;
  if (args.escalation_chain_id) payload.escalation_chain_id = args.escalation_chain_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  // Demo mode: mint locally, no network call
  if (config.demo) {
    const verdict = factorB >= factorA ? "PASS" : "FAIL";
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-${verdict}-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Verdict: ${verdict}`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Model: ${args.model_id}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
      ``,
      `This anchor was minted locally. To persist anchors to the SWT3 ledger,`,
      `use the signup tool to create a free account, or set SWT3_API_KEY.`,
      ``,
      `Integrate directly: pip install swt3-ai | npm install @tenova/swt3-ai`,
      `Also available in Rust, C#, and Ruby.`,
    ].join("\n");
  }

  // POST to witness endpoint
  const receipt = await client.postWitness(payload);

  // Auto-resolve tenant ID for future calls
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt.tenant_id;
  }

  return [
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Procedure: ${receipt.procedure_id}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
