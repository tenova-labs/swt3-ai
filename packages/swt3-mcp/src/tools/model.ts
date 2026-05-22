/**
 * SWT3 MCP Server: model integrity tools.
 *
 * witness_model_integrity (AI-MDL.5): Verify model weight file hash.
 * witness_adapter_stack (AI-MDL.6): Attest active LoRA/PEFT adapters.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

// -- AI-MDL.5: Weight File Integrity --

interface ModelIntegrityArgs {
  model_id: string;
  weight_hash: string;
  expected_hash?: string;
  format?: string;
  file_size_bytes?: number;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessModelIntegrity(
  args: ModelIntegrityArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-MDL.5";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;

  const match = args.expected_hash
    ? args.weight_hash === args.expected_hash
    : true;

  const factorA = 1;
  const factorB = match ? 1 : 0;
  const factorC = 0;
  const verdict = match ? "PASS" : "FAIL";

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
    payload.ai_model_id = args.model_id;
    const ctx: Record<string, unknown> = {
      provider: "model-weights",
      file_hash: args.weight_hash,
    };
    if (args.expected_hash) ctx.expected_hash = args.expected_hash;
    if (args.format) ctx.format = args.format;
    if (args.file_size_bytes != null) ctx.file_size_bytes = args.file_size_bytes;
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.model_id;
  } else {
    payload.ai_model_id = sha256Truncated(args.model_id);
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-${verdict}-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Model Weight Integrity`,
      `Verdict: ${verdict}`,
      `Anchor: ${demoAnchor}`,
      `Model: ${args.model_id}`,
      `Hash Match: ${match}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Model Weight Integrity`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Model: ${args.model_id}`,
    `Hash Match: ${match}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}

// -- AI-MDL.6: Adapter Stack Attestation --

interface AdapterStackArgs {
  base_model: string;
  adapters: Array<{ name: string; hash: string; base_model?: string }>;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessAdapterStack(
  args: AdapterStackArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-MDL.6";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;

  const allVerified = args.adapters.length === 0 || args.adapters.every((a) => a.hash);
  const factorA = args.adapters.length;
  const factorB = allVerified ? 1 : 0;
  const factorC = 0;
  const verdict = allVerified ? "PASS" : "FAIL";

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
    payload.ai_model_id = args.base_model;
    payload.ai_context = {
      provider: "adapter",
      base_model_id: args.base_model,
      adapters: args.adapters,
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.base_model;
  } else {
    payload.ai_model_id = sha256Truncated(args.base_model);
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-${verdict}-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Adapter Stack Attestation`,
      `Verdict: ${verdict}`,
      `Anchor: ${demoAnchor}`,
      `Base Model: ${args.base_model}`,
      `Adapters: ${args.adapters.length}`,
      `All Verified: ${allVerified}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Adapter Stack Attestation`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Base Model: ${args.base_model}`,
    `Adapters: ${args.adapters.length}`,
    `All Verified: ${allVerified}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
