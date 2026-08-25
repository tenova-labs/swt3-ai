/**
 * SWT3 MCP Server: witness_model_provenance tool (AI-PROV.1).
 *
 * Attests model provenance chain -- training, fine-tuning, distillation,
 * deployment lineage linked via parent model fingerprints.
 *
 * NIST AI RMF MAP 1.1, EU AI Act Art. 11, G7 Hiroshima AI Code of Conduct.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

const LINK_TYPE_CODES: Record<string, number> = {
  training: 0, fine_tuning: 1, deployment: 2, distillation: 3,
};

interface ModelProvenanceArgs {
  chain_length: number;
  integrity_verified: boolean;
  link_type: string;
  parent_model_fingerprint?: string;
  model_id?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessModelProvenance(
  args: ModelProvenanceArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-PROV.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const linkType = args.link_type ?? "training";

  const factorA = args.chain_length;
  const factorB = args.integrity_verified ? 1 : 0;
  const factorC = LINK_TYPE_CODES[linkType] ?? 0;

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
    payload.ai_model_id = args.model_id ?? `provenance-${linkType}`;
    payload.ai_context = {
      provider: "model-provenance",
      link_type: linkType,
      chain_length: args.chain_length,
      integrity_verified: args.integrity_verified,
      ...(args.parent_model_fingerprint ? { parent_model_fingerprint: args.parent_model_fingerprint } : {}),
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.model_id ?? `provenance-${linkType}`;
    payload.ai_context = { provider_category: "model-provenance" };
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  const verdict = args.integrity_verified ? "PASS" : "FAIL";

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIPROV1-${verdict}-${epoch}-${fp}`;
    return [
      `Verdict: ${verdict}`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Chain Length: ${factorA}`,
      `Integrity Verified: ${args.integrity_verified}`,
      `Link Type: ${linkType}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Verdict: ${receipt.verdict ?? verdict}`,
    `Anchor: ${receipt.swt3_anchor ?? fp}`,
    `Procedure: ${procedureId}`,
    `Chain Length: ${factorA}`,
    `Integrity Verified: ${args.integrity_verified}`,
    `Link Type: ${linkType}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
