/**
 * SWT3 MCP Server: witness_data_provenance tool (AI-DATA.1).
 *
 * Witnesses training data governance diligence WITHOUT disclosing
 * training data contents. Attests that governance review, license
 * verification, and demographic screening were performed.
 * Evidence only -- never blocks execution.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

interface DataProvenanceArgs {
  governance_reviewed?: boolean;
  documentation_hash?: string;
  license_verified?: boolean;
  demographic_features_excluded?: boolean;
  data_sources_count?: number;
  model_id?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessDataProvenance(
  args: DataProvenanceArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-DATA.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const govReviewed = args.governance_reviewed ?? true;

  const factorA = 1; // provenance required
  const factorB = govReviewed ? 1 : 0;
  const factorC = 0; // reserved per registry

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
    payload.ai_model_id = args.model_id ?? "data-provenance";
    const ctx: Record<string, unknown> = {
      provider: "data-provenance",
      governance_reviewed: govReviewed,
      license_verified: args.license_verified ?? false,
      demographic_features_excluded: args.demographic_features_excluded ?? false,
    };
    if (args.documentation_hash) ctx.documentation_hash = args.documentation_hash;
    if (args.data_sources_count != null) ctx.data_sources_count = args.data_sources_count;
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.model_id ?? "data-provenance";
    payload.ai_context = { provider_category: "data-provenance" };
  } else {
    payload.ai_model_id = sha256Truncated(args.model_id ?? "data-provenance");
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIDATA1-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Data Provenance Witnessed (AI-DATA.1)`,
      `Verdict: PASS`,
      `Anchor: ${demoAnchor}`,
      `Governance Reviewed: ${govReviewed ? "YES" : "NO"}`,
      `License Verified: ${args.license_verified ? "YES" : "NO"}`,
      `Demographic Features Excluded: ${args.demographic_features_excluded ? "YES" : "NO"}`,
      args.data_sources_count != null ? `Data Sources: ${args.data_sources_count}` : null,
      args.documentation_hash ? `Documentation Hash: ${args.documentation_hash.substring(0, 12)}...` : null,
      `Model: ${args.model_id ?? "unknown"}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].filter(Boolean).join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Data Provenance Witnessed (AI-DATA.1)`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Governance Reviewed: ${govReviewed ? "YES" : "NO"}`,
    `License Verified: ${args.license_verified ? "YES" : "NO"}`,
    `Demographic Features Excluded: ${args.demographic_features_excluded ? "YES" : "NO"}`,
    args.data_sources_count != null ? `Data Sources: ${args.data_sources_count}` : null,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].filter(Boolean).join("\n");
}
