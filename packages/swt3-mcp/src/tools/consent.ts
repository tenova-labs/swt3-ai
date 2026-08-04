/**
 * SWT3 MCP Server: witness_consent tool (AI-CONSENT.1).
 *
 * Witnesses that consent or lawful basis was documented before
 * processing. Evidence only -- never blocks execution.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

const CONSENT_BASIS_CODES: Record<string, number> = {
  consent: 0,
  contract: 1,
  legal_obligation: 2,
  vital_interest: 3,
  public_task: 4,
  legitimate_interest: 5,
};

interface ConsentArgs {
  subjects_covered?: number;
  legal_basis?: string;
  withdrawal_available?: boolean;
  jurisdiction?: string;
  purpose?: string;
  consent_mechanism?: string;
  model_id?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessConsent(
  args: ConsentArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-CONSENT.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const legalBasis = args.legal_basis ?? "consent";
  const subjectsCovered = args.subjects_covered ?? 1;

  const factorA = subjectsCovered;
  const factorB = CONSENT_BASIS_CODES[legalBasis] ?? 0;
  const factorC = (args.withdrawal_available ?? true) ? 1 : 0;

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
    payload.ai_model_id = `consent-${legalBasis}`;
    const ctx: Record<string, unknown> = {
      provider: "consent-management",
      legal_basis_type: legalBasis,
      subjects_covered: subjectsCovered,
    };
    if (args.purpose) ctx.purpose = args.purpose;
    if (args.consent_mechanism) ctx.consent_mechanism = args.consent_mechanism;
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = `consent-${legalBasis}`;
    payload.ai_context = { provider_category: "consent" };
  } else {
    payload.ai_model_id = sha256Truncated(`consent-${legalBasis}`);
  }

  if (args.jurisdiction) payload.jurisdiction = args.jurisdiction;
  if (legalBasis) payload.legal_basis = legalBasis;
  if (args.purpose) payload.purpose_class = args.purpose;

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AICONSENT1-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Consent Witnessed (AI-CONSENT.1)`,
      `Verdict: PASS`,
      `Anchor: ${demoAnchor}`,
      `Legal Basis: ${legalBasis}`,
      `Subjects: ${subjectsCovered}`,
      `Withdrawal Available: ${args.withdrawal_available ?? true ? "YES" : "NO"}`,
      args.jurisdiction ? `Jurisdiction: ${args.jurisdiction}` : null,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].filter(Boolean).join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Consent Witnessed (AI-CONSENT.1)`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Legal Basis: ${legalBasis}`,
    `Subjects: ${subjectsCovered}`,
    `Withdrawal Available: ${args.withdrawal_available ?? true ? "YES" : "NO"}`,
    args.jurisdiction ? `Jurisdiction: ${args.jurisdiction}` : null,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].filter(Boolean).join("\n");
}
