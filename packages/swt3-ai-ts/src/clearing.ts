/**
 * SWT3 AI Witness SDK — Clearing Engine (Levels 0-3).
 *
 * The "Sovereign Wire" protocol: controls what leaves the developer's
 * infrastructure. Raw prompts/responses NEVER appear in payloads.
 * Clearing operates on the wire payload, not the developer's response.
 *
 * Level 0 — Analytics:   All metadata
 * Level 1 — Standard:    Hashes + model_id + ai_context
 * Level 2 — Sensitive:   Hashes + model_id only. ai_context DELETED.
 * Level 3 — Classified:  Factors only. model_id hashed. Everything else DELETED.
 */

import { mintFingerprint, sha256Truncated, timestampMs } from "./fingerprint.js";
import { signPayload } from "./signing.js";
import type { AnchorReference, InferenceRecord, WitnessPayload } from "./types.js";

/**
 * Normalize references input to structured AnchorReference array.
 * Accepts strings, AnchorReference objects, or a mix.
 */
export function normalizeReferences(
  input: (string | AnchorReference)[] | undefined,
): AnchorReference[] | undefined {
  if (!input || input.length === 0) return undefined;
  return input.map((ref) =>
    typeof ref === "string" ? { fingerprint: ref } : ref,
  );
}

/**
 * Extract witness payloads from an inference record.
 * Applies clearing level to each payload via object destructuring (Level 2+
 * fields are simply never assigned, guaranteeing they don't exist on the wire).
 */
export function extractPayloads(
  record: InferenceRecord,
  tenantId: string,
  clearingLevel: 0 | 1 | 2 | 3,
  latencyThresholdMs: number = 30000,
  guardrailsRequired: number = 0,
  procedures?: string[],
  agentId?: string,
  signingKey?: string,
  signingKeyId?: string,
  signingKeyVersion?: number,
  cycleId?: string,
  policyVersionHash?: string,
  jurisdiction?: string,
  legalBasis?: string,
  purposeClass?: string,
  authorizationId?: string,
  signingAlgorithm?: string,
  references?: AnchorReference[],
): WitnessPayload[] {
  const [ts, epoch] = timestampMs();
  const payloads: WitnessPayload[] = [];

  // Access control records produce only AI-ACC.1 (skip inference procedures)
  if (record.accessTarget) {
    let accFactors = [
      {
        procedureId: "AI-ACC.1",
        factorA: 1,
        factorB: !record.accessScope || record.accessGranted ? 1 : 0,
        factorC: record.accessGranted ? 1 : 0,
      },
    ];

    if (procedures) {
      const allowed = new Set(procedures);
      accFactors = accFactors.filter((p) => allowed.has(p.procedureId));
    }

    for (const pf of accFactors) {
      const fp = mintFingerprint(tenantId, pf.procedureId, pf.factorA, pf.factorB, pf.factorC, ts);
      const payload: WitnessPayload = {
        procedure_id: pf.procedureId,
        factor_a: pf.factorA,
        factor_b: pf.factorB,
        factor_c: pf.factorC,
        clearing_level: clearingLevel,
        anchor_fingerprint: fp,
        anchor_epoch: epoch,
        fingerprint_timestamp_ms: ts,
      };

      if (clearingLevel <= 2) {
        payload.ai_latency_ms = record.latencyMs;
      }
      if (clearingLevel <= 1) {
        payload.ai_model_id = record.modelId;
        const ctx: WitnessPayload["ai_context"] = {
          provider: "access",
          access_target: record.accessTarget,
          access_granted: record.accessGranted,
        };
        if (record.accessScope) {
          ctx.access_scope = record.accessScope;
        }
        if (cycleId) ctx.cycle_id = cycleId;
        payload.ai_context = ctx;
      }

      applyOperationalMetadata(payload, fp, agentId, signingKey, signingKeyId, signingKeyVersion, cycleId, policyVersionHash, jurisdiction, legalBasis, purposeClass, authorizationId, signingAlgorithm, references);

      payloads.push(payload);
    }
    return payloads;
  }

  // Tool call records produce only AI-TOOL.1 (skip inference procedures)
  if (record.toolName) {
    let toolFactors = [
      { procedureId: "AI-TOOL.1", factorA: 1, factorB: record.latencyMs, factorC: record.hasRefusal ? 0 : 1 },
    ];

    if (procedures) {
      const allowed = new Set(procedures);
      toolFactors = toolFactors.filter((p) => allowed.has(p.procedureId));
    }

    for (const pf of toolFactors) {
      const fp = mintFingerprint(tenantId, pf.procedureId, pf.factorA, pf.factorB, pf.factorC, ts);
      const payload: WitnessPayload = {
        procedure_id: pf.procedureId,
        factor_a: pf.factorA,
        factor_b: pf.factorB,
        factor_c: pf.factorC,
        clearing_level: clearingLevel,
        anchor_fingerprint: fp,
        anchor_epoch: epoch,
        fingerprint_timestamp_ms: ts,
      };

      if (clearingLevel <= 2) {
        payload.ai_latency_ms = record.latencyMs;
      }
      if (clearingLevel <= 1) {
        payload.ai_model_id = record.modelId;
        const ctx: WitnessPayload["ai_context"] = {
          provider: "tool",
          tool_name: record.toolName,
        };
        if (record.toolCallId) {
          ctx.tool_call_id = record.toolCallId;
        }
        if (cycleId) ctx.cycle_id = cycleId;
        payload.ai_context = ctx;
      }

      applyOperationalMetadata(payload, fp, agentId, signingKey, signingKeyId, signingKeyVersion, cycleId, policyVersionHash, jurisdiction, legalBasis, purposeClass, authorizationId, signingAlgorithm, references);

      payloads.push(payload);
    }
    return payloads;
  }

  // Build raw factors for each procedure
  interface ProcFactor {
    procedureId: string;
    factorA: number;
    factorB: number;
    factorC: number;
  }

  let procFactors: ProcFactor[] = [
    // AI-INF.1: Inference Provenance
    {
      procedureId: "AI-INF.1",
      factorA: 1,
      factorB: record.promptHash && record.responseHash ? 1 : 0,
      factorC: 0,
    },
    // AI-INF.2: Inference Latency
    {
      procedureId: "AI-INF.2",
      factorA: latencyThresholdMs,
      factorB: record.latencyMs,
      factorC: record.latencyMs > latencyThresholdMs ? 1 : 0,
    },
    // AI-MDL.1: Model Weight Integrity
    {
      procedureId: "AI-MDL.1",
      factorA: 1,
      factorB: record.modelHash ? 1 : 0,
      factorC: 0,
    },
    // AI-MDL.2: Model Version Tracking
    {
      procedureId: "AI-MDL.2",
      factorA: 1,
      factorB: record.modelId ? 1 : 0,
      factorC: 0,
    },
  ];

  // AI-GRD.1: Guardrail Enforcement (only if guardrails configured)
  const grdRequired = guardrailsRequired || record.guardrailsRequired;
  if (grdRequired > 0) {
    procFactors.push({
      procedureId: "AI-GRD.1",
      factorA: grdRequired,
      factorB: record.guardrailsActive,
      factorC: record.guardrailPassed ? 1 : 0,
    });
  }

  // AI-GRD.2: Content Safety Filter
  procFactors.push({
    procedureId: "AI-GRD.2",
    factorA: 1,
    factorB: record.hasRefusal ? 0 : 1,
    factorC: record.hasRefusal ? 1 : 0,
  });

  // AI-ID.1: Agent Identity Attestation (only when agentId is configured)
  if (agentId) {
    procFactors.push({
      procedureId: "AI-ID.1",
      factorA: 1,
      factorB: 1,
      factorC: 0,
    });
  }

  // Filter to requested procedures
  if (procedures) {
    const allowed = new Set(procedures);
    procFactors = procFactors.filter((p) => allowed.has(p.procedureId));
  }

  // Build payloads with clearing applied
  for (const pf of procFactors) {
    const fp = mintFingerprint(tenantId, pf.procedureId, pf.factorA, pf.factorB, pf.factorC, ts);

    // Base payload — always present regardless of clearing level
    const payload: WitnessPayload = {
      procedure_id: pf.procedureId,
      factor_a: pf.factorA,
      factor_b: pf.factorB,
      factor_c: pf.factorC,
      clearing_level: clearingLevel,
      anchor_fingerprint: fp,
      anchor_epoch: epoch,
      fingerprint_timestamp_ms: ts,
    };

    // Apply clearing — use conditional assignment so Level 2+ fields
    // are never set (not even as undefined). This guarantees they are
    // absent from JSON.stringify output, not just null.
    applyClearingLevel(payload, record, clearingLevel);

    // Operational metadata survives all clearing levels
    applyOperationalMetadata(payload, fp, agentId, signingKey, signingKeyId, signingKeyVersion, cycleId, policyVersionHash, jurisdiction, legalBasis, purposeClass, authorizationId, signingAlgorithm, references);

    payloads.push(payload);
  }

  return payloads;
}

/** Apply operational metadata that survives all clearing levels. */
function applyOperationalMetadata(
  payload: WitnessPayload,
  fingerprint: string,
  agentId?: string,
  signingKey?: string,
  signingKeyId?: string,
  signingKeyVersion?: number,
  cycleId?: string,
  policyVersionHash?: string,
  jurisdiction?: string,
  legalBasis?: string,
  purposeClass?: string,
  authorizationId?: string,
  signingAlgorithm?: string,
  references?: AnchorReference[],
): void {
  if (agentId) payload.agent_id = agentId;
  if (cycleId) payload.cycle_id = cycleId;
  if (policyVersionHash) payload.policy_version_hash = policyVersionHash;
  if (jurisdiction) payload.jurisdiction = jurisdiction;
  if (legalBasis) payload.legal_basis = legalBasis;
  if (purposeClass) payload.purpose_class = purposeClass;
  if (authorizationId) payload.authorization_id = authorizationId;
  if (references && references.length > 0) payload.references = references;
  if (signingKey) {
    const algo = (signingAlgorithm ?? "hmac-sha256") as import("./signing.js").SigningAlgorithm;
    payload.payload_signature = signPayload(signingKey, fingerprint, agentId, algo);
    payload.signing_algorithm = algo;
    if (signingKeyId) payload.signing_key_id = signingKeyId;
    if (signingKeyVersion !== undefined) payload.signing_key_version = signingKeyVersion;
  }
}

/**
 * Apply clearing level to a payload using explicit field assignment.
 *
 * Level 0-1: All metadata assigned
 * Level 2:   Hashes + model_id only. ai_context NOT assigned (absent from wire).
 * Level 3:   model_id hashed. Hashes NOT assigned. No metadata.
 */
function applyClearingLevel(
  payload: WitnessPayload,
  record: InferenceRecord,
  level: 0 | 1 | 2 | 3,
): void {
  if (level <= 2) {
    // Levels 0-2: include hashes and metrics
    payload.ai_prompt_hash = record.promptHash;
    payload.ai_response_hash = record.responseHash;
    payload.ai_latency_ms = record.latencyMs;
    payload.ai_input_tokens = record.inputTokens;
    payload.ai_output_tokens = record.outputTokens;
  }

  if (level <= 1) {
    // Levels 0-1: include full ai_context + system prompt hash
    payload.ai_model_id = record.modelId;
    const ctx: WitnessPayload["ai_context"] = {
      provider: record.provider,
    };
    if (record.guardrailNames.length > 0) {
      ctx.guardrails = record.guardrailNames;
    }
    if (record.systemFingerprint) {
      ctx.system_fingerprint = record.systemFingerprint;
    }
    if (payload.cycle_id) {
      ctx.cycle_id = payload.cycle_id;
    }
    payload.ai_context = ctx;
    if (record.systemPromptHash) {
      payload.ai_system_prompt_hash = record.systemPromptHash;
    }
  } else if (level === 2) {
    // Level 2: model_id in cleartext, NO ai_context
    payload.ai_model_id = record.modelId;
    // ai_context is never assigned — absent from JSON
  } else {
    // Level 3: model_id HASHED, no hashes, no metadata
    payload.ai_model_id = record.modelId
      ? sha256Truncated(record.modelId)
      : undefined;
    // Delete hash fields that were set above (Level 3 overrides Level 2 path)
    delete payload.ai_prompt_hash;
    delete payload.ai_response_hash;
    delete payload.ai_latency_ms;
    delete payload.ai_input_tokens;
    delete payload.ai_output_tokens;
    // ai_context is never assigned
  }
}

/**
 * Mint an AI-GRD.3 (Gatekeeper Gate) payload.
 *
 * factor_a = required guardrail count
 * factor_b = actual guardrail count at call time
 * factor_c = 1 if gate passed, 0 if blocked
 * Verdict: PASS if b >= a AND c == 1
 */
export function extractGatekeeperPayload(
  tenantId: string,
  required: number,
  active: number,
  gatePassed: boolean,
  clearingLevel: 0 | 1 | 2 | 3,
  agentId?: string,
  signingKey?: string,
  signingKeyId?: string,
  signingKeyVersion?: number,
  cycleId?: string,
  policyVersionHash?: string,
  jurisdiction?: string,
  legalBasis?: string,
  purposeClass?: string,
  signingAlgorithm?: string,
): WitnessPayload {
  const [ts, epoch] = timestampMs();
  const fa = required;
  const fb = active;
  const fc = gatePassed ? 1 : 0;
  const fp = mintFingerprint(tenantId, "AI-GRD.3", fa, fb, fc, ts);

  const payload: WitnessPayload = {
    procedure_id: "AI-GRD.3",
    factor_a: fa,
    factor_b: fb,
    factor_c: fc,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
  };

  applyOperationalMetadata(payload, fp, agentId, signingKey, signingKeyId, signingKeyVersion, cycleId, policyVersionHash, jurisdiction, legalBasis, purposeClass, undefined, signingAlgorithm);

  return payload;
}

/** Revocation reason code mapping. */
export const REVOCATION_REASONS: Record<string, number> = {
  unspecified: 0,
  model_recall: 1,
  policy_violation: 2,
  data_contamination: 3,
  consent_withdrawal: 4,
  regulatory_order: 5,
  error_correction: 6,
};

/**
 * Mint an AI-REV.1 (Anchor Revocation) payload.
 *
 * factor_a = 1 (revocation event occurred)
 * factor_b = 1 (target declared valid by caller)
 * factor_c = reason code (integer from REVOCATION_REASONS)
 */
export function extractRevocationPayload(
  tenantId: string,
  targetFingerprint: string,
  reason: string,
  clearingLevel: 0 | 1 | 2 | 3,
  agentId?: string,
  signingKey?: string,
  signingKeyId?: string,
  signingKeyVersion?: number,
  cycleId?: string,
  policyVersionHash?: string,
  jurisdiction?: string,
  legalBasis?: string,
  purposeClass?: string,
  signingAlgorithm?: string,
): WitnessPayload {
  const [ts, epoch] = timestampMs();
  const reasonCode = REVOCATION_REASONS[reason] ?? 0;
  const fa = 1;
  const fb = 1;
  const fc = reasonCode;
  const fp = mintFingerprint(tenantId, "AI-REV.1", fa, fb, fc, ts);

  const payload: WitnessPayload = {
    procedure_id: "AI-REV.1",
    factor_a: fa,
    factor_b: fb,
    factor_c: fc,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
    revocation_target: targetFingerprint,
    revocation_reason: reason,
  };

  applyOperationalMetadata(payload, fp, agentId, signingKey, signingKeyId, signingKeyVersion, cycleId, policyVersionHash, jurisdiction, legalBasis, purposeClass, undefined, signingAlgorithm);

  return payload;
}

/**
 * Mint an AI-CHAIN.2 (Trust Degradation) payload.
 *
 * Minted automatically when the effective trust level drops during
 * a multi-agent chain handoff. Provides auditors with a specific,
 * searchable anchor for trust boundary crossings.
 *
 * factor_a = previous effective trust level
 * factor_b = new effective trust level
 * factor_c = delta (negative = degradation)
 */
export function extractChainTrustDegradationPayload(
  tenantId: string,
  previousTrustLevel: number,
  newTrustLevel: number,
  clearingLevel: 0 | 1 | 2 | 3,
  agentId?: string,
  signingKey?: string,
  signingKeyId?: string,
  signingKeyVersion?: number,
  cycleId?: string,
  policyVersionHash?: string,
  signingAlgorithm?: string,
): WitnessPayload {
  const [ts, epoch] = timestampMs();
  const fa = previousTrustLevel;
  const fb = newTrustLevel;
  const fc = newTrustLevel - previousTrustLevel;
  const fp = mintFingerprint(tenantId, "AI-CHAIN.2", fa, fb, fc, ts);

  const payload: WitnessPayload = {
    procedure_id: "AI-CHAIN.2",
    factor_a: fa,
    factor_b: fb,
    factor_c: fc,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
  };

  applyOperationalMetadata(payload, fp, agentId, signingKey, signingKeyId, signingKeyVersion, cycleId, policyVersionHash, undefined, undefined, undefined, undefined, signingAlgorithm);

  return payload;
}
