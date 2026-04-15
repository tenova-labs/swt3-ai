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
import type { InferenceRecord, WitnessPayload } from "./types.js";

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
  cycleId?: string,
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

      if (agentId) payload.agent_id = agentId;
      if (cycleId) payload.cycle_id = cycleId;
      if (signingKey) payload.payload_signature = signPayload(signingKey, fp, agentId);

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

      if (agentId) payload.agent_id = agentId;
      if (cycleId) payload.cycle_id = cycleId;
      if (signingKey) payload.payload_signature = signPayload(signingKey, fp, agentId);

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

    // agent_id and cycle_id survive all clearing levels (operational metadata)
    if (agentId) payload.agent_id = agentId;
    if (cycleId) payload.cycle_id = cycleId;
    if (signingKey) payload.payload_signature = signPayload(signingKey, fp, agentId);

    payloads.push(payload);
  }

  return payloads;
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
