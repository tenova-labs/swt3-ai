/**
 * SWT3 AI Witness SDK — Factor Handoff (Local File Export).
 *
 * Writes factor data to local JSON files before the clearing engine strips
 * them from the wire payload. If the write fails, clearing does NOT proceed.
 *
 * Spec: SWT3 Factor Handoff Protocol v1.0.0
 */

import { writeFileSync, mkdirSync, renameSync, unlinkSync, chmodSync } from "node:fs";
import { join } from "node:path";
import type { WitnessPayload, InferenceRecord } from "./types.js";

const HANDOFF_VERSION = "1.0.0";

interface HandoffRecord {
  handoff_version: string;
  handoff_type: string;
  tenant_id: string;
  agent_id?: string;
  timestamp_iso: string;
  anchor_fingerprint: string;
  anchor_epoch: number;
  fingerprint_timestamp_ms: number;
  clearing_level: number;
  factors: {
    procedure_id: string;
    factor_a: number;
    factor_b: number;
    factor_c: number;
  };
  metadata: {
    ai_model_id: string;
    ai_model_hash: string;
    ai_prompt_hash: string;
    ai_response_hash: string;
    ai_latency_ms: number;
    ai_input_tokens?: number;
    ai_output_tokens?: number;
    ai_provider: string;
    ai_system_fingerprint?: string;
    ai_guardrail_names: string[];
    ai_guardrails_active: number;
    ai_guardrails_required: number;
    ai_guardrail_passed: boolean;
    ai_tool_name?: string;
    ai_tool_call_id?: string;
  };
}

/**
 * Write one JSON file per payload to the handoff directory.
 *
 * Throws on failure — the caller must NOT proceed with clearing
 * if this function throws.
 */
export function writeHandoffFiles(
  payloads: WitnessPayload[],
  inference: InferenceRecord,
  tenantId: string,
  handoffPath: string,
): void {
  mkdirSync(handoffPath, { recursive: true });

  for (const payload of payloads) {
    const record = buildHandoffRecord(payload, inference, tenantId);
    const filename = `${payload.anchor_fingerprint}.json`;
    const filepath = join(handoffPath, filename);
    const tmpPath = filepath + ".tmp";

    try {
      writeFileSync(tmpPath, JSON.stringify(record, null, 2) + "\n", "utf-8");

      // Set restrictive permissions (owner read/write only, 0o600)
      try {
        chmodSync(tmpPath, 0o600);
      } catch {
        // chmod may not be supported on all platforms (e.g., Windows)
      }

      // Atomic rename
      renameSync(tmpPath, filepath);
    } catch (err) {
      // Clean up temp file on failure
      try {
        unlinkSync(tmpPath);
      } catch {
        // ignore cleanup errors
      }
      throw err;
    }
  }
}

function buildHandoffRecord(
  payload: WitnessPayload,
  inference: InferenceRecord,
  tenantId: string,
): HandoffRecord {
  return {
    handoff_version: HANDOFF_VERSION,
    handoff_type: `clearing_level_${payload.clearing_level}`,
    tenant_id: tenantId,
    timestamp_iso: new Date(payload.anchor_epoch * 1000).toISOString(),
    anchor_fingerprint: payload.anchor_fingerprint,
    anchor_epoch: payload.anchor_epoch,
    fingerprint_timestamp_ms: payload.fingerprint_timestamp_ms,
    clearing_level: payload.clearing_level,
    factors: {
      procedure_id: payload.procedure_id,
      factor_a: payload.factor_a,
      factor_b: payload.factor_b,
      factor_c: payload.factor_c,
    },
    metadata: {
      ai_model_id: inference.modelId,
      ai_model_hash: inference.modelHash,
      ai_prompt_hash: inference.promptHash,
      ai_response_hash: inference.responseHash,
      ai_latency_ms: inference.latencyMs,
      ai_input_tokens: inference.inputTokens,
      ai_output_tokens: inference.outputTokens,
      ai_provider: inference.provider,
      ai_system_fingerprint: inference.systemFingerprint,
      ai_guardrail_names: inference.guardrailNames ?? [],
      ai_guardrails_active: inference.guardrailsActive,
      ai_guardrails_required: inference.guardrailsRequired,
      ai_guardrail_passed: inference.guardrailPassed,
    },
  };
}
