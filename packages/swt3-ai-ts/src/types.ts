/**
 * SWT3 AI Witness SDK — Type definitions.
 */

export interface WitnessConfig {
  endpoint: string;
  apiKey: string;
  tenantId: string;
  clearingLevel: 0 | 1 | 2 | 3;
  bufferSize: number;
  flushInterval: number; // seconds
  timeout: number; // ms
  maxRetries: number;
  latencyThresholdMs: number;
  guardrailsRequired: number;
  guardrailNames: string[];
  procedures?: string[];
  factorHandoff?: "file";
  factorHandoffPath?: string;
  agentId?: string;
  signingKey?: string;
}

export interface WitnessPayload {
  procedure_id: string;
  factor_a: number;
  factor_b: number;
  factor_c: number;
  clearing_level: number;
  anchor_fingerprint: string;
  anchor_epoch: number;
  fingerprint_timestamp_ms: number;
  ai_model_id?: string;
  ai_prompt_hash?: string;
  ai_response_hash?: string;
  ai_latency_ms?: number;
  ai_input_tokens?: number;
  ai_output_tokens?: number;
  ai_context?: {
    provider?: string;
    guardrails?: string[];
    system_fingerprint?: string;
    tool_name?: string;
    tool_call_id?: string;
  };
  agent_id?: string;
  payload_signature?: string;
}

export interface WitnessReceipt {
  procedure_id: string;
  verdict: "PASS" | "FAIL" | string;
  swt3_anchor: string;
  clearing_level: number;
  witnessed_at: string;
  verification_url: string;
  ok: boolean;
  error?: string;
}

export interface BatchResponse {
  ok: boolean;
  tenant_id: string;
  total: number;
  accepted: number;
  rejected: number;
  receipts: WitnessReceipt[];
}

export interface InferenceRecord {
  modelId: string;
  modelHash: string;
  promptHash: string;
  responseHash: string;
  latencyMs: number;
  inputTokens?: number;
  outputTokens?: number;
  guardrailsActive: number;
  guardrailsRequired: number;
  guardrailPassed: boolean;
  hasRefusal: boolean;
  provider: string;
  systemFingerprint?: string;
  guardrailNames: string[];
  toolName?: string;
  toolCallId?: string;
}

/** Valid AI procedure IDs from SWT3 Spec v1.2.0 */
export const AI_PROCEDURES = new Set([
  "AI-INF.1", "AI-INF.2", "AI-INF.3",
  "AI-MDL.1", "AI-MDL.2", "AI-MDL.3",
  "AI-GRD.1", "AI-GRD.2", "AI-GRD.3",
  "AI-FAIR.1", "AI-FAIR.2",
  "AI-DATA.1", "AI-DATA.2",
  "AI-HITL.1", "AI-HITL.2",
  "AI-EXPL.1", "AI-EXPL.2",
  "AI-TOOL.1",
  "AI-ID.1",
]);
