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
  signingKeyId?: string;
  signingKeyVersion?: number;
  signingAlgorithm?: "hmac-sha256" | "ml-dsa-65";
  cycleId?: string;
  policyVersion?: string;
  jurisdiction?: string;
  legalBasis?: string;
  purposeClass?: string;
  tokenBudget?: number; // Mint anchor every N tokens (undefined = disabled, use bufferSize)
  chainMinTrustLevel?: number; // Minimum effective trust level for chain handoffs (0-4). Enforced in strict mode.
  onFlush?: (payloads: WitnessPayload[], receipts: WitnessReceipt[]) => void;
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
  ai_system_prompt_hash?: string;
  ai_latency_ms?: number;
  ai_input_tokens?: number;
  ai_output_tokens?: number;
  ai_context?: Record<string, unknown>;
  agent_id?: string;
  cycle_id?: string;
  payload_signature?: string;
  signing_algorithm?: string;
  signing_key_id?: string;
  signing_key_version?: number;
  policy_version_hash?: string;
  jurisdiction?: string;
  legal_basis?: string;
  purpose_class?: string;
  authorization_id?: string;
  revocation_target?: string;
  revocation_reason?: string;
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
  systemPromptHash?: string;
  guardrailNames: string[];
  toolName?: string;
  toolCallId?: string;
  accessTarget?: string;
  accessGranted?: boolean;
  accessScope?: string;
}

/** Valid AI procedure IDs from SWT3 Spec v1.2.0 */
export const AI_PROCEDURES = new Set([
  "AI-INF.1", "AI-INF.2", "AI-INF.3",
  "AI-MDL.1", "AI-MDL.2", "AI-MDL.3",
  "AI-GRD.1", "AI-GRD.2", "AI-GRD.3",
  "AI-FAIR.1", "AI-FAIR.2", "AI-FAIR.3",
  "AI-DATA.1", "AI-DATA.2",
  "AI-HITL.1", "AI-HITL.2",
  "AI-EXPL.1", "AI-EXPL.2",
  "AI-TOOL.1",
  "AI-ID.1",
  "AI-ACC.1",
  "AI-REV.1",
  "AI-SEC.1",
  "AI-SEC.2",
  "AI-RAG.1",
  "AI-RAG.2",
  "AI-MDL.5",
  "AI-MDL.6",
  "AI-MDL.7",
  "AI-SKILL.1",
  "AI-SKILL.2",
  "AI-SKILL.3",
  "AI-HW.1",
  "AI-HW.3",
  "AI-TRUST.1",
  "AI-TRUST.2",
  "AI-CHR.1",
  "AI-VIO.1",
  "AI-CHAIN.1",
  "AI-CHAIN.2",
  "AI-SAFE.1",
  "AI-DATA.3",
  "AI-DATA.4",
  "AI-ENV.1",
  "AI-ENV.2",
  "AI-MARK.1",
  "AI-BASE.1",
  "AI-LIC.1",
  "AI-SBOM.1",
  "AI-REDTEAM.1",
  "AI-CONSENT.1",
  "AI-MULTI.1",
  "AI-DRIFT.1",
  "AI-AUDIT.1",
  "AI-INCIDENT.1",
  "AI-PERF.1",
  "AI-ROBUST.1",
  "AI-CYBER.1",
  "AI-TRANS.1",
  "AI-WATERMARK.1",
  "AI-DPIA.1",
  "AI-AUTO.1",
  "AI-DUALUSE.1",
  "AI-SUPPLY.1",
  "AI-PMM.1",
]);

/** A single retrieved context chunk for RAG witnessing. */
export interface RagChunk {
  contentHash: string;
  sourceId?: string;
  similarityScore?: number;
  metadata?: Record<string, unknown>;
}

/** Options for witnessRagContext(). */
export interface RagContextOptions {
  chunks: (string | RagChunk)[];
  corpusId?: string;
  corpusHash?: string;
  embeddingModel?: string;
  retrievalLatencyMs?: number;
  topK?: number;
  similarityThreshold?: number;
}

/** Model weight file metadata for AI-MDL.5 witnessing. */
export interface ModelWeightInfo {
  fileHash: string;
  filePath?: string;
  fileSizeBytes?: number;
  format?: string;
}

/** LoRA/QLoRA/PEFT adapter metadata for AI-MDL.6 witnessing. */
export interface AdapterInfo {
  name: string;
  adapterHash: string;
  baseModel?: string;
}

/** Skill/tool/plugin metadata for AI-SKILL.1 witnessing. */
export interface SkillInfo {
  name: string;
  version?: string;
  skillHash?: string;
}

/** Persistent memory source metadata for AI-SKILL.2 witnessing. */
export interface MemorySource {
  sourceType: string;
  sourceId?: string;
  contentHash?: string;
}

/** Quantization method codes for AI-MDL.7. */
export const QUANTIZATION_CODES: Record<string, number> = {
  fp32: 0, fp16: 1, bf16: 2, int8: 3, int4: 4, gptq: 5, awq: 6, gguf: 7,
};

/** Violation policy category codes for AI-VIO.1. */
export const POLICY_CATEGORIES: Record<string, number> = {
  unspecified: 0, content: 1, access: 2, data: 3, safety: 4, regulatory: 5,
};

/** Identity binding method codes for AI-HITL.3. */
export const BINDING_METHODS: Record<string, number> = {
  none: 0, session: 1, cryptographic: 2,
};

/** Model registry approval status codes for AI-MDL.8. */
export const APPROVAL_STATUS: Record<string, number> = {
  approved: 0, pending: 1, denied: 2,
};

/** Training data PII lifecycle event type codes for AI-DATA.4. */
export const PII_EVENT_TYPES: Record<string, number> = {
  unspecified: 0, pseudonymization: 1, anonymization: 2,
  access_restriction: 3, deletion: 4, encryption: 5,
};

/** Content type codes for AI-MARK.1 content provenance marking. */
export const CONTENT_TYPE_CODES: Record<string, number> = {
  text: 0, image: 1, audio: 2, video: 3, multimodal: 4, code: 5, structured_data: 6,
};

/** Valid marking methods for AI-MARK.1. */
export const MARKING_METHODS = [
  "c2pa", "watermark", "metadata_tag", "steganographic", "manifest",
] as const;

/** Baseline mode codes for AI-BASE.1 agent behavioral baseline. */
export const BASELINE_MODE_CODES: Record<string, number> = {
  establishing: 0, monitoring: 1, drift_detected: 2, baseline_reset: 3,
};

/** License type codes for AI-LIC.1 license provenance witnessing. */
export const LICENSE_TYPE_CODES: Record<string, number> = {
  permissive: 0, copyleft: 1, proprietary: 2, dual: 3, openmdw: 4, unknown: 5,
};

/** SBOM format codes for AI-SBOM.1 AI bill of materials witnessing. */
export const SBOM_FORMAT_CODES: Record<string, number> = {
  cyclonedx: 0, spdx: 1, custom: 2, unknown: 3,
};

/** Red team coverage category codes for AI-REDTEAM.1 adversarial test witnessing. */
export const REDTEAM_CATEGORY_CODES: Record<string, number> = {
  prompt_injection: 0, jailbreak: 1, data_poisoning: 2, model_extraction: 3,
  membership_inference: 4, adversarial_examples: 5, supply_chain: 6,
  denial_of_service: 7, output_manipulation: 8, privilege_escalation: 9,
  comprehensive: 10,
};

/** GDPR lawful basis codes for AI-CONSENT.1 data subject consent witnessing. */
export const CONSENT_BASIS_CODES: Record<string, number> = {
  consent: 0, contract: 1, legal_obligation: 2, vital_interest: 3,
  public_task: 4, legitimate_interest: 5,
};

/** Drift type codes for AI-DRIFT.1 model drift detection. */
export const DRIFT_TYPE_CODES: Record<string, number> = {
  data: 0, concept: 1, prediction: 2, feature: 3, label: 4, prior_probability: 5,
};

/** Log format codes for AI-AUDIT.1 audit log integrity. */
export const LOG_FORMAT_CODES: Record<string, number> = {
  jsonl: 0, syslog: 1, otel: 2, custom: 3,
};

/** Incident severity codes for AI-INCIDENT.1. */
export const INCIDENT_SEVERITY_CODES: Record<string, number> = {
  low: 1, medium: 2, high: 3, critical: 4,
};

/** Incident type codes for AI-INCIDENT.1 incident reporting. */
export const INCIDENT_TYPE_CODES: Record<string, number> = {
  safety: 0, rights: 1, security: 2, performance: 3, bias: 4, other: 5,
};

/** Benchmark type codes for AI-PERF.1 performance metrics. */
export const BENCHMARK_TYPE_CODES: Record<string, number> = {
  accuracy: 0, precision: 1, recall: 2, f1: 3, auc: 4, custom: 5,
};

/** Perturbation type codes for AI-ROBUST.1 robustness testing. */
export const PERTURBATION_TYPE_CODES: Record<string, number> = {
  noise: 0, corruption: 1, missing_data: 2, out_of_distribution: 3, edge_case: 4, adversarial_input: 5,
};

/** Cybersecurity framework codes for AI-CYBER.1. */
export const CYBER_FRAMEWORK_CODES: Record<string, number> = {
  nist_csf: 0, iso27001: 1, owasp: 2, cis: 3, custom: 4,
};

/** Disclosure type codes for AI-TRANS.1 transparency disclosure. */
export const DISCLOSURE_TYPE_CODES: Record<string, number> = {
  ai_usage: 0, data_processing: 1, automated_decision: 2, profiling: 3, capability_limitation: 4,
};

/** Recipient type codes for AI-TRANS.1 transparency disclosure. */
export const RECIPIENT_TYPE_CODES: Record<string, number> = {
  deployer: 0, end_user: 1, data_subject: 2, authority: 3,
};

/** Detection method codes for AI-WATERMARK.1 watermark verification. */
export const DETECTION_METHOD_CODES: Record<string, number> = {
  c2pa_verify: 0, synthid_check: 1, metadata_scan: 2, spectral_analysis: 3, classifier: 4,
};

/** Processing type codes for AI-DPIA.1 data protection impact assessment. */
export const PROCESSING_TYPE_CODES: Record<string, number> = {
  profiling: 0, automated_decision: 1, large_scale_monitoring: 2, sensitive_data: 3, combined: 4,
};

/** Decision type codes for AI-AUTO.1 automated decision notification. */
export const DECISION_TYPE_CODES: Record<string, number> = {
  credit: 0, employment: 1, insurance: 2, benefits: 3, legal: 4, other: 5,
};

/** Classification codes for AI-DUALUSE.1 dual-use model classification. */
export const CLASSIFICATION_CODES: Record<string, number> = {
  standard: 0, dual_use: 1, high_impact: 2,
};

/** Reporting status codes for AI-DUALUSE.1. */
export const REPORTING_STATUS_CODES: Record<string, number> = {
  not_required: 0, pending: 1, notified: 2, acknowledged: 3,
};

/** Supply chain risk level codes for AI-SUPPLY.1. */
export const SUPPLY_RISK_CODES: Record<string, number> = {
  low: 0, medium: 1, high: 2, critical: 3,
};

/** Post-market monitoring type codes for AI-PMM.1. */
export const PMM_TYPE_CODES: Record<string, number> = {
  performance: 0, fairness: 1, safety: 2, security: 3, comprehensive: 4,
};

// ── Declarative Governance Config Types ────────────────────────────────

/** Trust mesh configuration from .swt3.yaml trust_mesh section. */
export interface TrustMeshConfig {
  mode: "strict" | "permissive" | "monitor";
  minTrustLevel: number;
  requireSignature: boolean;
  freshnessWindow: number;
  trustedTenants: string[];
  trustedAgents: { tenant: string; agent: string }[];
  denyAgents: string[];
  denyTenants: string[];
  requiredProcedures: string[];
  signingKeys: { agent: string; key: string }[];
}

/** Hardware runtime profile for config-time topology binding. */
export interface RuntimeProfileConfig {
  expectedTopology?: string;
  minGpuCount?: number;
  minMemoryMb?: number;
  expectedAccelerator?: string;  // substring match against GPU names
  maxTemperatureCelsius?: number;
  maxPowerWatts?: number;
}

/** Hardware attestation configuration from .swt3.yaml hardware section. */
export interface HardwareConfig {
  requireAttestation: boolean;
  attestationFreshness: number;
  allowedMethods: string[];
  runtimeProfile?: RuntimeProfileConfig;
}

/** Skill card configuration from .swt3.yaml skill_card section. */
export interface SkillCardConfig {
  skills: (string | SkillInfo)[];
  expectedManifestHash?: string;
}

/** Density policy configuration from .swt3.yaml density_policy section. */
export interface DensityPolicyConfig {
  minAnchorsPerThousandTokens: number;
  requiredProviders: string[];
  maxChainGapSeconds: number;
  requireSigningKey: boolean;
  minTrustLevel: number;
}

/** A single chain enforcement rule from .swt3.yaml mcp_policy.rules array. */
export interface ChainRule {
  /** Glob pattern matching tool names this rule applies to. "*" = all tools. */
  match: string;
  /** Action on violation: block execution or log and continue. */
  action: "block" | "log";
  /** Human-readable reason shown in violation errors. */
  reason: string;
  /** Optional rule-specific parameters (extensible). */
  params?: Record<string, unknown>;
}

/** Error context for a chain density policy violation. */
export interface ChainPolicyViolation {
  /** Which rule fired (e.g., "velocity", "blocklist", "custom"). */
  rule: string;
  /** Tool name that triggered the violation. */
  toolName: string;
  /** Action taken: "blocked" or "logged". */
  action: "blocked" | "logged";
  /** Human-readable reason. */
  reason: string;
  /** Timestamp of violation (ms since epoch). */
  timestamp: number;
  /** Rule-specific metadata (current count, limit, etc.). */
  context?: Record<string, unknown>;
}

/** MCP tool witnessing policy from .swt3.yaml mcp_policy section. */
export interface McpPolicyConfig {
  /** Glob patterns for tools that MUST be witnessed (e.g., "write_*", "search_*"). */
  witnessedTools: string[];
  /** Glob patterns for tools exempt from witnessing (e.g., "list_files"). */
  exemptTools: string[];
  /** Minimum trust level required before executing any MCP tool. */
  requireTrustLevel: number;
  /** Auto-witness all MCP tool calls without explicit wrapping. */
  autoWitness: boolean;
  /** Block tool execution if witnessing fails (true) or log-only (false). */
  blockOnFailure: boolean;
  /** Rate limit: "N/Xs" format (e.g., "4/30s" = max 4 calls per 30 seconds). */
  maxVelocity?: string;
  /** Maximum sequential dependent tool calls before blocking. */
  maxChainDepth?: number;
  /** Only these tools are permitted. Empty array = all permitted. */
  toolAllowlist?: string[];
  /** These tools are always blocked. */
  toolBlocklist?: string[];
  /** On enforcement error: true = block, false = log and continue. Default true. */
  failSecure?: boolean;
  /** Custom rule objects for extensibility. */
  rules?: ChainRule[];
  /** Maximum cumulative tokens per session before blocking tool execution. */
  maxTokensPerSession?: number;
}

/** Merkle accumulator configuration from .swt3.yaml merkle section. */
export interface MerkleConfig {
  /** Enable SDK-side Merkle accumulator. */
  enabled: boolean;
  /** Interval in seconds for session root computation (0 = on every flush). */
  accumulatorInterval: number;
}

/** Parsed policy rules from .swt3.yaml policy section. */
export interface PolicyConfig {
  requireSigning?: boolean;
  minClearingLevel?: number;
  requiredProcedures?: string[];
  requireAgentId?: boolean;
  maxFlushInterval?: number;
  requireJurisdiction?: boolean;
}

/** Full parsed config returned by loadFullConfig(). */
export interface LoadedConfig {
  witnessOptions: Record<string, unknown>;
  trustMesh: TrustMeshConfig | null;
  hardware: HardwareConfig | null;
  skillCard: SkillCardConfig | null;
  densityPolicy: DensityPolicyConfig | null;
  mcpPolicy: McpPolicyConfig | null;
  merkle: MerkleConfig | null;
  policy: PolicyConfig | null;
  configHash: string;
}
