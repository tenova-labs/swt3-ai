/**
 * @tenova/swt3-ai — SWT3 AI Witness SDK for TypeScript/Node.js
 *
 * Usage:
 *   import { Witness } from "@tenova/swt3-ai";
 *   import OpenAI from "openai";
 *
 *   const witness = new Witness({
 *     endpoint: "https://sovereign.tenova.io",
 *     apiKey: "axm_live_...",
 *     tenantId: "YOUR_TENANT_ID",
 *   });
 *
 *   const client = witness.wrap(new OpenAI()) as OpenAI;
 */

export { Witness, GatekeeperError, ChainTrustError, ChainEnforcer, PolicyViolationError } from "./witness.js";
export { ChainMonitorExporter } from "./exporters/chain-monitor.js";
export type { ChainMonitorOptions, AuditReport, TimelineEntry } from "./exporters/chain-monitor.js";
export { EvidenceExporter } from "./exporters/evidence.js";
export type { EvidenceBundleOptions, EvidenceBundleMetadata, EvidenceBundle } from "./exporters/evidence.js";
export type { WitnessOptions } from "./witness.js";
export type {
  WitnessConfig,
  WitnessPayload,
  WitnessReceipt,
  InferenceRecord,
  BatchResponse,
  RagChunk,
  RagContextOptions,
  ModelWeightInfo,
  AdapterInfo,
  SkillInfo,
  MemorySource,
} from "./types.js";
export { QUANTIZATION_CODES, POLICY_CATEGORIES, BINDING_METHODS, APPROVAL_STATUS, PII_EVENT_TYPES, CONTENT_TYPE_CODES, MARKING_METHODS, BASELINE_MODE_CODES } from "./types.js";
export { mintFingerprint, sha256Truncated, sha256Hex, timestampMs } from "./fingerprint.js";
export { extractPayloads, extractGatekeeperPayload, extractRevocationPayload, extractChainTrustDegradationPayload, REVOCATION_REASONS } from "./clearing.js";
export { signPayload } from "./signing.js";
export { loadConfig, loadFullConfig, computeConfigHash } from "./config.js";
export type { TrustMeshConfig, HardwareConfig, RuntimeProfileConfig, SkillCardConfig, DensityPolicyConfig, McpPolicyConfig, MerkleConfig, LoadedConfig, ChainRule, ChainPolicyViolation } from "./types.js";
export { validateSchema } from "./schema.js";
export type { ValidationResult, ValidationError } from "./schema.js";
export { WriteAheadLog } from "./wal.js";
export type { WalOptions } from "./wal.js";
export { wrapOllama, isOllamaClient } from "./adapters/ollama.js";
export { wrapVllm } from "./adapters/vllm.js";
export { queryHardware, detectTopology, topologyCode, TOPOLOGY_CODES, queryTPM, parseTPMPcrOutput, ZERO_PCR_HASH } from "./hardware.js";
export type { GpuInfo, HardwareSnapshot, TPMSnapshot, PcrRegister } from "./hardware.js";
export {
  hashLeaf, hashNode, getMerkleRoot, getMerkleProof, verifyMerkleProof,
  MerkleAccumulator,
} from "./merkle.js";
export type { MerkleProof, MerkleProofStep, SessionRoot, MerkleAccumulatorOptions } from "./merkle.js";
export { queryEnvironment, NODE_TYPE_CODES } from "./environment.js";
export type { EnvironmentSnapshot } from "./environment.js";
export {
  TrustRegistry, verifyCredential, evaluateTrustLevel,
  signCredential, verifyCredentialSignature, buildCredentialMessage,
  TRUST_DENIED, TRUST_BASIC, TRUST_VERIFIED, TRUST_ATTESTED, TRUST_SOVEREIGN,
  TRUST_LEVEL_NAMES,
} from "./trust.js";
export type { TrustCredential, TrustResult } from "./trust.js";
export { SentinelClient } from "./sentinel-client.js";
export type { SentinelClientOptions, SentinelCheckResult, SentinelStatusResult } from "./sentinel-client.js";
