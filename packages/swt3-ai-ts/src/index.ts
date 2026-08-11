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

export { Witness, GatekeeperError, ChainTrustError, ChainEnforcer, PolicyViolationError, LifecycleChain, ChainContext, LIFECYCLE_CHAIN_STAGES, OVERRIDE_TRIGGER_CODES, AUTHORIZATION_LEVEL_CODES, FALLBACK_STATE_CODES, CONSEQUENCE_CATEGORY_CODES, DRIFT_RESPONSE_CODES, REACHABILITY_METHOD_CODES, DISPOSAL_METHOD_CODES, RECOMMISSION_TYPE_CODES, LOCK_SCOPE_CODES } from "./witness.js";
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
  AnchorReference,
  ProcedureAttestation,
  ModelTrustProfile,
  CoverageResult,
  ChainLink,
  ChainSummary,
} from "./types.js";
export { QUANTIZATION_CODES, POLICY_CATEGORIES, BINDING_METHODS, APPROVAL_STATUS, PII_EVENT_TYPES, CONTENT_TYPE_CODES, MARKING_METHODS, BASELINE_MODE_CODES, LICENSE_TYPE_CODES, SBOM_FORMAT_CODES, REDTEAM_CATEGORY_CODES, CONSENT_BASIS_CODES, DRIFT_TYPE_CODES, LOG_FORMAT_CODES, INCIDENT_SEVERITY_CODES, INCIDENT_TYPE_CODES, BENCHMARK_TYPE_CODES, PERTURBATION_TYPE_CODES, CYBER_FRAMEWORK_CODES, DISCLOSURE_TYPE_CODES, RECIPIENT_TYPE_CODES, DETECTION_METHOD_CODES, PROCESSING_TYPE_CODES, DECISION_TYPE_CODES, CLASSIFICATION_CODES, REPORTING_STATUS_CODES, SUPPLY_RISK_CODES, PMM_TYPE_CODES, LIFECYCLE_STAGE_CODES, DESIGN_DOMAIN_CODES, SIMULATION_TYPE_CODES, APPROVAL_TYPE_CODES, MATERIAL_STANDARD_CODES, CHAIN_STATUS_CODES, RELEASE_TYPE_CODES, SAFETY_CLASSIFICATION_CODES } from "./types.js";
export { mintFingerprint, sha256Truncated, sha256Hex, timestampMs, generateLifecycleChainId } from "./fingerprint.js";
export { extractPayloads, extractGatekeeperPayload, extractRevocationPayload, extractChainTrustDegradationPayload, REVOCATION_REASONS } from "./clearing.js";
export { signPayload, generateMldsaKeypair, verifyMldsa, SIGNING_ALGORITHM_HMAC, SIGNING_ALGORITHM_MLDSA, VALID_SIGNING_ALGORITHMS, DEFAULT_SIGNING_ALGORITHM } from "./signing.js";
export type { SigningAlgorithm } from "./signing.js";
export { loadConfig, loadFullConfig, computeConfigHash } from "./config.js";
export { loadGateConfig, parseGateDict, parseMaxAge, findGateFile, validateProcedures, allProcedures } from "./gate.js";
export type { GateConfig, GateProcedure, GateGroup, FrameworkGate, GateModel, GateDefaults } from "./gate.js";
export type { TrustMeshConfig, HardwareConfig, RuntimeProfileConfig, SkillCardConfig, DensityPolicyConfig, McpPolicyConfig, MerkleConfig, LoadedConfig, ChainRule, ChainPolicyViolation } from "./types.js";
export { validateSchema } from "./schema.js";
export type { ValidationResult, ValidationError } from "./schema.js";
export { WriteAheadLog } from "./wal.js";
export type { WalOptions } from "./wal.js";
export { wrapOllama, isOllamaClient } from "./adapters/ollama.js";
export { wrapVllm } from "./adapters/vllm.js";
export { wrapGoogleADK } from "./adapters/google-adk.js";
export { wrapCrewAI } from "./adapters/crewai.js";
export { wrapA2A } from "./adapters/a2a.js";
export { wrapFoundry } from "./adapters/foundry.js";
export { wrapAGT } from "./adapters/agt.js";
export { wrapLangGraph } from "./adapters/langgraph.js";
export { queryHardware, detectTopology, topologyCode, TOPOLOGY_CODES, queryTPM, parseTPMPcrOutput, ZERO_PCR_HASH, queryGoogleTPU, queryAmdRocm, queryAwsNeuron, queryIntelGaudi, queryPciFallback } from "./hardware.js";
export type { GpuInfo, HardwareSnapshot, TPMSnapshot, PcrRegister, AcceleratorInfo, SiliconVendor } from "./hardware.js";
export {
  hashLeaf, hashNode, getMerkleRoot, getMerkleProof, verifyMerkleProof,
  MerkleAccumulator,
} from "./merkle.js";
export type { MerkleProof, MerkleProofStep, SessionRoot, MerkleAccumulatorOptions } from "./merkle.js";
export { detectDeploymentContext, contextToObservations, resetCache as resetDeploymentCache } from "./deployment.js";
export type { DeploymentContext } from "./deployment.js";
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
export { generateProfile, signProfile, verifyProfileSignature, isProfileValid, coverageScore, buildProfileMessage, RECOMMENDED_PROCEDURES } from "./profile.js";
export type { GenerateProfileOptions } from "./profile.js";
export { buildLookup, walkChain, verifyChainIntegrity } from "./chain.js";
export { resolve, resolveFramework, frameworks as crosswalkFrameworks, procedures as crosswalkProcedures, crosswalkVersion, frameworksForJurisdiction } from "./crosswalk.js";
export type { FrameworkMeta, ProcedureMeta, JurisdictionFramework } from "./crosswalk.js";
