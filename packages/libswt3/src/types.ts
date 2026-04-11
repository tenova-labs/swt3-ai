// ── SWT3 Protocol Types ───────────────────────────────────────────
//
// Zero-dependency type definitions for the SWT3 protocol.
// See SWT3-SPEC-v1.0.md for the full specification.

/** Deployment tier of the witnessed environment. */
export type Tier = "E" | "S" | "H";

/** Infrastructure provider identifier. */
export type Provider = "VULTR" | "AWS" | "AZURE" | "GCP" | "HYBRID" | "ON-PREM";

/** Universal Control Taxonomy — Core codes (required). */
export type UCTCore = "ACC" | "AUD" | "CFG" | "CRY" | "IDN" | "INT" | "NET" | "BCP" | "GOV" | "IRP" | "PHY";

/** Universal Control Taxonomy — Extended codes (optional per implementation). */
export type UCTExtended = "ACQ" | "AI" | "CHG" | "CON" | "DEV" | "EVI" | "FIN" | "HCF" | "HRS" | "MON" | "OT" | "PRI" | "RSK" | "TRN" | "VUL";

/** Universal Control Taxonomy category (UCT Registry v1.0). */
export type UCT = UCTCore | UCTExtended;

/** Compliance verdict. */
export type Verdict = "PASS" | "FAIL" | "INHERITED" | "LAPSED" | "UNKNOWN";

/** The three measurable inputs to a compliance determination. */
export interface Factors {
  procedure_id: string;
  tenant_id: string;
  factor_a: number;
  factor_b: number;
  factor_c: number;
  timestamp_ms: number;
}

/** Parsed components of an SWT3 anchor token. */
export interface AnchorComponents {
  protocol: "SWT3";
  tier: string;
  provider: string;
  uct: string;
  procedure: string;
  verdict: string;
  epoch: number;
  fingerprint: string;
}

/** Parameters for minting a new SWT3 anchor. */
export interface MintParams {
  tier: Tier;
  provider: Provider;
  uct: UCT;
  procedure_id: string;
  tenant_id: string;
  verdict: Verdict;
  factor_a: number;
  factor_b: number;
  factor_c: number;
  /** Millisecond-precision timestamp. If omitted, Date.now() is used. */
  timestamp_ms?: number;
}

/** Result of anchor minting. */
export interface MintResult {
  anchor: string;
  fingerprint: string;
  fingerprint_full: string;
  epoch: number;
  timestamp_ms: number;
  factors: Factors;
}

/** Result of anchor verification. */
export interface VerifyResult {
  verified: boolean;
  status: "CERTIFIED TRUTH" | "TAMPERED" | "INVALID TOKEN" | "MISSING INPUT";
  claimed_fingerprint: string;
  recomputed_fingerprint: string;
  factors?: Factors;
}

/** Enclave integrity summary. */
export interface EnclaveIntegrity {
  total: number;
  verified: number;
  tampered: number;
  enclave_signature: string;
  /** Tamper-evident integrity digest for rollup verification. */
  integrity_digest?: string;
}

/** Internal: proof step (not exported from public API). */
export interface MerkleProofStep {
  hash: string;
  position: "left" | "right";
}

/** Internal: inclusion proof (not exported from public API). */
export interface MerkleProof {
  fingerprint: string;
  leaf_hash: string;
  root: string;
  steps: MerkleProofStep[];
}

/** Canonical JSON transport format for SWT3 evidence (Spec Section 8.1). */
export interface EvidenceFactor {
  swt3_version: "1.0";
  anchor: string;
  factors: Factors;
  verdict: Verdict;
  witnessed_at: string;
  metadata?: Record<string, unknown>;
}
