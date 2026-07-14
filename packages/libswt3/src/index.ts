// ── libswt3 — SWT3 Protocol Reference Implementation ──────────────
//
// Sovereign Witness Traceability Protocol v1.0
// Provenance → Verification → Clearing
// Zero-dependency, open-source, auditor-verifiable.
//
// See SWT3-SPEC-v1.0.md for the full protocol specification.
//
// Copyright (c) 2026 Tenable Nova LLC — Apache 2.0 — Patent pending

export { mintAnchor, parseAnchor, extractFingerprint } from "./anchor.js";
export {
  generateFingerprint,
  generateFingerprintFull,
  sha256,
  computeEnclaveSignature,
  buildFingerprintInput,
  FINGERPRINT_LENGTH,
} from "./fingerprint.js";
export { verifyAnchor, verifyEnclave } from "./verify.js";
export {
  generateLifecycleChainId,
  isLifecycleChainId,
  validateLifecycleStage,
  isTerminalStage,
  isValidFingerprint,
} from "./lifecycle.js";
export type {
  Tier,
  Provider,
  UCT,
  Verdict,
  Factors,
  AnchorComponents,
  MintParams,
  MintResult,
  VerifyResult,
  EnclaveIntegrity,
  EvidenceFactor,
  LifecycleStage,
  LifecycleChainMeta,
} from "./types.js";
export { LIFECYCLE_CHAIN_STAGES } from "./types.js";
