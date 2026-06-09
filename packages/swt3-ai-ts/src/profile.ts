/**
 * SWT3 AI Witness SDK -- Model Trust Profiles.
 *
 * Portable, cryptographically signed summaries of a model's compliance posture.
 * Profiles bind a model artifact hash to its attestation coverage and can be
 * verified offline without network calls.
 */

import { createHmac } from "node:crypto";
import type { AnchorReference, ProcedureAttestation, ModelTrustProfile, CoverageResult } from "./types.js";

/** Recommended procedure sets by compliance profile. */
export const RECOMMENDED_PROCEDURES: Record<string, string[]> = {
  minimal: ["AI-INF.1"],
  standard: ["AI-INF.1", "AI-INF.2", "AI-MDL.1", "AI-MDL.2", "AI-GRD.1", "AI-GRD.2"],
  "eu-ai-act-high-risk": ["AI-INF.1", "AI-GRD.1", "AI-FAIR.1", "AI-EXPL.1", "AI-DATA.1", "AI-HITL.1"],
  "nist-ai-rmf": ["AI-INF.1", "AI-GRD.1", "AI-MDL.1"],
  "defense-govcon": ["AI-INF.1", "AI-GRD.1", "AI-MDL.1", "AI-ID.1", "AI-SEC.1"],
  "healthcare-clinical": ["AI-INF.1", "AI-GRD.1", "AI-FAIR.1", "AI-DATA.1", "AI-HITL.1", "AI-EXPL.1"],
  "fintech-model-risk": ["AI-INF.1", "AI-GRD.1", "AI-MDL.1", "AI-FAIR.1", "AI-EXPL.1"],
};

export interface GenerateProfileOptions {
  modelId: string;
  modelHash: string;
  attestations: ProcedureAttestation[];
  upstreamReferences?: AnchorReference[];
  ttlMs?: number;
  signingKey?: string;
  signingKeyId?: string;
  nowMs?: number;
}

/**
 * Build a canonical message string for profile signing.
 * Format: PROFILE:{model_id}:{model_hash}:{generated_at}:{valid_until}:{sorted_procedures}:{score_3dp}
 */
export function buildProfileMessage(profile: ModelTrustProfile): string {
  const procs = [...profile.coverage.map((a) => a.procedure)].sort().join(",");
  const score3dp = profile.coverage_score.toFixed(3);
  return `PROFILE:${profile.model_id}:${profile.model_hash}:${profile.generated_at}:${profile.valid_until}:${procs}:${score3dp}`;
}

/**
 * Sign a ModelTrustProfile with HMAC-SHA256.
 */
export function signProfile(profile: ModelTrustProfile, signingKey: string): string {
  const message = buildProfileMessage(profile);
  return createHmac("sha256", signingKey).update(message, "utf-8").digest("hex");
}

/**
 * Verify a profile signature against a known signing key.
 * Constant-time comparison to prevent timing attacks.
 */
export function verifyProfileSignature(profile: ModelTrustProfile, signingKey: string): boolean {
  if (!profile.signature) return false;
  const expected = signProfile(profile, signingKey);
  if (expected.length !== profile.signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ profile.signature.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Check whether a profile is still within its validity window.
 */
export function isProfileValid(profile: ModelTrustProfile, nowMs?: number): boolean {
  return (nowMs ?? Date.now()) <= profile.valid_until;
}

/**
 * Generate a ModelTrustProfile from attestation data.
 */
export function generateProfile(opts: GenerateProfileOptions): ModelTrustProfile {
  const now = opts.nowMs ?? Date.now();
  const ttl = opts.ttlMs ?? 86_400_000; // 24h default
  const passing = opts.attestations.filter((a) => a.status === "pass").length;
  const score = opts.attestations.length > 0 ? passing / opts.attestations.length : 0;

  const profile: ModelTrustProfile = {
    model_id: opts.modelId,
    model_hash: opts.modelHash,
    coverage: opts.attestations,
    coverage_score: score,
    upstream_references: opts.upstreamReferences ?? [],
    generated_at: now,
    valid_until: now + ttl,
    signing_key_id: opts.signingKeyId,
  };

  if (opts.signingKey) {
    profile.signature = signProfile(profile, opts.signingKey);
  }

  return profile;
}

/**
 * Calculate coverage against a target procedure set.
 *
 * @param attestedProcedures - Procedure IDs the model has passing attestations for.
 * @param target - Profile name (key into RECOMMENDED_PROCEDURES) or custom array. Default: "standard".
 */
export function coverageScore(attestedProcedures: string[], target?: string | string[]): CoverageResult {
  let targetSet: string[];
  if (target === undefined) {
    targetSet = RECOMMENDED_PROCEDURES["standard"];
  } else if (typeof target === "string") {
    const resolved = RECOMMENDED_PROCEDURES[target];
    if (!resolved) {
      throw new Error(`Unknown profile: "${target}". Available: ${Object.keys(RECOMMENDED_PROCEDURES).join(", ")}`);
    }
    targetSet = resolved;
  } else {
    targetSet = target;
  }

  const targetLookup = new Set(targetSet);
  const attestedLookup = new Set(attestedProcedures);
  const covered = targetSet.filter((p) => attestedLookup.has(p));
  const missing = targetSet.filter((p) => !attestedLookup.has(p));
  const extra = attestedProcedures.filter((p) => !targetLookup.has(p));
  const score = targetSet.length > 0 ? covered.length / targetSet.length : 0;

  return { score, covered, missing, extra, target: targetSet };
}
