/**
 * SWT3 AI Witness SDK -- Agent Trust Mesh (AI-TRUST.1 / AI-TRUST.2).
 *
 * Mutual compliance trust verification between AI agents.
 * Before two agents exchange data, invoke tools, or share context,
 * each verifies the other's SWT3 compliance anchor.
 *
 * Credentials are HMAC-signed to prevent forgery and escalation.
 * Unsigned credentials are capped at TRUST_BASIC.
 *
 * Zero external dependencies. All verification is local (no network calls).
 */

import { createHmac, randomBytes } from "node:crypto";

export const TRUST_DENIED = 0;
export const TRUST_BASIC = 1;
export const TRUST_VERIFIED = 2;
export const TRUST_ATTESTED = 3;
export const TRUST_SOVEREIGN = 4;

export const TRUST_LEVEL_NAMES: Record<number, string> = {
  0: "denied",
  1: "basic",
  2: "verified",
  3: "attested",
  4: "sovereign",
};

export const DENIAL_ANCHOR_NOT_FOUND = "anchor_not_found";
export const DENIAL_ANCHOR_EXPIRED = "anchor_expired";
export const DENIAL_ANCHOR_REVOKED = "anchor_revoked";
export const DENIAL_SIGNATURE_MISSING = "signature_missing";
export const DENIAL_TENANT_NOT_TRUSTED = "tenant_not_trusted";
export const DENIAL_DENY_LISTED = "deny_listed";
export const DENIAL_INSUFFICIENT_PROCEDURES = "insufficient_procedures";
export const DENIAL_SIGNATURE_INVALID = "signature_invalid";
export const DENIAL_SIGNATURE_UNVERIFIABLE = "signature_unverifiable";
export const DENIAL_INSUFFICIENT_TRUST_LEVEL = "insufficient_trust_level";
export const DENIAL_TIMESTAMP_FUTURE = "timestamp_future";
export const DENIAL_RATE_LIMITED = "rate_limited";

export interface TrustCredential {
  agentId: string;
  tenantId: string;
  anchorFingerprint: string;
  anchorTimestampMs: number;
  isSigned?: boolean;
  procedures?: string[];
  clearingLevel?: number;
  hasHardwareAttestation?: boolean;
  hasGuardrails?: boolean;
  credentialSignature?: string;
  governancePolicyHash?: string;
  governanceVersion?: number;
}

export interface TrustResult {
  granted: boolean;
  trustLevel: number;
  denialReason?: string;
  checksPerformed: number;
  checksPassed: number;
  counterpartAgentId: string;
  counterpartTenantId: string;
}

export interface DenyEvent {
  type: "agent" | "tenant";
  target: string;
  reason: string;
  timestamp: number;
}

/** Sliding-window rate limiter for verification attempts. */
class RateLimiter {
  private attempts = new Map<string, number[]>();
  private maxFailures: number;
  private windowMs: number;

  constructor(maxFailures: number, windowMs: number) {
    this.maxFailures = maxFailures;
    this.windowMs = windowMs;
  }

  isExceeded(source: string): boolean {
    const now = Date.now();
    const history = this.attempts.get(source);
    if (!history) return false;
    const recent = history.filter((t) => now - t < this.windowMs);
    this.attempts.set(source, recent);
    return recent.length >= this.maxFailures;
  }

  recordFailure(source: string): void {
    const history = this.attempts.get(source) ?? [];
    history.push(Date.now());
    this.attempts.set(source, history);
  }
}

export class TrustRegistry {
  private trustedTenants = new Set<string>();
  private trustedAgents = new Set<string>();
  private deniedAgents = new Set<string>();
  private deniedTenants = new Set<string>();
  private signingKeys = new Map<string, string>();
  private requiredProcedures: string[] = [];
  private freshnessWindowMs = 24 * 60 * 60 * 1000;
  private requireSignature = false;
  private minTrustLevel = TRUST_BASIC;
  private requireIntraTenantSigning = false;
  private rateLimiter: RateLimiter | null = null;
  private perLevelFreshnessMs: Map<number, number> | null = null;
  private verifyBooleanClaims = false;
  private denyEventListeners: Array<(event: DenyEvent) => void> = [];

  trustTenant(tenantId: string): void {
    this.trustedTenants.add(tenantId);
    this.deniedTenants.delete(tenantId);
  }

  trustAgent(tenantId: string, agentId: string): void {
    this.trustedAgents.add(`${tenantId}:${agentId}`);
  }

  denyAgent(agentId: string, reason = "manual"): void {
    this.deniedAgents.add(agentId);
    this._emitDenyEvent({ type: "agent", target: agentId, reason, timestamp: Date.now() });
  }

  denyTenant(tenantId: string, reason = "manual"): void {
    this.deniedTenants.add(tenantId);
    this.trustedTenants.delete(tenantId);
    this._emitDenyEvent({ type: "tenant", target: tenantId, reason, timestamp: Date.now() });
  }

  registerSigningKey(agentId: string, key: string): void {
    this.signingKeys.set(agentId, key);
  }

  setRequiredProcedures(procedures: string[]): void {
    this.requiredProcedures = procedures;
  }

  setFreshnessWindow(seconds: number): void {
    this.freshnessWindowMs = seconds * 1000;
  }

  setRequireSignature(require: boolean): void {
    this.requireSignature = require;
  }

  setMinTrustLevel(level: number): void {
    this.minTrustLevel = Math.max(0, Math.min(4, level));
  }

  setRequireIntraTenantSigning(require: boolean): void {
    this.requireIntraTenantSigning = require;
  }

  setRateLimit(maxFailures: number, windowSeconds: number): void {
    this.rateLimiter = new RateLimiter(maxFailures, windowSeconds * 1000);
  }

  setPerLevelFreshness(windows: Record<number, number>): void {
    this.perLevelFreshnessMs = new Map();
    for (const [level, seconds] of Object.entries(windows)) {
      this.perLevelFreshnessMs.set(Number(level), seconds * 1000);
    }
  }

  setVerifyBooleanClaims(verify: boolean): void {
    this.verifyBooleanClaims = verify;
  }

  onDenyEvent(listener: (event: DenyEvent) => void): void {
    this.denyEventListeners.push(listener);
  }

  applyRevocationEvent(event: { agentId?: string; tenantId?: string; reason: string }): void {
    if (event.agentId) {
      this.deniedAgents.add(event.agentId);
      this._emitDenyEvent({ type: "agent", target: event.agentId, reason: event.reason, timestamp: Date.now() });
    }
    if (event.tenantId) {
      this.deniedTenants.add(event.tenantId);
      this.trustedTenants.delete(event.tenantId);
      this._emitDenyEvent({ type: "tenant", target: event.tenantId, reason: event.reason, timestamp: Date.now() });
    }
  }

  isAgentDenied(agentId: string): boolean {
    return this.deniedAgents.has(agentId);
  }

  isTenantDenied(tenantId: string): boolean {
    return this.deniedTenants.has(tenantId);
  }

  isTenantTrusted(tenantId: string, ownTenantId: string): boolean {
    if (tenantId === ownTenantId && !this.requireIntraTenantSigning) return true;
    return this.trustedTenants.has(tenantId);
  }

  isAgentTrusted(tenantId: string, agentId: string, ownTenantId: string): boolean {
    if (this.isAgentDenied(agentId)) return false;
    if (this.isTenantDenied(tenantId)) return false;
    if (this.isTenantTrusted(tenantId, ownTenantId)) return true;
    return this.trustedAgents.has(`${tenantId}:${agentId}`);
  }

  /** @internal */
  get _freshnessWindowMs(): number { return this.freshnessWindowMs; }
  /** @internal */
  get _requireSignature(): boolean { return this.requireSignature; }
  /** @internal */
  get _requiredProcedures(): string[] { return this.requiredProcedures; }
  /** @internal */
  get _minTrustLevel(): number { return this.minTrustLevel; }
  /** @internal */
  get _rateLimiter(): RateLimiter | null { return this.rateLimiter; }
  /** @internal */
  get _perLevelFreshnessMs(): Map<number, number> | null { return this.perLevelFreshnessMs; }
  /** @internal */
  get _verifyBooleanClaims(): boolean { return this.verifyBooleanClaims; }
  /** @internal */
  getSigningKey(agentId: string): string | undefined { return this.signingKeys.get(agentId); }

  private _emitDenyEvent(event: DenyEvent): void {
    for (const listener of this.denyEventListeners) {
      listener(event);
    }
  }
}

/**
 * Build the deterministic message used for credential signing/verification.
 * Formula is LOCKED for cross-language parity.
 */
export function buildCredentialMessage(credential: TrustCredential): string {
  const procs = [...(credential.procedures ?? [])].sort().join(",");
  return `${credential.agentId}:${credential.tenantId}:${credential.anchorFingerprint}:${credential.anchorTimestampMs}:${credential.isSigned ? 1 : 0}:${credential.hasHardwareAttestation ? 1 : 0}:${credential.hasGuardrails ? 1 : 0}:${credential.clearingLevel ?? 0}:${procs}`;
}

/**
 * Sign a credential with HMAC-SHA256.
 */
export function signCredential(credential: TrustCredential, signingKey: string): string {
  const message = buildCredentialMessage(credential);
  return createHmac("sha256", signingKey).update(message, "utf-8").digest("hex");
}

/**
 * Verify a credential signature against a known signing key.
 */
export function verifyCredentialSignature(credential: TrustCredential, signingKey: string): boolean {
  if (!credential.credentialSignature) return false;
  const expected = signCredential(credential, signingKey);
  // Constant-time comparison to prevent timing attacks
  if (expected.length !== credential.credentialSignature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ credential.credentialSignature.charCodeAt(i);
  }
  return diff === 0;
}

export function evaluateTrustLevel(credential: TrustCredential): number {
  if (!credential.isSigned) return TRUST_BASIC;
  if (!credential.hasHardwareAttestation || !credential.hasGuardrails) return TRUST_VERIFIED;
  if ((credential.clearingLevel ?? 1) < 2) return TRUST_ATTESTED;
  return TRUST_SOVEREIGN;
}

export function verifyCredential(
  credential: TrustCredential,
  registry: TrustRegistry,
  ownTenantId: string,
): TrustResult {
  let checks = 0;
  let passed = 0;
  const base = {
    counterpartAgentId: credential.agentId,
    counterpartTenantId: credential.tenantId,
  };

  const denied = (reason: string, recordRateLimit = true): TrustResult => {
    if (recordRateLimit && registry._rateLimiter) {
      registry._rateLimiter.recordFailure(credential.agentId);
    }
    return {
      granted: false, trustLevel: TRUST_DENIED, denialReason: reason,
      checksPerformed: checks, checksPassed: passed, ...base,
    };
  };

  // Check 0: rate limiting
  if (registry._rateLimiter && registry._rateLimiter.isExceeded(credential.agentId)) {
    return denied(DENIAL_RATE_LIMITED, false);
  }

  // Check 1: deny list
  checks++;
  if (registry.isAgentDenied(credential.agentId)) return denied(DENIAL_DENY_LISTED);
  if (registry.isTenantDenied(credential.tenantId)) return denied(DENIAL_DENY_LISTED);
  passed++;

  // Check 2: tenant trust
  checks++;
  if (!registry.isAgentTrusted(credential.tenantId, credential.agentId, ownTenantId)) {
    return denied(DENIAL_TENANT_NOT_TRUSTED);
  }
  passed++;

  // Check 3: basic freshness (default window)
  checks++;
  const now = Date.now();
  const ageMs = now - credential.anchorTimestampMs;
  if (ageMs > registry._freshnessWindowMs) return denied(DENIAL_ANCHOR_EXPIRED);
  // Reject future-dated credentials (allow 60s clock skew)
  if (credential.anchorTimestampMs > now + 60_000) return denied(DENIAL_TIMESTAMP_FUTURE);
  passed++;

  // Check 4: signing key presence
  checks++;
  if (registry._requireSignature && !credential.isSigned) return denied(DENIAL_SIGNATURE_MISSING);
  passed++;

  // Check 5: credential signature verification
  let signatureVerified = false;
  if (credential.credentialSignature) {
    checks++;
    const counterpartKey = registry.getSigningKey(credential.agentId);
    if (!counterpartKey) {
      return denied(DENIAL_SIGNATURE_UNVERIFIABLE);
    }
    if (!verifyCredentialSignature(credential, counterpartKey)) {
      return denied(DENIAL_SIGNATURE_INVALID);
    }
    signatureVerified = true;
    passed++;
  }

  // Check 6: procedures
  if (registry._requiredProcedures.length > 0) {
    checks++;
    const credProcs = new Set(credential.procedures ?? []);
    if (!registry._requiredProcedures.every((p) => credProcs.has(p))) {
      return denied(DENIAL_INSUFFICIENT_PROCEDURES);
    }
    passed++;
  }

  let level = evaluateTrustLevel(credential);

  // Cap: unsigned or unverifiable credentials cannot exceed TRUST_BASIC
  if (!signatureVerified && level > TRUST_BASIC) {
    level = TRUST_BASIC;
  }

  // Check 7: per-level freshness (stricter windows for higher trust levels)
  if (registry._perLevelFreshnessMs) {
    const levelFreshness = registry._perLevelFreshnessMs.get(level);
    if (levelFreshness !== undefined && ageMs > levelFreshness) {
      return denied(DENIAL_ANCHOR_EXPIRED);
    }
  }

  // Check 8: verifiable boolean claims (degrade, don't deny)
  if (registry._verifyBooleanClaims) {
    const credProcs = new Set(credential.procedures ?? []);
    if (credential.hasHardwareAttestation && !credProcs.has("AI-HW.1")) {
      level = TRUST_BASIC;
    }
    if (credential.hasGuardrails && ![...credProcs].some((p) => p.startsWith("AI-GRD."))) {
      level = TRUST_BASIC;
    }
  }

  if (level < registry._minTrustLevel) {
    return denied(DENIAL_INSUFFICIENT_TRUST_LEVEL);
  }

  return {
    granted: true, trustLevel: level,
    checksPerformed: checks, checksPassed: passed, ...base,
  };
}

// ── Task 6: Key Attestation ──────────────────────────────────────────

export interface KeyAttestation {
  agentId: string;
  publicKey: string;
  anchorFingerprint: string;
  anchorTimestampMs: number;
  keyPurpose: "signing" | "encryption" | "delegation";
  attestationProof: string;
}

/**
 * Generate a key attestation binding a public key to an anchor fingerprint.
 * The attestation proof is HMAC(agentId:publicKey:fingerprint:timestamp:purpose, signingKey).
 */
export function generateKeyAttestation(
  agentId: string,
  publicKey: string,
  anchorFingerprint: string,
  anchorTimestampMs: number,
  signingKey: string,
  keyPurpose: "signing" | "encryption" | "delegation" = "signing",
): KeyAttestation {
  const message = `${agentId}:${publicKey}:${anchorFingerprint}:${anchorTimestampMs}:${keyPurpose}`;
  const proof = createHmac("sha256", signingKey).update(message, "utf-8").digest("hex");
  return { agentId, publicKey, anchorFingerprint, anchorTimestampMs, keyPurpose, attestationProof: proof };
}

/**
 * Verify a key attestation against a known signing key.
 * Returns true if the attestation proof is valid.
 */
export function verifyKeyAttestation(attestation: KeyAttestation, signingKey: string): boolean {
  const message = `${attestation.agentId}:${attestation.publicKey}:${attestation.anchorFingerprint}:${attestation.anchorTimestampMs}:${attestation.keyPurpose}`;
  const expected = createHmac("sha256", signingKey).update(message, "utf-8").digest("hex");
  if (expected.length !== attestation.attestationProof.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ attestation.attestationProof.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Check if a key attestation is fresh (bound anchor not expired).
 */
export function isKeyAttestationFresh(attestation: KeyAttestation, freshnessWindowMs: number): boolean {
  return (Date.now() - attestation.anchorTimestampMs) <= freshnessWindowMs;
}

// ── Task 7: Challenge-Response Liveness ──────────────────────────────

export interface LivenessChallenge {
  nonce: string;
  challengeTimestampMs: number;
  targetAgentId: string;
}

export interface LivenessResponse {
  nonce: string;
  challengeTimestampMs: number;
  agentId: string;
  anchorFingerprint: string;
  responseSignature: string;
}

export interface LivenessResult {
  valid: boolean;
  reason?: string;
}

/**
 * Generate a liveness challenge for a target agent.
 * The nonce is 32 random bytes encoded as hex.
 */
export function generateChallenge(targetAgentId: string): LivenessChallenge {
  return {
    nonce: randomBytes(32).toString("hex"),
    challengeTimestampMs: Date.now(),
    targetAgentId,
  };
}

/**
 * Respond to a liveness challenge by signing the challenge data with the agent's key.
 * Signed message: agentId:anchorFingerprint:nonce:challengeTimestamp
 */
export function respondToChallenge(
  challenge: LivenessChallenge,
  agentId: string,
  anchorFingerprint: string,
  signingKey: string,
): LivenessResponse {
  const message = `${agentId}:${anchorFingerprint}:${challenge.nonce}:${challenge.challengeTimestampMs}`;
  const signature = createHmac("sha256", signingKey).update(message, "utf-8").digest("hex");
  return {
    nonce: challenge.nonce,
    challengeTimestampMs: challenge.challengeTimestampMs,
    agentId,
    anchorFingerprint,
    responseSignature: signature,
  };
}

/**
 * Verify a liveness response against the original challenge.
 * Checks: nonce match, timestamp match, signature validity, timeout.
 */
export function verifyLivenessResponse(
  response: LivenessResponse,
  challenge: LivenessChallenge,
  signingKey: string,
  timeoutMs = 5000,
): LivenessResult {
  // Check nonce matches
  if (response.nonce !== challenge.nonce) {
    return { valid: false, reason: "nonce_mismatch" };
  }
  // Check timestamp matches
  if (response.challengeTimestampMs !== challenge.challengeTimestampMs) {
    return { valid: false, reason: "timestamp_mismatch" };
  }
  // Check agent matches target
  if (response.agentId !== challenge.targetAgentId) {
    return { valid: false, reason: "agent_mismatch" };
  }
  // Check timeout
  const elapsed = Date.now() - challenge.challengeTimestampMs;
  if (elapsed > timeoutMs) {
    return { valid: false, reason: "liveness_timeout" };
  }
  // Verify signature
  const message = `${response.agentId}:${response.anchorFingerprint}:${response.nonce}:${response.challengeTimestampMs}`;
  const expected = createHmac("sha256", signingKey).update(message, "utf-8").digest("hex");
  if (expected.length !== response.responseSignature.length) {
    return { valid: false, reason: "signature_invalid" };
  }
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ response.responseSignature.charCodeAt(i);
  }
  if (diff !== 0) {
    return { valid: false, reason: "signature_invalid" };
  }
  return { valid: true };
}
