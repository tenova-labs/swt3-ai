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

import { createHmac } from "node:crypto";

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

  trustTenant(tenantId: string): void {
    this.trustedTenants.add(tenantId);
    this.deniedTenants.delete(tenantId);
  }

  trustAgent(tenantId: string, agentId: string): void {
    this.trustedAgents.add(`${tenantId}:${agentId}`);
  }

  denyAgent(agentId: string): void {
    this.deniedAgents.add(agentId);
  }

  denyTenant(tenantId: string): void {
    this.deniedTenants.add(tenantId);
    this.trustedTenants.delete(tenantId);
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

  isAgentDenied(agentId: string): boolean {
    return this.deniedAgents.has(agentId);
  }

  isTenantDenied(tenantId: string): boolean {
    return this.deniedTenants.has(tenantId);
  }

  isTenantTrusted(tenantId: string, ownTenantId: string): boolean {
    if (tenantId === ownTenantId) return true;
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
  getSigningKey(agentId: string): string | undefined { return this.signingKeys.get(agentId); }
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

  const denied = (reason: string): TrustResult => ({
    granted: false, trustLevel: TRUST_DENIED, denialReason: reason,
    checksPerformed: checks, checksPassed: passed, ...base,
  });

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

  // Check 3: freshness
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

  if (level < registry._minTrustLevel) {
    return denied(DENIAL_INSUFFICIENT_TRUST_LEVEL);
  }

  return {
    granted: true, trustLevel: level,
    checksPerformed: checks, checksPassed: passed, ...base,
  };
}
