/**
 * SWT3 AI Witness SDK -- AI-TRUST.1 / AI-TRUST.2 Trust Mesh Tests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Witness } from "../src/witness.js";
import {
  TrustRegistry, verifyCredential, evaluateTrustLevel, signCredential,
  generateKeyAttestation, verifyKeyAttestation, isKeyAttestationFresh,
  generateChallenge, respondToChallenge, verifyLivenessResponse,
  TRUST_DENIED, TRUST_BASIC, TRUST_VERIFIED, TRUST_ATTESTED, TRUST_SOVEREIGN,
  DENIAL_DENY_LISTED, DENIAL_TENANT_NOT_TRUSTED, DENIAL_ANCHOR_EXPIRED,
  DENIAL_SIGNATURE_MISSING, DENIAL_INSUFFICIENT_PROCEDURES,
  DENIAL_RATE_LIMITED, DENIAL_INSUFFICIENT_TRUST_LEVEL,
} from "../src/trust.js";
import type { TrustCredential, DenyEvent } from "../src/trust.js";

beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

function mkWitness(overrides: Record<string, unknown> = {}): Witness {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    flushInterval: 999999,
    ...overrides,
  } as any);
}

function mkCredential(overrides: Partial<TrustCredential> = {}): TrustCredential {
  return {
    agentId: "remote-agent-001",
    tenantId: "partner_tenant",
    anchorFingerprint: "abc123def456",
    anchorTimestampMs: Date.now(),
    ...overrides,
  };
}

// ── TrustRegistry ────────────────────────────────────────────────────

describe("TrustRegistry", () => {
  it("same tenant auto-trusted", () => {
    const reg = new TrustRegistry();
    expect(reg.isTenantTrusted("my_t", "my_t")).toBe(true);
  });

  it("unknown tenant not trusted", () => {
    const reg = new TrustRegistry();
    expect(reg.isTenantTrusted("stranger", "my_t")).toBe(false);
  });

  it("trust then deny tenant", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    expect(reg.isTenantTrusted("partner", "my_t")).toBe(true);
    reg.denyTenant("partner");
    expect(reg.isTenantTrusted("partner", "my_t")).toBe(false);
  });

  it("deny agent overrides tenant trust", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.denyAgent("bad-agent");
    expect(reg.isAgentTrusted("partner", "bad-agent", "my_t")).toBe(false);
    expect(reg.isAgentTrusted("partner", "good-agent", "my_t")).toBe(true);
  });

  it("trust specific agent", () => {
    const reg = new TrustRegistry();
    reg.trustAgent("other", "specific");
    expect(reg.isAgentTrusted("other", "specific", "my_t")).toBe(true);
    expect(reg.isAgentTrusted("other", "other-agent", "my_t")).toBe(false);
  });
});

// ── evaluateTrustLevel ───────────────────────────────────────────────

describe("evaluateTrustLevel", () => {
  it("unsigned -> basic", () => {
    expect(evaluateTrustLevel(mkCredential({ isSigned: false }))).toBe(TRUST_BASIC);
  });

  it("signed no hw -> verified", () => {
    expect(evaluateTrustLevel(mkCredential({ isSigned: true }))).toBe(TRUST_VERIFIED);
  });

  it("signed + hw + guardrails -> attested", () => {
    expect(evaluateTrustLevel(mkCredential({
      isSigned: true, hasHardwareAttestation: true, hasGuardrails: true, clearingLevel: 1,
    }))).toBe(TRUST_ATTESTED);
  });

  it("signed + hw + guardrails + cl2 -> sovereign", () => {
    expect(evaluateTrustLevel(mkCredential({
      isSigned: true, hasHardwareAttestation: true, hasGuardrails: true, clearingLevel: 2,
    }))).toBe(TRUST_SOVEREIGN);
  });
});

// ── verifyCredential ─────────────────────────────────────────────────

describe("verifyCredential", () => {
  it("deny-listed agent", () => {
    const reg = new TrustRegistry();
    reg.denyAgent("bad");
    const r = verifyCredential(mkCredential({ agentId: "bad" }), reg, "my_t");
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_DENY_LISTED);
  });

  it("untrusted tenant", () => {
    const reg = new TrustRegistry();
    const r = verifyCredential(mkCredential({ tenantId: "stranger" }), reg, "my_t");
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_TENANT_NOT_TRUSTED);
  });

  it("same tenant passes", () => {
    const reg = new TrustRegistry();
    const r = verifyCredential(mkCredential({ tenantId: "my_t" }), reg, "my_t");
    expect(r.granted).toBe(true);
  });

  it("expired anchor", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.setFreshnessWindow(1);
    const r = verifyCredential(
      mkCredential({ tenantId: "partner", anchorTimestampMs: Date.now() - 5000 }),
      reg, "my_t",
    );
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_ANCHOR_EXPIRED);
  });

  it("signature required but missing", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.setRequireSignature(true);
    const r = verifyCredential(
      mkCredential({ tenantId: "partner", isSigned: false }),
      reg, "my_t",
    );
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_SIGNATURE_MISSING);
  });

  it("insufficient procedures", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.setRequiredProcedures(["AI-ID.1", "AI-HW.1"]);
    const r = verifyCredential(
      mkCredential({ tenantId: "partner", procedures: ["AI-ID.1"] }),
      reg, "my_t",
    );
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_INSUFFICIENT_PROCEDURES);
  });

  it("all checks pass (unsigned credential gets TRUST_BASIC)", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    const r = verifyCredential(
      mkCredential({ tenantId: "partner", isSigned: true }),
      reg, "my_t",
    );
    expect(r.granted).toBe(true);
    // isSigned=true but no credentialSignature -> signatureVerified=false -> capped at BASIC
    expect(r.trustLevel).toBe(TRUST_BASIC);
  });

  it("signed + verified credential gets TRUST_VERIFIED", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.registerSigningKey("remote-agent-001", "test-secret");
    const cred = mkCredential({ tenantId: "partner", isSigned: true });
    cred.credentialSignature = signCredential(cred, "test-secret");
    const r = verifyCredential(cred, reg, "my_t");
    expect(r.granted).toBe(true);
    expect(r.trustLevel).toBe(TRUST_VERIFIED);
  });
});

// ── Witness.verifyTrust ──────────────────────────────────────────────

describe("Witness.verifyTrust", () => {
  it("mints trust anchors", () => {
    const w = mkWitness();
    w.trustRegistry.trustTenant("partner");
    const r = w.verifyTrust(mkCredential({ tenantId: "partner" }));
    expect(r.granted).toBe(true);
    expect(w.pending).toBeGreaterThanOrEqual(2);
  });

  it("denied still mints", () => {
    const w = mkWitness();
    const r = w.verifyTrust(mkCredential({ tenantId: "stranger" }));
    expect(r.granted).toBe(false);
    expect(w.pending).toBeGreaterThanOrEqual(2);
  });

  it("counterpart info in result", () => {
    const w = mkWitness();
    const r = w.verifyTrust(mkCredential({ agentId: "remote-007", tenantId: "test_tenant" }));
    expect(r.counterpartAgentId).toBe("remote-007");
  });
});

// ── Witness.presentCredential ────────────────────────────────────────

describe("Witness.presentCredential", () => {
  it("basic credential", () => {
    const w = mkWitness({ agentId: "my-agent" });
    const c = w.presentCredential();
    expect(c.agentId).toBe("my-agent");
    expect(c.tenantId).toBe("test_tenant");
    expect(c.anchorFingerprint).toHaveLength(12);
    expect(c.isSigned).toBe(false);
  });

  it("signed credential", () => {
    const w = mkWitness({ agentId: "my-agent", signingKey: "secret123" });
    const c = w.presentCredential();
    expect(c.isSigned).toBe(true);
  });

  it("no agent_id uses anonymous", () => {
    const w = mkWitness();
    const c = w.presentCredential();
    expect(c.agentId).toBe("anonymous");
  });

  it("guardrails detected", () => {
    const w = mkWitness({ guardrailNames: ["filter"] });
    const c = w.presentCredential();
    expect(c.hasGuardrails).toBe(true);
  });
});

// ── Bilateral Handshake ──────────────────────────────────────────────

describe("bilateral handshake", () => {
  it("mutual trust succeeds", () => {
    const a = mkWitness({ agentId: "a", tenantId: "t_a" } as any);
    const b = mkWitness({ agentId: "b", tenantId: "t_b" } as any);
    a.trustRegistry.trustTenant("t_b");
    b.trustRegistry.trustTenant("t_a");

    const credA = a.presentCredential();
    const rB = b.verifyTrust(credA);
    expect(rB.granted).toBe(true);

    const credB = b.presentCredential();
    const rA = a.verifyTrust(credB);
    expect(rA.granted).toBe(true);
  });

  it("one-sided trust fails", () => {
    const a = mkWitness({ agentId: "a", tenantId: "t_a" } as any);
    const b = mkWitness({ agentId: "b", tenantId: "t_b" } as any);
    a.trustRegistry.trustTenant("t_b");
    // B does NOT trust A

    const credA = a.presentCredential();
    const rB = b.verifyTrust(credA);
    expect(rB.granted).toBe(false);
    expect(rB.denialReason).toBe(DENIAL_TENANT_NOT_TRUSTED);
  });
});

// ── Task 1: Intra-Tenant Zero-Trust ─────────────────────────────────

describe("intra-tenant zero-trust", () => {
  it("same tenant auto-trusted by default", () => {
    const reg = new TrustRegistry();
    const r = verifyCredential(mkCredential({ tenantId: "my_t" }), reg, "my_t");
    expect(r.granted).toBe(true);
  });

  it("same tenant denied when requireIntraTenantSigning=true and not explicitly trusted", () => {
    const reg = new TrustRegistry();
    reg.setRequireIntraTenantSigning(true);
    const r = verifyCredential(mkCredential({ tenantId: "my_t" }), reg, "my_t");
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_TENANT_NOT_TRUSTED);
  });

  it("same tenant passes when explicitly trusted with intra-tenant signing on", () => {
    const reg = new TrustRegistry();
    reg.setRequireIntraTenantSigning(true);
    reg.trustTenant("my_t");
    const r = verifyCredential(mkCredential({ tenantId: "my_t" }), reg, "my_t");
    expect(r.granted).toBe(true);
  });
});

// ── Task 2: Rate Limiting ───────────────────────────────────────────

describe("verification rate limiting", () => {
  it("no rate limit by default", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    const r = verifyCredential(mkCredential({ tenantId: "partner" }), reg, "my_t");
    expect(r.granted).toBe(true);
  });

  it("passes under limit", () => {
    const reg = new TrustRegistry();
    reg.setRateLimit(3, 60);
    // Two failures should still allow through
    reg.denyAgent("bad1");
    verifyCredential(mkCredential({ agentId: "target", tenantId: "stranger" }), reg, "my_t");
    verifyCredential(mkCredential({ agentId: "target", tenantId: "stranger" }), reg, "my_t");
    // Third attempt from same agent -- still under (failures recorded for "target")
    reg.trustTenant("partner");
    const r = verifyCredential(mkCredential({ agentId: "target", tenantId: "partner" }), reg, "my_t");
    // target has 2 failures, limit is 3 -- should pass
    expect(r.granted).toBe(true);
  });

  it("denied when rate limit exceeded", () => {
    const reg = new TrustRegistry();
    reg.setRateLimit(2, 60);
    // Generate failures
    verifyCredential(mkCredential({ agentId: "attacker", tenantId: "stranger" }), reg, "my_t");
    verifyCredential(mkCredential({ agentId: "attacker", tenantId: "stranger" }), reg, "my_t");
    // Now rate limited
    reg.trustTenant("partner");
    const r = verifyCredential(mkCredential({ agentId: "attacker", tenantId: "partner" }), reg, "my_t");
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_RATE_LIMITED);
  });
});

// ── Task 3: Per-Level Freshness ─────────────────────────────────────

describe("per-level freshness windows", () => {
  it("BASIC level uses generous window", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.setPerLevelFreshness({ 1: 86400, 2: 3600, 3: 900, 4: 300 });
    // 2h old anchor, BASIC level (unsigned) -- 86400s window, should pass
    const r = verifyCredential(
      mkCredential({ tenantId: "partner", anchorTimestampMs: Date.now() - 7200_000 }),
      reg, "my_t",
    );
    expect(r.granted).toBe(true);
  });

  it("VERIFIED level fails with old anchor", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.registerSigningKey("remote-agent-001", "key");
    reg.setPerLevelFreshness({ 1: 86400, 2: 3600, 3: 900, 4: 300 });
    // 2h old anchor, VERIFIED level -- 3600s window, should fail
    const cred = mkCredential({
      tenantId: "partner", isSigned: true,
      anchorTimestampMs: Date.now() - 7200_000,
    });
    cred.credentialSignature = signCredential(cred, "key");
    const r = verifyCredential(cred, reg, "my_t");
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_ANCHOR_EXPIRED);
  });

  it("SOVEREIGN level requires very fresh anchor", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.registerSigningKey("remote-agent-001", "key");
    reg.setPerLevelFreshness({ 1: 86400, 2: 3600, 3: 900, 4: 300 });
    // 10min old, SOVEREIGN level (300s window) -- should fail
    const cred = mkCredential({
      tenantId: "partner", isSigned: true,
      hasHardwareAttestation: true, hasGuardrails: true, clearingLevel: 2,
      procedures: ["AI-HW.1", "AI-GRD.1"],
      anchorTimestampMs: Date.now() - 600_000,
    });
    cred.credentialSignature = signCredential(cred, "key");
    const r = verifyCredential(cred, reg, "my_t");
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_ANCHOR_EXPIRED);
  });

  it("SOVEREIGN passes with fresh anchor", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.registerSigningKey("remote-agent-001", "key");
    reg.setPerLevelFreshness({ 1: 86400, 2: 3600, 3: 900, 4: 300 });
    // 2min old, SOVEREIGN level (300s window) -- should pass
    const cred = mkCredential({
      tenantId: "partner", isSigned: true,
      hasHardwareAttestation: true, hasGuardrails: true, clearingLevel: 2,
      procedures: ["AI-HW.1", "AI-GRD.1"],
      anchorTimestampMs: Date.now() - 120_000,
    });
    cred.credentialSignature = signCredential(cred, "key");
    const r = verifyCredential(cred, reg, "my_t");
    expect(r.granted).toBe(true);
    expect(r.trustLevel).toBe(TRUST_SOVEREIGN);
  });
});

// ── Task 4: Verifiable Boolean Claims ───────────────────────────────

describe("verifiable boolean claims", () => {
  it("disabled by default (no degradation)", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.registerSigningKey("remote-agent-001", "key");
    const cred = mkCredential({
      tenantId: "partner", isSigned: true,
      hasHardwareAttestation: true, hasGuardrails: true,
      clearingLevel: 1, procedures: [],
    });
    cred.credentialSignature = signCredential(cred, "key");
    const r = verifyCredential(cred, reg, "my_t");
    expect(r.trustLevel).toBe(TRUST_ATTESTED);
  });

  it("hasHardwareAttestation without AI-HW.1 degrades to BASIC", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.registerSigningKey("remote-agent-001", "key");
    reg.setVerifyBooleanClaims(true);
    const cred = mkCredential({
      tenantId: "partner", isSigned: true,
      hasHardwareAttestation: true, hasGuardrails: true,
      clearingLevel: 1, procedures: ["AI-GRD.1"],
    });
    cred.credentialSignature = signCredential(cred, "key");
    const r = verifyCredential(cred, reg, "my_t");
    expect(r.trustLevel).toBe(TRUST_BASIC);
  });

  it("hasGuardrails without AI-GRD.* degrades to BASIC", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.registerSigningKey("remote-agent-001", "key");
    reg.setVerifyBooleanClaims(true);
    const cred = mkCredential({
      tenantId: "partner", isSigned: true,
      hasHardwareAttestation: true, hasGuardrails: true,
      clearingLevel: 1, procedures: ["AI-HW.1"],
    });
    cred.credentialSignature = signCredential(cred, "key");
    const r = verifyCredential(cred, reg, "my_t");
    expect(r.trustLevel).toBe(TRUST_BASIC);
  });

  it("both claims backed by procedures keeps full level", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.registerSigningKey("remote-agent-001", "key");
    reg.setVerifyBooleanClaims(true);
    const cred = mkCredential({
      tenantId: "partner", isSigned: true,
      hasHardwareAttestation: true, hasGuardrails: true,
      clearingLevel: 1, procedures: ["AI-HW.1", "AI-GRD.1"],
    });
    cred.credentialSignature = signCredential(cred, "key");
    const r = verifyCredential(cred, reg, "my_t");
    expect(r.trustLevel).toBe(TRUST_ATTESTED);
  });
});

// ── Task 5: Deny List Propagation ───────────────────────────────────

describe("deny list propagation", () => {
  it("onDenyEvent fires on denyAgent", () => {
    const reg = new TrustRegistry();
    const events: DenyEvent[] = [];
    reg.onDenyEvent((e) => events.push(e));
    reg.denyAgent("bad-agent");
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("agent");
    expect(events[0].target).toBe("bad-agent");
  });

  it("onDenyEvent fires on denyTenant", () => {
    const reg = new TrustRegistry();
    const events: DenyEvent[] = [];
    reg.onDenyEvent((e) => events.push(e));
    reg.denyTenant("bad-tenant");
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("tenant");
    expect(events[0].target).toBe("bad-tenant");
  });

  it("applyRevocationEvent denies agent and tenant", () => {
    const reg = new TrustRegistry();
    const events: DenyEvent[] = [];
    reg.onDenyEvent((e) => events.push(e));
    reg.applyRevocationEvent({ agentId: "revoked-agent", tenantId: "revoked-tenant", reason: "model_recall" });
    expect(reg.isAgentDenied("revoked-agent")).toBe(true);
    expect(reg.isTenantDenied("revoked-tenant")).toBe(true);
    expect(events).toHaveLength(2);
    expect(events[0].reason).toBe("model_recall");
  });
});

// ── Task 6: Key Attestation ─────────────────────────────────────────

describe("key attestation", () => {
  it("generates and verifies attestation", () => {
    const att = generateKeyAttestation("agent-1", "pubkey123", "abc123def456", Date.now(), "secret");
    expect(att.agentId).toBe("agent-1");
    expect(att.publicKey).toBe("pubkey123");
    expect(att.attestationProof).toHaveLength(64);
    expect(verifyKeyAttestation(att, "secret")).toBe(true);
  });

  it("fails with wrong key", () => {
    const att = generateKeyAttestation("agent-1", "pubkey123", "abc123def456", Date.now(), "secret");
    expect(verifyKeyAttestation(att, "wrong-secret")).toBe(false);
  });

  it("fails with tampered data", () => {
    const att = generateKeyAttestation("agent-1", "pubkey123", "abc123def456", Date.now(), "secret");
    att.publicKey = "tampered";
    expect(verifyKeyAttestation(att, "secret")).toBe(false);
  });

  it("freshness check passes for recent attestation", () => {
    const att = generateKeyAttestation("agent-1", "pubkey123", "abc123def456", Date.now(), "secret");
    expect(isKeyAttestationFresh(att, 86400_000)).toBe(true);
  });

  it("freshness check fails for old attestation", () => {
    const att = generateKeyAttestation("agent-1", "pubkey123", "abc123def456", Date.now() - 100_000, "secret");
    expect(isKeyAttestationFresh(att, 50_000)).toBe(false);
  });

  it("supports key purpose", () => {
    const att = generateKeyAttestation("agent-1", "pubkey123", "abc123def456", Date.now(), "secret", "delegation");
    expect(att.keyPurpose).toBe("delegation");
    expect(verifyKeyAttestation(att, "secret")).toBe(true);
    // Wrong purpose won't verify against different purpose attestation
    att.keyPurpose = "signing";
    expect(verifyKeyAttestation(att, "secret")).toBe(false);
  });
});

// ── Task 7: Challenge-Response Liveness ─────────────────────────────

describe("challenge-response liveness", () => {
  it("full handshake succeeds", () => {
    const challenge = generateChallenge("agent-a");
    expect(challenge.nonce).toHaveLength(64);
    const response = respondToChallenge(challenge, "agent-a", "fingerprint123", "secret");
    const result = verifyLivenessResponse(response, challenge, "secret", 60_000);
    expect(result.valid).toBe(true);
  });

  it("fails with wrong signing key", () => {
    const challenge = generateChallenge("agent-a");
    const response = respondToChallenge(challenge, "agent-a", "fingerprint123", "secret");
    const result = verifyLivenessResponse(response, challenge, "wrong-key", 60_000);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  it("fails with nonce mismatch", () => {
    const challenge = generateChallenge("agent-a");
    const response = respondToChallenge(challenge, "agent-a", "fingerprint123", "secret");
    response.nonce = "tampered_nonce";
    const result = verifyLivenessResponse(response, challenge, "secret", 60_000);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("nonce_mismatch");
  });

  it("fails with agent mismatch", () => {
    const challenge = generateChallenge("agent-a");
    const response = respondToChallenge(challenge, "agent-b", "fingerprint123", "secret");
    const result = verifyLivenessResponse(response, challenge, "secret", 60_000);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("agent_mismatch");
  });

  it("fails with timeout", () => {
    const challenge = generateChallenge("agent-a");
    // Backdate challenge to simulate timeout
    challenge.challengeTimestampMs = Date.now() - 10_000;
    const response = respondToChallenge(challenge, "agent-a", "fingerprint123", "secret");
    const result = verifyLivenessResponse(response, challenge, "secret", 5000);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("liveness_timeout");
  });

  it("mutual challenge succeeds", () => {
    // A challenges B
    const challengeAtoB = generateChallenge("agent-b");
    const responseB = respondToChallenge(challengeAtoB, "agent-b", "fp_b", "key_b");
    const resultB = verifyLivenessResponse(responseB, challengeAtoB, "key_b", 60_000);
    expect(resultB.valid).toBe(true);

    // B challenges A
    const challengeBtoA = generateChallenge("agent-a");
    const responseA = respondToChallenge(challengeBtoA, "agent-a", "fp_a", "key_a");
    const resultA = verifyLivenessResponse(responseA, challengeBtoA, "key_a", 60_000);
    expect(resultA.valid).toBe(true);
  });
});
