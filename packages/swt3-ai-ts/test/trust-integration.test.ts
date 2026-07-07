/**
 * SWT3 Trust Mesh -- Comprehensive Integration Test.
 *
 * Validates that the full Trust Mesh (Tasks 1-7) is:
 *   1. FRICTIONLESS by default (zero-config path works)
 *   2. SIMPLE to use (minimal API surface for common cases)
 *   3. SECURE when hardened (all protections compose correctly)
 *   4. FUNCTIONAL (no gaps in the security model)
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

// ═══════════════════════════════════════════════════════════════════════
// SCENARIO 1: FRICTIONLESS DEFAULT PATH
// Zero configuration. Two agents from trusted tenants just work.
// ═══════════════════════════════════════════════════════════════════════

describe("Scenario 1: Frictionless Default Path", () => {
  it("two agents handshake with minimal setup (3 lines)", () => {
    // THIS IS THE MINIMUM VIABLE TRUST MESH USAGE:
    const agentA = mkWitness({ agentId: "agent-a", tenantId: "org_alpha" });
    const agentB = mkWitness({ agentId: "agent-b", tenantId: "org_beta" });

    // Each trusts the other's org (one line each)
    agentA.trustRegistry.trustTenant("org_beta");
    agentB.trustRegistry.trustTenant("org_alpha");

    // Handshake: present and verify (one line each direction)
    const credA = agentA.presentCredential();
    const resultB = agentB.verifyTrust(credA);
    expect(resultB.granted).toBe(true);
    expect(resultB.trustLevel).toBe(TRUST_BASIC);

    const credB = agentB.presentCredential();
    const resultA = agentA.verifyTrust(credB);
    expect(resultA.granted).toBe(true);
  });

  it("same-tenant agents auto-trust without any configuration", () => {
    const agent1 = mkWitness({ agentId: "worker-1", tenantId: "acme_corp" });
    const agent2 = mkWitness({ agentId: "worker-2", tenantId: "acme_corp" });

    // NO SETUP NEEDED -- same tenant auto-trusts
    const cred1 = agent1.presentCredential();
    const result = agent2.verifyTrust(cred1);
    expect(result.granted).toBe(true);
  });

  it("default registry has zero hardening features active", () => {
    const reg = new TrustRegistry();
    // All hardening is opt-in, defaults are permissive
    expect(reg._freshnessWindowMs).toBe(86400_000); // 24h
    expect(reg._requireSignature).toBe(false);
    expect(reg._minTrustLevel).toBe(TRUST_BASIC);
    expect(reg._rateLimiter).toBeNull();
    expect(reg._perLevelFreshnessMs).toBeNull();
    expect(reg._verifyBooleanClaims).toBe(false);
  });

  it("unsigned credentials work at BASIC level (no keys needed)", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    const cred: TrustCredential = {
      agentId: "simple-agent",
      tenantId: "partner",
      anchorFingerprint: "abc123def456",
      anchorTimestampMs: Date.now(),
    };
    const r = verifyCredential(cred, reg, "my_tenant");
    expect(r.granted).toBe(true);
    expect(r.trustLevel).toBe(TRUST_BASIC);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// SCENARIO 2: PROGRESSIVE SECURITY HARDENING
// Each feature is opt-in. They compose without breaking each other.
// ═══════════════════════════════════════════════════════════════════════

describe("Scenario 2: Progressive Security Hardening", () => {
  it("adding signing upgrades trust level without breaking flow", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.registerSigningKey("agent-x", "shared_secret_key");

    // Agent presents signed credential
    const cred: TrustCredential = {
      agentId: "agent-x",
      tenantId: "partner",
      anchorFingerprint: "abc123def456",
      anchorTimestampMs: Date.now(),
      isSigned: true,
    };
    cred.credentialSignature = signCredential(cred, "shared_secret_key");

    const r = verifyCredential(cred, reg, "my_tenant");
    expect(r.granted).toBe(true);
    expect(r.trustLevel).toBe(TRUST_VERIFIED); // Upgraded from BASIC
  });

  it("requiring signature rejects unsigned agents gracefully", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.setRequireSignature(true); // Opt-in hardening

    const cred: TrustCredential = {
      agentId: "unsigned-agent",
      tenantId: "partner",
      anchorFingerprint: "abc123def456",
      anchorTimestampMs: Date.now(),
      isSigned: false,
    };
    const r = verifyCredential(cred, reg, "my_tenant");
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_SIGNATURE_MISSING);
  });

  it("intra-tenant zero-trust composes with signing", () => {
    const reg = new TrustRegistry();
    reg.setRequireIntraTenantSigning(true);
    reg.setRequireSignature(true);
    reg.trustTenant("acme_corp"); // Must explicitly trust own tenant now
    reg.registerSigningKey("internal-agent", "internal_key");

    // Unsigned same-tenant agent: rejected
    const unsignedCred: TrustCredential = {
      agentId: "internal-agent",
      tenantId: "acme_corp",
      anchorFingerprint: "abc123def456",
      anchorTimestampMs: Date.now(),
      isSigned: false,
    };
    const r1 = verifyCredential(unsignedCred, reg, "acme_corp");
    expect(r1.granted).toBe(false);

    // Signed same-tenant agent: passes
    const signedCred: TrustCredential = {
      agentId: "internal-agent",
      tenantId: "acme_corp",
      anchorFingerprint: "abc123def456",
      anchorTimestampMs: Date.now(),
      isSigned: true,
    };
    signedCred.credentialSignature = signCredential(signedCred, "internal_key");
    const r2 = verifyCredential(signedCred, reg, "acme_corp");
    expect(r2.granted).toBe(true);
    expect(r2.trustLevel).toBe(TRUST_VERIFIED);
  });

  it("rate limiting protects without affecting legitimate agents", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.setRateLimit(3, 60); // 3 failures per 60 seconds

    // Legitimate agent passes
    const goodCred: TrustCredential = {
      agentId: "good-agent",
      tenantId: "partner",
      anchorFingerprint: "abc123def456",
      anchorTimestampMs: Date.now(),
    };
    expect(verifyCredential(goodCred, reg, "my_t").granted).toBe(true);

    // Attacker hits rate limit
    const badCred: TrustCredential = {
      agentId: "attacker",
      tenantId: "unknown",
      anchorFingerprint: "abc123def456",
      anchorTimestampMs: Date.now(),
    };
    verifyCredential(badCred, reg, "my_t"); // fail 1
    verifyCredential(badCred, reg, "my_t"); // fail 2
    verifyCredential(badCred, reg, "my_t"); // fail 3

    // Attacker now rate limited even with valid credential
    const attackerValid: TrustCredential = {
      agentId: "attacker",
      tenantId: "partner",
      anchorFingerprint: "abc123def456",
      anchorTimestampMs: Date.now(),
    };
    const r = verifyCredential(attackerValid, reg, "my_t");
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_RATE_LIMITED);

    // Good agent still works (rate limit is per-agent)
    expect(verifyCredential(goodCred, reg, "my_t").granted).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// SCENARIO 3: FULL SOVEREIGN-LEVEL VERIFICATION
// Maximum security: signing + hardware + guardrails + fresh anchor +
// per-level freshness + boolean verification + key attestation + liveness
// ═══════════════════════════════════════════════════════════════════════

describe("Scenario 3: Full Sovereign-Level Verification", () => {
  it("achieves SOVEREIGN level with all requirements met", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("defense_contractor");
    reg.registerSigningKey("classified-agent", "top_secret_key");
    reg.setRequireSignature(true);
    reg.setMinTrustLevel(TRUST_SOVEREIGN);
    reg.setVerifyBooleanClaims(true);
    reg.setPerLevelFreshness({ 1: 86400, 2: 3600, 3: 900, 4: 300 });

    const cred: TrustCredential = {
      agentId: "classified-agent",
      tenantId: "defense_contractor",
      anchorFingerprint: "sec123class456",
      anchorTimestampMs: Date.now() - 60_000, // 1 min ago (within 300s sovereign window)
      isSigned: true,
      hasHardwareAttestation: true,
      hasGuardrails: true,
      clearingLevel: 2,
      procedures: ["AI-HW.1", "AI-GRD.1", "AI-ID.1"],
    };
    cred.credentialSignature = signCredential(cred, "top_secret_key");

    const r = verifyCredential(cred, reg, "my_tenant");
    expect(r.granted).toBe(true);
    expect(r.trustLevel).toBe(TRUST_SOVEREIGN);
  });

  it("sovereign fails when anchor too old for per-level freshness", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("defense_contractor");
    reg.registerSigningKey("classified-agent", "top_secret_key");
    reg.setPerLevelFreshness({ 1: 86400, 2: 3600, 3: 900, 4: 300 });

    const cred: TrustCredential = {
      agentId: "classified-agent",
      tenantId: "defense_contractor",
      anchorFingerprint: "sec123class456",
      anchorTimestampMs: Date.now() - 600_000, // 10 min ago (over 300s sovereign window)
      isSigned: true,
      hasHardwareAttestation: true,
      hasGuardrails: true,
      clearingLevel: 2,
      procedures: ["AI-HW.1", "AI-GRD.1"],
    };
    cred.credentialSignature = signCredential(cred, "top_secret_key");

    const r = verifyCredential(cred, reg, "my_tenant");
    expect(r.granted).toBe(false);
    expect(r.denialReason).toBe(DENIAL_ANCHOR_EXPIRED);
  });

  it("sovereign degrades to BASIC when boolean claims unverified", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");
    reg.registerSigningKey("agent-1", "key");
    reg.setVerifyBooleanClaims(true);
    reg.setMinTrustLevel(TRUST_SOVEREIGN);

    // Claims hw + guardrails but no matching procedures
    const cred: TrustCredential = {
      agentId: "agent-1",
      tenantId: "partner",
      anchorFingerprint: "abc123",
      anchorTimestampMs: Date.now(),
      isSigned: true,
      hasHardwareAttestation: true,
      hasGuardrails: true,
      clearingLevel: 2,
      procedures: [], // EMPTY -- claims are unverifiable
    };
    cred.credentialSignature = signCredential(cred, "key");

    const r = verifyCredential(cred, reg, "my_tenant");
    expect(r.granted).toBe(false);
    // Degraded to BASIC, which is below SOVEREIGN min
    expect(r.denialReason).toBe(DENIAL_INSUFFICIENT_TRUST_LEVEL);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// SCENARIO 4: KEY ATTESTATION + LIVENESS COMBINED FLOW
// The full secure agent identity verification pipeline.
// ═══════════════════════════════════════════════════════════════════════

describe("Scenario 4: Key Attestation + Liveness Combined Flow", () => {
  it("complete sovereign handshake with key attestation and liveness proof", () => {
    const AGENT_A_KEY = "agent_a_signing_key_2026";
    const AGENT_B_KEY = "agent_b_signing_key_2026";

    // Step 1: Both agents generate key attestations (binding keys to anchors)
    const keyAttA = generateKeyAttestation(
      "agent-a", "pubkey_a_hex", "fp_a_anchor", Date.now(), AGENT_A_KEY,
    );
    const keyAttB = generateKeyAttestation(
      "agent-b", "pubkey_b_hex", "fp_b_anchor", Date.now(), AGENT_B_KEY,
    );

    // Step 2: Each verifies the other's key attestation
    expect(verifyKeyAttestation(keyAttA, AGENT_A_KEY)).toBe(true);
    expect(verifyKeyAttestation(keyAttB, AGENT_B_KEY)).toBe(true);
    expect(isKeyAttestationFresh(keyAttA, 300_000)).toBe(true);
    expect(isKeyAttestationFresh(keyAttB, 300_000)).toBe(true);

    // Step 3: Liveness proof (A proves to B it's alive)
    const challengeForA = generateChallenge("agent-a");
    const responseA = respondToChallenge(challengeForA, "agent-a", "fp_a_anchor", AGENT_A_KEY);
    const livenessA = verifyLivenessResponse(responseA, challengeForA, AGENT_A_KEY, 60_000);
    expect(livenessA.valid).toBe(true);

    // Step 4: Liveness proof (B proves to A it's alive)
    const challengeForB = generateChallenge("agent-b");
    const responseB = respondToChallenge(challengeForB, "agent-b", "fp_b_anchor", AGENT_B_KEY);
    const livenessB = verifyLivenessResponse(responseB, challengeForB, AGENT_B_KEY, 60_000);
    expect(livenessB.valid).toBe(true);

    // Step 5: Now proceed with credential verification (trust established)
    const regA = new TrustRegistry();
    regA.trustTenant("org_b");
    regA.registerSigningKey("agent-b", AGENT_B_KEY);

    const credB: TrustCredential = {
      agentId: "agent-b",
      tenantId: "org_b",
      anchorFingerprint: "fp_b_anchor",
      anchorTimestampMs: Date.now(),
      isSigned: true,
      hasHardwareAttestation: true,
      hasGuardrails: true,
      clearingLevel: 2,
      procedures: ["AI-HW.1", "AI-GRD.1"],
    };
    credB.credentialSignature = signCredential(credB, AGENT_B_KEY);

    const finalResult = verifyCredential(credB, regA, "org_a");
    expect(finalResult.granted).toBe(true);
    expect(finalResult.trustLevel).toBe(TRUST_SOVEREIGN);
  });

  it("stolen credential detected by liveness failure", () => {
    const REAL_KEY = "real_agent_key";
    const ATTACKER_KEY = "attacker_has_wrong_key";

    // Attacker replays a valid credential but can't prove liveness
    const challenge = generateChallenge("real-agent");

    // Attacker tries to respond but doesn't have the real signing key
    const fakeResponse = respondToChallenge(challenge, "real-agent", "stolen_fp", ATTACKER_KEY);
    const result = verifyLivenessResponse(fakeResponse, challenge, REAL_KEY, 60_000);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  it("key attestation expires when anchor becomes stale", () => {
    const att = generateKeyAttestation(
      "agent-x", "pubkey_x", "old_anchor_fp",
      Date.now() - 400_000, // 400 seconds ago
      "key_x",
    );

    // Attestation itself is valid (signature checks out)
    expect(verifyKeyAttestation(att, "key_x")).toBe(true);

    // But the bound anchor is stale for sovereign-level freshness (300s)
    expect(isKeyAttestationFresh(att, 300_000)).toBe(false);

    // Still fresh for basic-level (24h)
    expect(isKeyAttestationFresh(att, 86400_000)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// SCENARIO 5: DENY LIST PROPAGATION + REVOCATION CASCADE
// Sentinel integration point: external revocation propagates correctly.
// ═══════════════════════════════════════════════════════════════════════

describe("Scenario 5: Revocation Cascade", () => {
  it("sentinel revocation immediately blocks previously trusted agent", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("partner");

    // Agent is trusted and passes
    const cred: TrustCredential = {
      agentId: "compromised-agent",
      tenantId: "partner",
      anchorFingerprint: "abc123",
      anchorTimestampMs: Date.now(),
    };
    expect(verifyCredential(cred, reg, "my_t").granted).toBe(true);

    // Sentinel detects compromise, pushes revocation
    reg.applyRevocationEvent({
      agentId: "compromised-agent",
      reason: "model_recall",
    });

    // Same credential now fails
    expect(verifyCredential(cred, reg, "my_t").granted).toBe(false);
    expect(verifyCredential(cred, reg, "my_t").denialReason).toBe(DENIAL_DENY_LISTED);
  });

  it("tenant-level revocation blocks all agents from that tenant", () => {
    const reg = new TrustRegistry();
    reg.trustTenant("compromised_org");

    const cred1: TrustCredential = {
      agentId: "agent-1", tenantId: "compromised_org",
      anchorFingerprint: "x", anchorTimestampMs: Date.now(),
    };
    const cred2: TrustCredential = {
      agentId: "agent-2", tenantId: "compromised_org",
      anchorFingerprint: "y", anchorTimestampMs: Date.now(),
    };

    expect(verifyCredential(cred1, reg, "my_t").granted).toBe(true);
    expect(verifyCredential(cred2, reg, "my_t").granted).toBe(true);

    // Revoke entire tenant
    reg.applyRevocationEvent({ tenantId: "compromised_org", reason: "data_contamination" });

    expect(verifyCredential(cred1, reg, "my_t").granted).toBe(false);
    expect(verifyCredential(cred2, reg, "my_t").granted).toBe(false);
  });

  it("deny event listeners receive all revocation events", () => {
    const reg = new TrustRegistry();
    const events: DenyEvent[] = [];
    reg.onDenyEvent((e) => events.push(e));

    // Simulate sentinel pushing multiple revocations
    reg.applyRevocationEvent({ agentId: "bad-1", reason: "policy_violation" });
    reg.applyRevocationEvent({ agentId: "bad-2", tenantId: "bad-org", reason: "regulatory_order" });
    reg.denyAgent("manual-deny");

    expect(events).toHaveLength(4); // 1 + 2 + 1
    expect(events.map(e => e.target)).toContain("bad-1");
    expect(events.map(e => e.target)).toContain("bad-2");
    expect(events.map(e => e.target)).toContain("bad-org");
    expect(events.map(e => e.target)).toContain("manual-deny");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// SCENARIO 6: API ERGONOMICS CHECK
// Verify the API is simple, discoverable, and chainable.
// ═══════════════════════════════════════════════════════════════════════

describe("Scenario 6: API Ergonomics", () => {
  it("all hardening features can be set in one configuration block", () => {
    const reg = new TrustRegistry();

    // Enterprise security team configures once:
    reg.setRequireIntraTenantSigning(true);
    reg.setRequireSignature(true);
    reg.setMinTrustLevel(TRUST_ATTESTED);
    reg.setVerifyBooleanClaims(true);
    reg.setRateLimit(5, 300);
    reg.setPerLevelFreshness({
      [TRUST_BASIC]: 86400,
      [TRUST_VERIFIED]: 3600,
      [TRUST_ATTESTED]: 900,
      [TRUST_SOVEREIGN]: 300,
    });
    reg.setRequiredProcedures(["AI-ID.1", "AI-GRD.1"]);

    // All configured -- verify it works
    reg.trustTenant("my_org");
    reg.registerSigningKey("internal", "key123");

    const cred: TrustCredential = {
      agentId: "internal",
      tenantId: "my_org",
      anchorFingerprint: "fp123",
      anchorTimestampMs: Date.now() - 120_000, // 2 min
      isSigned: true,
      hasHardwareAttestation: true,
      hasGuardrails: true,
      clearingLevel: 1,
      procedures: ["AI-ID.1", "AI-GRD.1", "AI-HW.1"],
    };
    cred.credentialSignature = signCredential(cred, "key123");

    const r = verifyCredential(cred, reg, "my_org");
    expect(r.granted).toBe(true);
    expect(r.trustLevel).toBe(TRUST_ATTESTED);
  });

  it("key attestation is a one-liner", () => {
    // Generate: one function call
    const att = generateKeyAttestation("my-agent", "my-pubkey", "my-fp", Date.now(), "my-key");
    // Verify: one function call
    expect(verifyKeyAttestation(att, "my-key")).toBe(true);
  });

  it("liveness proof is three function calls", () => {
    // Verifier: generate challenge
    const ch = generateChallenge("target");
    // Prover: respond
    const resp = respondToChallenge(ch, "target", "fp", "key");
    // Verifier: verify
    const result = verifyLivenessResponse(resp, ch, "key", 60_000);
    expect(result.valid).toBe(true);
  });

  it("Witness.presentCredential + verifyTrust is the complete simple path", () => {
    const alice = mkWitness({ agentId: "alice", tenantId: "org_a" });
    const bob = mkWitness({ agentId: "bob", tenantId: "org_b" });
    alice.trustRegistry.trustTenant("org_b");
    bob.trustRegistry.trustTenant("org_a");

    // The ENTIRE handshake is 4 lines:
    const r1 = bob.verifyTrust(alice.presentCredential());
    const r2 = alice.verifyTrust(bob.presentCredential());
    expect(r1.granted).toBe(true);
    expect(r2.granted).toBe(true);
  });
});
