/**
 * SWT3 AI Witness SDK -- AI-TRUST.1 / AI-TRUST.2 Trust Mesh Tests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Witness } from "../src/witness.js";
import {
  TrustRegistry, verifyCredential, evaluateTrustLevel, signCredential,
  TRUST_DENIED, TRUST_BASIC, TRUST_VERIFIED, TRUST_ATTESTED, TRUST_SOVEREIGN,
  DENIAL_DENY_LISTED, DENIAL_TENANT_NOT_TRUSTED, DENIAL_ANCHOR_EXPIRED,
  DENIAL_SIGNATURE_MISSING, DENIAL_INSUFFICIENT_PROCEDURES,
} from "../src/trust.js";
import type { TrustCredential } from "../src/trust.js";

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
