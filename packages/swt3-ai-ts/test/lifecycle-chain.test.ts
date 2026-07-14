import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { Witness, LifecycleChain, LIFECYCLE_CHAIN_STAGES, OVERRIDE_TRIGGER_CODES, AUTHORIZATION_LEVEL_CODES, FALLBACK_STATE_CODES, CONSEQUENCE_CATEGORY_CODES, DRIFT_RESPONSE_CODES } from "../src/index.js";
import { generateLifecycleChainId } from "../src/fingerprint.js";

describe("LIFECYCLE_CHAIN_STAGES", () => {
  it("has 6 canonical stages", () => {
    expect(LIFECYCLE_CHAIN_STAGES).toEqual({
      initiated: 0,
      checkpoint: 1,
      escalated: 2,
      resolved: 3,
      abandoned: 4,
      superseded: 5,
    });
  });
});

describe("generateLifecycleChainId", () => {
  it("produces LC- prefix + 16 hex chars", () => {
    const cid = generateLifecycleChainId("T1", "AI-EMRG.1", "abc123def456", 1000);
    expect(cid).toMatch(/^LC-[0-9a-f]{16}$/);
  });

  it("is deterministic", () => {
    const a = generateLifecycleChainId("T1", "AI-EMRG.1", "abc123def456", 1000);
    const b = generateLifecycleChainId("T1", "AI-EMRG.1", "abc123def456", 1000);
    expect(a).toBe(b);
  });

  it("differs with different inputs", () => {
    const a = generateLifecycleChainId("T1", "AI-EMRG.1", "abc123def456", 1000);
    const b = generateLifecycleChainId("T2", "AI-EMRG.1", "abc123def456", 1000);
    expect(a).not.toBe(b);
  });

  it("matches test vectors (cross-language parity)", () => {
    const vectorsPath = join(__dirname, "..", "..", "swt3-ai", "test-vectors.json");
    const data = JSON.parse(readFileSync(vectorsPath, "utf-8"));
    for (const v of data.lifecycle_chain_vectors ?? []) {
      if (!v.expected_chain_id) continue;
      const cid = generateLifecycleChainId(
        v.tenant_id, v.procedure_id, v.initiator_fingerprint, v.timestamp_ms,
      );
      expect(cid).toBe(v.expected_chain_id);
    }
  });
});

describe("Witness.beginLifecycle", () => {
  const makeWitness = () => new Witness({
    endpoint: "https://example.com",
    apiKey: "axm_test_key",
    tenantId: "TEST_TENANT",
    clearingLevel: 1,
  });

  it("returns a LifecycleChain", () => {
    const w = makeWitness();
    const chain = w.beginLifecycle("AI-EMRG.1", 1.0, 1.0, 0.0);
    expect(chain).toBeInstanceOf(LifecycleChain);
    expect(chain.chainId).toMatch(/^LC-[0-9a-f]{16}$/);
    expect(chain.anchorCount).toBe(1);
    expect(chain.closed).toBe(false);
  });

  it("enqueues initiation payload", () => {
    const w = makeWitness();
    w.beginLifecycle("AI-EMRG.1", 1.0, 1.0, 0.0);
    expect(w.pending).toBe(1);
  });
});

describe("LifecycleChain methods", () => {
  const makeChain = () => {
    const w = new Witness({
      endpoint: "https://example.com",
      apiKey: "axm_test_key",
      tenantId: "TEST_TENANT",
      clearingLevel: 1,
    });
    const chain = w.beginLifecycle("AI-EMRG.1", 1.0, 1.0, 0.0);
    return { w, chain };
  };

  it("checkpoint mints with correct stage", () => {
    const { w, chain } = makeChain();
    const initialFp = chain.lastFingerprint;
    const payload = chain.checkpoint(1.0, 0.8, 0.0);
    expect(payload.lifecycle_stage).toBe("checkpoint");
    expect(payload.lifecycle_parent).toBe(initialFp);
    expect(payload.lifecycle_chain_id).toBe(chain.chainId);
    expect(chain.anchorCount).toBe(2);
    expect(chain.closed).toBe(false);
  });

  it("resolve closes the chain", () => {
    const { chain } = makeChain();
    const payload = chain.resolve(1.0, 1.0, 0.0);
    expect(payload.lifecycle_stage).toBe("resolved");
    expect(chain.closed).toBe(true);
  });

  it("abandon closes the chain", () => {
    const { chain } = makeChain();
    const payload = chain.abandon({ reason: "test" });
    expect(payload.lifecycle_stage).toBe("abandoned");
    expect(chain.closed).toBe(true);
  });

  it("rejects minting after terminal stage", () => {
    const { chain } = makeChain();
    chain.resolve(1.0, 1.0, 0.0);
    expect(() => chain.checkpoint(1.0, 0.5, 0.0)).toThrow("closed");
  });

  it("maintains parent chain across checkpoints", () => {
    const { chain } = makeChain();
    const fp0 = chain.lastFingerprint;
    const p1 = chain.checkpoint(1.0, 0.8, 0.0);
    expect(p1.lifecycle_parent).toBe(fp0);
    const fp1 = chain.lastFingerprint;
    const p2 = chain.checkpoint(1.0, 0.9, 0.0);
    expect(p2.lifecycle_parent).toBe(fp1);
  });
});

describe("Escalation", () => {
  it("creates a new chain for the target procedure", () => {
    const w = new Witness({
      endpoint: "https://example.com",
      apiKey: "axm_test_key",
      tenantId: "TEST_TENANT",
      clearingLevel: 1,
    });
    const driftChain = w.beginLifecycle("AI-DRIFT.2", 0.5, 0.0, 1.0);
    const emrgChain = driftChain.escalate("AI-EMRG.1", 1.0, 1.0, 0.0);

    expect(emrgChain).toBeInstanceOf(LifecycleChain);
    expect(emrgChain.chainId).not.toBe(driftChain.chainId);
    expect(emrgChain.chainId).toMatch(/^LC-[0-9a-f]{16}$/);
    // 3 payloads: drift initiated + emrg initiated + drift escalated
    expect(w.pending).toBe(3);
  });
});

describe("Witness.resumeLifecycle", () => {
  it("reconstructs a chain handle", () => {
    const w = new Witness({
      endpoint: "https://example.com",
      apiKey: "axm_test_key",
      tenantId: "TEST_TENANT",
      clearingLevel: 1,
    });
    const chain = w.resumeLifecycle("AI-EMRG.1", "LC-7a38936db8ecec94", "2e16e2fe92dd", 3);
    expect(chain.chainId).toBe("LC-7a38936db8ecec94");
    expect(chain.lastFingerprint).toBe("2e16e2fe92dd");
    expect(chain.anchorCount).toBe(3);
    expect(chain.closed).toBe(false);
  });

  it("validates chain ID format", () => {
    const w = new Witness({
      endpoint: "https://example.com",
      apiKey: "axm_test_key",
      tenantId: "TEST_TENANT",
      clearingLevel: 1,
    });
    expect(() => w.resumeLifecycle("AI-EMRG.1", "bad-id", "2e16e2fe92dd")).toThrow("Invalid lifecycle chain ID");
  });

  it("resumed chain can mint", () => {
    const w = new Witness({
      endpoint: "https://example.com",
      apiKey: "axm_test_key",
      tenantId: "TEST_TENANT",
      clearingLevel: 1,
    });
    const chain = w.resumeLifecycle("AI-EMRG.1", "LC-7a38936db8ecec94", "2e16e2fe92dd");
    const payload = chain.checkpoint(1.0, 0.9, 0.0);
    expect(payload.lifecycle_parent).toBe("2e16e2fe92dd");
    expect(payload.lifecycle_chain_id).toBe("LC-7a38936db8ecec94");
  });
});

// ── Operational Governance Methods ──────────────────────────────

describe("witnessOperationalOverride (AI-EMRG.1)", () => {
  const makeWitness = () => new Witness({
    endpoint: "https://example.com",
    apiKey: "axm_test_key",
    tenantId: "TEST_TENANT",
    clearingLevel: 1,
  });

  it("mints AI-EMRG.1 with correct factors", () => {
    const w = makeWitness();
    const p = w.witnessOperationalOverride({
      triggerType: "operator_command",
      authorizationLevel: "supervisor",
      fallbackState: "safe_state",
    });
    expect(p.procedure_id).toBe("AI-EMRG.1");
    expect(p.factor_a).toBe(1); // operator_command
    expect(p.factor_b).toBe(1); // supervisor
    expect(p.factor_c).toBe(0); // safe_state
  });

  it("includes context at clearing level 1", () => {
    const w = makeWitness();
    const p = w.witnessOperationalOverride({
      triggerType: "escalation_protocol",
      authorizationLevel: "emergency_responder",
      fallbackState: "manual_mode",
      systemId: "reactor-ai-v3",
      operatorId: "eng-042",
    });
    expect(p.ai_model_id).toBe("reactor-ai-v3");
    expect(p.ai_context?.operator_id).toBe("eng-042");
  });

  it("code maps are correct", () => {
    expect(OVERRIDE_TRIGGER_CODES.emergency_stop).toBe(0);
    expect(AUTHORIZATION_LEVEL_CODES.site_manager).toBe(2);
    expect(FALLBACK_STATE_CODES.full_shutdown).toBe(4);
  });
});

describe("witnessDriftConsequence (AI-DRIFT.2)", () => {
  const makeWitness = () => new Witness({
    endpoint: "https://example.com",
    apiKey: "axm_test_key",
    tenantId: "TEST_TENANT",
    clearingLevel: 1,
  });

  it("mints AI-DRIFT.2 with correct factors", () => {
    const w = makeWitness();
    const p = w.witnessDriftConsequence({
      driftMagnitude: 0.15,
      consequenceCategory: "safety",
      responseAction: "circuit_breaker",
    });
    expect(p.procedure_id).toBe("AI-DRIFT.2");
    expect(p.factor_a).toBe(0.15);
    expect(p.factor_b).toBe(0);  // safety
    expect(p.factor_c).toBe(3);  // circuit_breaker
  });

  it("code maps are correct", () => {
    expect(CONSEQUENCE_CATEGORY_CODES.reputational).toBe(4);
    expect(DRIFT_RESPONSE_CODES.emergency_shutdown).toBe(5);
  });
});

describe("witnessChampionChallenger (AI-ASSESS.1)", () => {
  const makeWitness = () => new Witness({
    endpoint: "https://example.com",
    apiKey: "axm_test_key",
    tenantId: "TEST_TENANT",
    clearingLevel: 1,
  });

  it("mints AI-ASSESS.1 with x1000 divergence scaling", () => {
    const w = makeWitness();
    const p = w.witnessChampionChallenger({
      inputsProcessed: 10000,
      maxDivergence: 0.023,
      thresholdBreached: false,
    });
    expect(p.procedure_id).toBe("AI-ASSESS.1");
    expect(p.factor_a).toBe(10000);
    expect(p.factor_b).toBe(23); // 0.023 * 1000
    expect(p.factor_c).toBe(0);  // not breached
  });

  it("sets factor_c=1 when breached", () => {
    const w = makeWitness();
    const p = w.witnessChampionChallenger({
      inputsProcessed: 5000,
      maxDivergence: 0.15,
      thresholdBreached: true,
    });
    expect(p.factor_c).toBe(1);
  });

  it("includes context with model ids", () => {
    const w = makeWitness();
    const p = w.witnessChampionChallenger({
      inputsProcessed: 10000,
      maxDivergence: 0.023,
      thresholdBreached: false,
      championId: "gpt-4o-2026-05",
      challengerId: "gpt-4o-2026-07",
    });
    expect(p.ai_model_id).toBe("gpt-4o-2026-05");
    expect(p.ai_context?.challenger_id).toBe("gpt-4o-2026-07");
  });
});
