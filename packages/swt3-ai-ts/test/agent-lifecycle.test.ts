/**
 * Tests for PPA #23 agent lifecycle methods:
 * AI-DEL.1, AI-CAP.1, AI-AUTO.3, AI-COST.1, AI-CLR.2.
 */
import { describe, it, expect } from "vitest";
import { Witness } from "../src/witness.js";

function w(opts: Record<string, unknown> = {}) {
  return new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "TEST", clearingLevel: 1, disableFlush: true, ...opts });
}

// ── AI-DEL.1: Delegation Tree Witnessing ──────────────────────────

describe("witnessDelegation (AI-DEL.1)", () => {
  it("mints correct procedure", () => {
    const p = w().witnessDelegation({ scopeHash: "abc123", delegationDepth: 2, ttlSeconds: 3600, parentAgentId: "parent", childAgentId: "child" });
    expect(p.procedure_id).toBe("AI-DEL.1");
  });

  it("factor_b is delegation depth", () => {
    const p = w().witnessDelegation({ scopeHash: "abc", delegationDepth: 5, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c" });
    expect(p.factor_b).toBe(5);
  });

  it("factor_c is TTL seconds", () => {
    const p = w().witnessDelegation({ scopeHash: "abc", delegationDepth: 1, ttlSeconds: 7200, parentAgentId: "p", childAgentId: "c" });
    expect(p.factor_c).toBe(7200);
  });

  it("factor_a derives from scope hash", () => {
    const p = w().witnessDelegation({ scopeHash: "test-scope", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c" });
    expect(p.factor_a).toBeGreaterThan(0);
  });

  it("factor_a is 0 for empty scope", () => {
    const p = w().witnessDelegation({ scopeHash: "", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c" });
    expect(p.factor_a).toBe(0);
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessDelegation({ scopeHash: "abc", delegationDepth: 2, ttlSeconds: 3600, parentAgentId: "parent", childAgentId: "child" });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.provider).toBe("delegation-tree");
    expect(p.ai_context!.scope_hash).toBe("abc");
    expect(p.ai_context!.delegation_depth).toBe(2);
    expect(p.ai_context!.ttl_seconds).toBe(3600);
    expect(p.ai_context!.parent_agent_id).toBe("parent");
    expect(p.ai_context!.child_agent_id).toBe("child");
  });

  it("strips context at clearing level 2", () => {
    const p = w({ clearingLevel: 2 }).witnessDelegation({ scopeHash: "abc", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c" });
    expect(p.ai_context).toBeUndefined();
  });

  it("records cascade revocation flag", () => {
    const p = w().witnessDelegation({ scopeHash: "abc", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c", cascadeRevocation: true });
    expect(p.ai_context!.cascade_revocation).toBe(true);
  });

  it("records sub-delegation flag", () => {
    const p = w().witnessDelegation({ scopeHash: "abc", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c", subDelegationAllowed: true });
    expect(p.ai_context!.sub_delegation_allowed).toBe(true);
  });

  it("includes delegated capabilities when provided", () => {
    const p = w().witnessDelegation({ scopeHash: "abc", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c", delegatedCapabilities: ["read", "write"] });
    expect(p.ai_context!.delegated_capabilities).toEqual(["read", "write"]);
  });

  it("includes chain merkle when provided", () => {
    const p = w().witnessDelegation({ scopeHash: "abc", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c", delegationChainMerkle: "merkle123" });
    expect(p.ai_context!.delegation_chain_merkle).toBe("merkle123");
  });

  it("includes authorization chain when provided", () => {
    const p = w().witnessDelegation({ scopeHash: "abc", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c", authorizationChain: ["human", "a", "b"] });
    expect(p.ai_context!.authorization_chain).toEqual(["human", "a", "b"]);
  });

  it("mints valid 12-char hex fingerprint", () => {
    const p = w().witnessDelegation({ scopeHash: "abc", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c" });
    expect(p.anchor_fingerprint).toHaveLength(12);
    expect(parseInt(p.anchor_fingerprint, 16)).not.toBeNaN();
  });

  it("same scope_hash produces same factor_a", () => {
    const a1 = w().witnessDelegation({ scopeHash: "same", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c" }).factor_a;
    const a2 = w().witnessDelegation({ scopeHash: "same", delegationDepth: 1, ttlSeconds: 3600, parentAgentId: "p", childAgentId: "c" }).factor_a;
    expect(a1).toBe(a2);
  });
});

// ── AI-CAP.1: Capability Attestation ──────────────────────────────

describe("witnessCapabilityAttestation (AI-CAP.1)", () => {
  it("mints correct procedure", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2 });
    expect(p.procedure_id).toBe("AI-CAP.1");
  });

  it("factor_b is capability count", () => {
    expect(w().witnessCapabilityAttestation({ manifestHash: "h", capabilityCount: 10, autonomyLevel: 1 }).factor_b).toBe(10);
  });

  it("factor_c is autonomy level", () => {
    expect(w().witnessCapabilityAttestation({ manifestHash: "h", capabilityCount: 5, autonomyLevel: 3 }).factor_c).toBe(3);
  });

  it("factor_a derives from manifest hash", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "my-manifest", capabilityCount: 5, autonomyLevel: 2 });
    expect(p.factor_a).toBeGreaterThan(0);
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2 });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.provider).toBe("capability-attestation");
    expect(p.ai_context!.manifest_hash).toBe("mh");
    expect(p.ai_context!.capability_count).toBe(5);
    expect(p.ai_context!.autonomy_level).toBe(2);
  });

  it("strips context at clearing level 2", () => {
    const p = w({ clearingLevel: 2 }).witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2 });
    expect(p.ai_context).toBeUndefined();
  });

  it("records drift_detected flag", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2, driftDetected: true });
    expect(p.ai_context!.drift_detected).toBe(true);
  });

  it("records hitl_required flag", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2, hitlRequired: true });
    expect(p.ai_context!.hitl_required).toBe(true);
  });

  it("includes declared capabilities", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2, declaredCapabilities: ["search", "code"] });
    expect(p.ai_context!.declared_capabilities).toEqual(["search", "code"]);
  });

  it("includes observed capabilities", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2, observedCapabilities: ["search"] });
    expect(p.ai_context!.observed_capabilities).toEqual(["search"]);
  });

  it("uses provided model_id", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2, modelId: "gpt-4o" });
    expect(p.ai_model_id).toBe("gpt-4o");
  });

  it("default model_id includes autonomy level", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2 });
    expect(p.ai_model_id).toBe("capability-level-2");
  });

  it("includes capability version", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2, capabilityVersion: "v3.1" });
    expect(p.ai_context!.capability_version).toBe("v3.1");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const p = w().witnessCapabilityAttestation({ manifestHash: "mh", capabilityCount: 5, autonomyLevel: 2 });
    expect(p.anchor_fingerprint).toHaveLength(12);
    expect(parseInt(p.anchor_fingerprint, 16)).not.toBeNaN();
  });
});

// ── AI-AUTO.3: Autonomy Level Transition ──────────────────────────

describe("witnessAutonomyTransition (AI-AUTO.3)", () => {
  it("mints correct procedure", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 1, toLevel: 2, triggerType: "policy" });
    expect(p.procedure_id).toBe("AI-AUTO.3");
  });

  it("factor_a is from_level", () => {
    expect(w().witnessAutonomyTransition({ fromLevel: 0, toLevel: 3, triggerType: "manual" }).factor_a).toBe(0);
  });

  it("factor_b is to_level", () => {
    expect(w().witnessAutonomyTransition({ fromLevel: 1, toLevel: 3, triggerType: "manual" }).factor_b).toBe(3);
  });

  it("factor_c is trigger hash", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 1, toLevel: 2, triggerType: "policy" });
    expect(p.factor_c).toBeGreaterThan(0);
  });

  it("trigger is case-insensitive", () => {
    const a = w().witnessAutonomyTransition({ fromLevel: 1, toLevel: 2, triggerType: "POLICY" }).factor_c;
    const b = w().witnessAutonomyTransition({ fromLevel: 1, toLevel: 2, triggerType: "policy" }).factor_c;
    expect(a).toBe(b);
  });

  it("detects promotion direction", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 1, toLevel: 2, triggerType: "policy" });
    expect(p.ai_context!.direction).toBe("promotion");
  });

  it("detects demotion direction", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 2, toLevel: 1, triggerType: "risk" });
    expect(p.ai_context!.direction).toBe("demotion");
  });

  it("detects lateral direction", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 2, toLevel: 2, triggerType: "refresh" });
    expect(p.ai_context!.direction).toBe("lateral");
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 0, toLevel: 1, triggerType: "manual" });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.provider).toBe("autonomy-transition");
    expect(p.ai_context!.from_level).toBe(0);
    expect(p.ai_context!.to_level).toBe(1);
    expect(p.ai_context!.trigger_type).toBe("manual");
  });

  it("strips context at clearing level 2", () => {
    const p = w({ clearingLevel: 2 }).witnessAutonomyTransition({ fromLevel: 0, toLevel: 1, triggerType: "manual" });
    expect(p.ai_context).toBeUndefined();
  });

  it("records hitl_checkpoint", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 0, toLevel: 1, triggerType: "manual", hitlCheckpoint: true });
    expect(p.ai_context!.hitl_checkpoint).toBe(true);
  });

  it("includes justification", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 0, toLevel: 1, triggerType: "policy", justification: "Earned trust" });
    expect(p.ai_context!.justification).toBe("Earned trust");
  });

  it("includes risk_score", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 2, toLevel: 1, triggerType: "risk", riskScore: 0.85 });
    expect(p.ai_context!.risk_score).toBe(0.85);
  });

  it("includes transition_authorized_by", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 0, toLevel: 1, triggerType: "manual", transitionAuthorizedBy: "admin-42" });
    expect(p.ai_context!.transition_authorized_by).toBe("admin-42");
  });

  it("uses provided model_id", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 0, toLevel: 1, triggerType: "manual", modelId: "agent-v2" });
    expect(p.ai_model_id).toBe("agent-v2");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const p = w().witnessAutonomyTransition({ fromLevel: 0, toLevel: 1, triggerType: "manual" });
    expect(p.anchor_fingerprint).toHaveLength(12);
    expect(parseInt(p.anchor_fingerprint, 16)).not.toBeNaN();
  });
});

// ── AI-COST.1: Resource Consumption Witnessing ────────────────────

describe("witnessResourceConsumption (AI-COST.1)", () => {
  it("mints correct procedure", () => {
    const p = w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "0.42" });
    expect(p.procedure_id).toBe("AI-COST.1");
  });

  it("factor_a is token count", () => {
    expect(w().witnessResourceConsumption({ tokenCount: 12345, apiCalls: 10, estimatedCost: "1.00" }).factor_a).toBe(12345);
  });

  it("factor_b is API calls", () => {
    expect(w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 25, estimatedCost: "0.50" }).factor_b).toBe(25);
  });

  it("factor_c is estimated cost as float", () => {
    expect(w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "3.14" }).factor_c).toBeCloseTo(3.14);
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "0.42" });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.provider).toBe("resource-consumption");
    expect(p.ai_context!.token_count).toBe(5000);
    expect(p.ai_context!.api_calls).toBe(10);
    expect(p.ai_context!.estimated_cost).toBe("0.42");
  });

  it("strips context at clearing level 2", () => {
    const p = w({ clearingLevel: 2 }).witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "0.42" });
    expect(p.ai_context).toBeUndefined();
  });

  it("records cost_anomaly flag", () => {
    const p = w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "0.42", costAnomaly: true });
    expect(p.ai_context!.cost_anomaly).toBe(true);
  });

  it("includes budget_threshold", () => {
    const p = w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "0.42", budgetThreshold: "100.00" });
    expect(p.ai_context!.budget_threshold).toBe("100.00");
  });

  it("includes resource_attribution_id", () => {
    const p = w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "0.42", resourceAttributionId: "project-x" });
    expect(p.ai_context!.resource_attribution_id).toBe("project-x");
  });

  it("includes consumption_window_seconds", () => {
    const p = w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "0.42", consumptionWindowSeconds: 300 });
    expect(p.ai_context!.consumption_window_seconds).toBe(300);
  });

  it("default model_id is cost-witness", () => {
    const p = w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "0.42" });
    expect(p.ai_model_id).toBe("cost-witness");
  });

  it("uses provided model_id", () => {
    const p = w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "0.42", modelId: "claude-4" });
    expect(p.ai_model_id).toBe("claude-4");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const p = w().witnessResourceConsumption({ tokenCount: 5000, apiCalls: 10, estimatedCost: "0.42" });
    expect(p.anchor_fingerprint).toHaveLength(12);
    expect(parseInt(p.anchor_fingerprint, 16)).not.toBeNaN();
  });
});

// ── AI-CLR.2: Clearing Fidelity Attestation ───────────────────────

describe("witnessClearingFidelity (AI-CLR.2)", () => {
  it("mints correct procedure", () => {
    const p = w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 8 });
    expect(p.procedure_id).toBe("AI-CLR.2");
  });

  it("factor_a is clearing level applied", () => {
    expect(w().witnessClearingFidelity({ clearingLevelApplied: 3, inputFieldCount: 15, outputFieldCount: 5 }).factor_a).toBe(3);
  });

  it("factor_b is input field count", () => {
    expect(w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 20, outputFieldCount: 10 }).factor_b).toBe(20);
  });

  it("factor_c is output field count", () => {
    expect(w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 7 }).factor_c).toBe(7);
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 8 });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.provider).toBe("clearing-fidelity");
    expect(p.ai_context!.clearing_level_applied).toBe(2);
    expect(p.ai_context!.input_field_count).toBe(15);
    expect(p.ai_context!.output_field_count).toBe(8);
  });

  it("strips context at clearing level 2", () => {
    const p = w({ clearingLevel: 2 }).witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 8 });
    expect(p.ai_context).toBeUndefined();
  });

  it("records anomaly_detected flag", () => {
    const p = w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 8, anomalyDetected: true });
    expect(p.ai_context!.anomaly_detected).toBe(true);
  });

  it("includes clearing engine version", () => {
    const p = w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 8, clearingEngineVersion: "v2.1.0" });
    expect(p.ai_context!.clearing_engine_version).toBe("v2.1.0");
  });

  it("includes fidelity hash", () => {
    const p = w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 8, fidelityHash: "abc123def456" });
    expect(p.ai_context!.fidelity_hash).toBe("abc123def456");
  });

  it("includes stripped fields", () => {
    const p = w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 8, strippedFields: ["prompt", "response"] });
    expect(p.ai_context!.stripped_fields).toEqual(["prompt", "response"]);
  });

  it("default model_id is clearing-fidelity", () => {
    const p = w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 8 });
    expect(p.ai_model_id).toBe("clearing-fidelity");
  });

  it("uses provided model_id", () => {
    const p = w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 8, modelId: "custom" });
    expect(p.ai_model_id).toBe("custom");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const p = w().witnessClearingFidelity({ clearingLevelApplied: 2, inputFieldCount: 15, outputFieldCount: 8 });
    expect(p.anchor_fingerprint).toHaveLength(12);
    expect(parseInt(p.anchor_fingerprint, 16)).not.toBeNaN();
  });

  it("CL0 full retention: output equals input", () => {
    const p = w({ clearingLevel: 0 }).witnessClearingFidelity({ clearingLevelApplied: 0, inputFieldCount: 15, outputFieldCount: 15 });
    expect(p.factor_a).toBe(0);
    expect(p.factor_b).toBe(15);
    expect(p.factor_c).toBe(15);
  });

  it("CL3 maximum stripping: output much less than input", () => {
    const p = w().witnessClearingFidelity({ clearingLevelApplied: 3, inputFieldCount: 15, outputFieldCount: 3 });
    expect(p.factor_a).toBe(3);
    expect(p.factor_c).toBe(3);
  });
});
