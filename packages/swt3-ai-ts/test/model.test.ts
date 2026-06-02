/**
 * Model weights + procedural knowledge witnessing tests (TypeScript).
 *
 * Tests for AI-MDL.5/6/7 and AI-SKILL.1/2/3.
 */

import { describe, it, expect, vi } from "vitest";
import { Witness } from "../src/witness.js";
import type { AdapterInfo, SkillInfo, MemorySource } from "../src/types.js";

function makeWitness(clearingLevel: 0 | 1 | 2 | 3 = 1): Witness {
  const w = new Witness({
    endpoint: "https://test.tenova.io",
    apiKey: "axm_test_key",
    tenantId: "TEST_TENANT",
    clearingLevel,
  });
  (w as any).buffer = {
    enqueueMany: vi.fn(),
    flush: vi.fn().mockResolvedValue([]),
    stop: vi.fn().mockResolvedValue([]),
    pending: 0,
    receipts: [],
  };
  return w;
}

// ---------------------------------------------------------------------------
// AI-MDL.5: Weight File Integrity
// ---------------------------------------------------------------------------

describe("witnessModelWeights", () => {
  it("attests pre-computed hash", () => {
    const w = makeWitness();
    const p = w.witnessModelWeights({ fileHash: "abc123def456", format: "safetensors" });
    expect(p.procedure_id).toBe("AI-MDL.5");
    expect(p.factor_a).toBe(1);
    expect(p.factor_b).toBe(1);
    expect(p.ai_context!.file_hash).toBe("abc123def456");
  });

  it("detects hash mismatch", () => {
    const w = makeWitness();
    const p = w.witnessModelWeights(
      { fileHash: "actual" },
      { expectedHash: "different" },
    );
    expect(p.factor_b).toBe(0);
  });

  it("detects hash match", () => {
    const w = makeWitness();
    const p = w.witnessModelWeights(
      { fileHash: "matching" },
      { expectedHash: "matching" },
    );
    expect(p.factor_b).toBe(1);
  });

  it("strips context at level 3", () => {
    const w = makeWitness(3);
    const p = w.witnessModelWeights({ fileHash: "abc" });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// AI-MDL.6: Adapter Stack
// ---------------------------------------------------------------------------

describe("witnessAdapterStack", () => {
  it("witnesses multiple adapters", () => {
    const w = makeWitness();
    const adapters: AdapterInfo[] = [
      { name: "lora-legal", adapterHash: "aaa111" },
      { name: "lora-medical", adapterHash: "bbb222" },
    ];
    const p = w.witnessAdapterStack(adapters, "llama-3.1-70b");
    expect(p.procedure_id).toBe("AI-MDL.6");
    expect(p.factor_a).toBe(2);
    expect(p.factor_b).toBe(1);
    expect(p.ai_context!.base_model_id).toBe("llama-3.1-70b");
  });

  it("handles empty stack", () => {
    const w = makeWitness();
    const p = w.witnessAdapterStack([]);
    expect(p.factor_a).toBe(0);
    expect(p.factor_b).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// AI-MDL.7: Quantization
// ---------------------------------------------------------------------------

describe("witnessQuantization", () => {
  it("witnesses GPTQ", () => {
    const w = makeWitness();
    const p = w.witnessQuantization("gptq", { bits: 4, groupSize: 128 });
    expect(p.procedure_id).toBe("AI-MDL.7");
    expect(p.factor_c).toBe(5);
    expect(p.ai_context!.method).toBe("gptq");
    expect(p.ai_context!.bits).toBe(4);
  });

  it("witnesses FP16", () => {
    const w = makeWitness();
    const p = w.witnessQuantization("FP16");
    expect(p.factor_c).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// AI-SKILL.1: Skill Manifest
// ---------------------------------------------------------------------------

describe("witnessSkillManifest", () => {
  it("witnesses string skills", () => {
    const w = makeWitness();
    const p = w.witnessSkillManifest(["code_exec", "web_search", "file_read"]);
    expect(p.procedure_id).toBe("AI-SKILL.1");
    expect(p.factor_a).toBe(3);
    expect(p.factor_b).toBe(1);
    expect((p.ai_context!.skills as any[]).length).toBe(3);
    expect(p.ai_context!.manifest_hash).toBeTruthy();
  });

  it("witnesses SkillInfo objects", () => {
    const w = makeWitness();
    const skills: SkillInfo[] = [
      { name: "search", version: "1.2.0", skillHash: "abc123" },
      { name: "calc", version: "2.0.0", skillHash: "def456" },
    ];
    const p = w.witnessSkillManifest(skills);
    expect(p.factor_a).toBe(2);
  });

  it("detects manifest mismatch", () => {
    const w = makeWitness();
    const p = w.witnessSkillManifest(["a", "b"], { expectedManifestHash: "wrong" });
    expect(p.factor_b).toBe(0);
  });

  it("strips context at level 3", () => {
    const w = makeWitness(3);
    const p = w.witnessSkillManifest(["skill"]);
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// AI-SKILL.2: Memory Context
// ---------------------------------------------------------------------------

describe("witnessMemoryContext", () => {
  it("witnesses multiple sources", () => {
    const w = makeWitness();
    const sources: MemorySource[] = [
      { sourceType: "vector_store", sourceId: "pinecone-prod", contentHash: "aaa" },
      { sourceType: "conversation", sourceId: "session-123" },
    ];
    const p = w.witnessMemoryContext(sources);
    expect(p.procedure_id).toBe("AI-SKILL.2");
    expect(p.factor_a).toBe(2);
    expect(p.factor_b).toBe(1);
  });

  it("detects anonymous source", () => {
    const w = makeWitness();
    const p = w.witnessMemoryContext([{ sourceType: "scratchpad" }]);
    expect(p.factor_b).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// AI-SKILL.3: Reward Model
// ---------------------------------------------------------------------------

describe("witnessRewardModel", () => {
  it("witnesses identified reward model", () => {
    const w = makeWitness();
    const p = w.witnessRewardModel("rm-v3-legal", { modelHash: "abc", method: "dpo" });
    expect(p.procedure_id).toBe("AI-SKILL.3");
    expect(p.factor_b).toBe(1);
    expect(p.ai_context!.model_id).toBe("rm-v3-legal");
    expect(p.ai_context!.method).toBe("dpo");
  });

  it("detects unidentified reward model", () => {
    const w = makeWitness();
    const p = w.witnessRewardModel("");
    expect(p.factor_b).toBe(0);
  });
});
