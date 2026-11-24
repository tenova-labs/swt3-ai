import { describe, it, expect, vi } from "vitest";
import { TaskBuilder, generateTaskId } from "../src/task";
import { getMerkleRoot } from "../src/merkle";
import { sha256Truncated } from "../src/fingerprint";
import {
  TASK_TYPE_CODES,
  TASK_OUTCOME_CODES,
  COST_SOURCE_CODES,
} from "../src/types";
import type { WitnessPayload, TaskReceipt } from "../src/types";

function makeMockWitness(clearingLevel = 1) {
  return {
    config: {
      tenantId: "test_tenant",
      clearingLevel,
      policyVersion: undefined,
      agentId: undefined,
    },
    buffer: {
      enqueueMany: vi.fn(),
    },
    _applyOperationalMetadata: vi.fn(),
    _activeTask: null as any,
  };
}

function makeMockChain() {
  return {
    chainId: "LC-1234567890abcdef",
    lastFingerprint: "aabbccddeeff",
    anchorCount: 1,
    closed: false,
    _lastFingerprint: "aabbccddeeff",
    _anchorCount: 1,
    _closed: false,
  };
}

function makePayload(
  procedureId = "AI-INF.1",
  fingerprint = "a1b2c3d4e5f6",
  overrides: Partial<WitnessPayload> = {},
): WitnessPayload {
  return {
    procedure_id: procedureId,
    factor_a: 1,
    factor_b: 1,
    factor_c: 0,
    clearing_level: 1,
    anchor_fingerprint: fingerprint,
    anchor_epoch: 1700000000,
    fingerprint_timestamp_ms: 1700000000000,
    ...overrides,
  };
}

describe("Type Codes", () => {
  it("TASK_TYPE_CODES has 9 entries", () => {
    expect(Object.keys(TASK_TYPE_CODES)).toHaveLength(9);
    expect(TASK_TYPE_CODES.inference).toBe(0);
    expect(TASK_TYPE_CODES.custom).toBe(8);
  });

  it("TASK_OUTCOME_CODES has 5 entries", () => {
    expect(Object.keys(TASK_OUTCOME_CODES)).toHaveLength(5);
    expect(TASK_OUTCOME_CODES.completed).toBe(0);
    expect(TASK_OUTCOME_CODES.abandoned).toBe(4);
  });

  it("COST_SOURCE_CODES has 4 entries", () => {
    expect(Object.keys(COST_SOURCE_CODES)).toHaveLength(4);
    expect(COST_SOURCE_CODES.manual).toBe(0);
    expect(COST_SOURCE_CODES.invoice_verified).toBe(3);
  });
});

describe("Task ID Generation", () => {
  it("is deterministic", () => {
    const id1 = generateTaskId("tenant", "LC-abc123", 1700000000000);
    const id2 = generateTaskId("tenant", "LC-abc123", 1700000000000);
    expect(id1).toBe(id2);
  });

  it("has correct prefix and length", () => {
    const tid = generateTaskId("tenant", "LC-abc123", 1700000000000);
    expect(tid.startsWith("TASK-")).toBe(true);
    expect(tid).toHaveLength(21);
  });

  it("matches Python test vector", () => {
    const tid = generateTaskId(
      "test-tenant-001",
      "LC-a1b2c3d4e5f6a1b2",
      1732147200000,
    );
    expect(tid).toBe("TASK-5e5ec230343e8d7f");
  });
});

describe("TaskBuilder.addStep", () => {
  it("adds step with fingerprint", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    expect(builder.stepCount).toBe(1);
  });

  it("adds step with payload and tracks procedure", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    const payload = makePayload("AI-INF.1", "aabbccddee11");
    builder.addStep({ payload });
    expect(builder.stepCount).toBe(1);
  });

  it("tracks tool calls from AI-TOOL.1 payloads", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ payload: makePayload("AI-TOOL.1", "aabbccddee22") });
    expect((builder as any)._toolCallCount).toBe(1);
  });

  it("tracks agent IDs", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ payload: makePayload("AI-INF.1", "aabb", { agent_id: "agent-1" }) });
    expect((builder as any)._agentIds.has("agent-1")).toBe(true);
  });

  it("throws without fingerprint or payload", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    expect(() => builder.addStep({})).toThrow("fingerprint or payload");
  });
});

describe("TaskBuilder.declareCost", () => {
  it("stores manual cost", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.declareCost({ declared: 0.0042 });
    expect((builder as any)._costDeclared).toBe(0.0042);
    expect((builder as any)._costSource).toBe(0);
  });

  it("stores provider_api cost source", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.declareCost({ declared: 0.0042, source: "provider_api" });
    expect((builder as any)._costSource).toBe(2);
  });
});

describe("TaskBuilder.complete", () => {
  it("mints AI-TASK.1 anchor", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    builder.addStep({ fingerprint: "f6e5d4c3b2a1" });
    const receipt = builder.complete();
    expect(receipt.stepCount).toBe(2);
    expect(receipt.anchor.procedure_id).toBe("AI-TASK.1");
    expect(receipt.anchor.factor_a).toBe(2);
    expect(receipt.anchor.factor_c).toBe(0); // completed
    expect(receipt.anchor.lifecycle_stage).toBe("resolved");
  });

  it("computes correct merkle root", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    const fps = ["a1b2c3d4e5f6", "f6e5d4c3b2a1", "112233445566"];
    for (const fp of fps) builder.addStep({ fingerprint: fp });
    const receipt = builder.complete();
    expect(receipt.merkleRoot).toBe(getMerkleRoot(fps));
  });

  it("generates task ID with prefix", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    const receipt = builder.complete();
    expect(receipt.taskId.startsWith("TASK-")).toBe(true);
  });

  it("enqueues payload to buffer", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    builder.complete();
    expect(w.buffer.enqueueMany).toHaveBeenCalled();
  });

  it("closes the chain", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    builder.complete();
    expect(chain._closed).toBe(true);
  });

  it("clears active task", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    w._activeTask = builder;
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    builder.complete();
    expect(w._activeTask).toBeNull();
  });
});

describe("TaskBuilder.fail", () => {
  it("sets outcome to failed", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    const receipt = builder.fail("model_timeout");
    expect(receipt.anchor.factor_c).toBe(2); // failed
    expect(builder.explicitlyFailed).toBe(true);
  });
});

describe("TaskBuilder.markStepsComplete", () => {
  it("sets stepsComplete flag", () => {
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    expect(builder.stepsComplete).toBe(false);
    builder.markStepsComplete();
    expect(builder.stepsComplete).toBe(true);
  });
});

describe("Clearing Levels", () => {
  it("level 0 includes declared outcome", () => {
    const w = makeMockWitness(0);
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    builder.declareOutcome("approved");
    const receipt = builder.complete();
    const ctx = receipt.anchor.ai_context!;
    expect(ctx.declared_outcome).toBe("approved");
    expect(ctx.task_type).toBe("workflow");
  });

  it("level 1 hashes outcome, no cleartext", () => {
    const w = makeMockWitness(1);
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    builder.declareOutcome("approved");
    const receipt = builder.complete();
    const ctx = receipt.anchor.ai_context!;
    expect(ctx.declared_outcome).toBeUndefined();
    expect(ctx.outcome_hash).toBeDefined();
    expect(ctx.task_type).toBe("workflow");
  });

  it("level 2 strips cost and agents, keeps merkle", () => {
    const w = makeMockWitness(2);
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    builder.declareCost({ declared: 0.01, source: "sdk_estimated" });
    const receipt = builder.complete();
    const ctx = receipt.anchor.ai_context!;
    expect(ctx.merkle_root).toBeDefined();
    expect(ctx.step_count).toBe(1);
    expect(ctx.cost_declared).toBeUndefined();
    expect(ctx.cost_ratio).toBeUndefined();
    expect(ctx.agent_ids).toBeUndefined();
    expect(ctx.task_type).toBeUndefined();
  });

  it("level 3 has no ai_context", () => {
    const w = makeMockWitness(3);
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    const receipt = builder.complete();
    expect(receipt.anchor.ai_context).toBeUndefined();
    expect(receipt.anchor.factor_a).toBe(1);
    expect(receipt.anchor.factor_c).toBe(0);
  });

  it("cost_source propagates at level 0", () => {
    const w = makeMockWitness(0);
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    builder.addStep({ fingerprint: "a1b2c3d4e5f6" });
    builder.declareCost({ declared: 0.01, source: "invoice_verified" });
    const receipt = builder.complete();
    expect(receipt.anchor.ai_context!.cost_source).toBe(3);
  });
});

describe("Cross-language parity", () => {
  it("task ID matches Python vector", () => {
    const tid = generateTaskId(
      "test-tenant-001",
      "LC-a1b2c3d4e5f6a1b2",
      1732147200000,
    );
    expect(tid).toBe("TASK-5e5ec230343e8d7f");
  });

  it("merkle root matches standalone computation", () => {
    const fps = ["a1b2c3d4e5f6", "f6e5d4c3b2a1", "112233445566"];
    const expected = getMerkleRoot(fps);
    const w = makeMockWitness();
    const chain = makeMockChain();
    const builder = new TaskBuilder(w, "test", "workflow", chain as any);
    for (const fp of fps) builder.addStep({ fingerprint: fp });
    const receipt = builder.complete();
    expect(receipt.merkleRoot).toBe(expected);
  });
});
