import { describe, it, expect } from "vitest";
import { Witness } from "../src/witness.js";
import { SAFETY_CLASSIFICATION_CODES } from "../src/types.js";

function makeWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    tenantId: "TEST_TENANT",
    clearingLevel: 1,
    ...opts,
  });
}

// -- AI-MOB.6: witnessTrajectory -----------------------------------------

describe("witnessTrajectory", () => {
  it("witnesses nominal pass with correct factors", () => {
    const w = makeWitness();
    const p = w.witnessTrajectory({ safetyValidated: true });
    expect(p.procedure_id).toBe("AI-MOB.6");
    expect(p.factor_a).toBe(1);
    expect(p.factor_b).toBe(1);
    expect(p.factor_c).toBe(1); // nominal
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("witnesses failed validation", () => {
    const w = makeWitness();
    const p = w.witnessTrajectory({ safetyValidated: false });
    expect(p.factor_b).toBe(0);
  });

  it("maps emergency classification to fc=4", () => {
    const w = makeWitness();
    const p = w.witnessTrajectory({
      safetyValidated: true, safetyClassification: "emergency",
    });
    expect(p.factor_c).toBe(4);
  });

  it("maps abort classification to fc=5", () => {
    const w = makeWitness();
    const p = w.witnessTrajectory({
      safetyValidated: false, safetyClassification: "abort",
    });
    expect(p.factor_c).toBe(5);
  });

  it("defaults unknown classification to 0", () => {
    const w = makeWitness();
    const p = w.witnessTrajectory({
      safetyValidated: true, safetyClassification: "unknown_value",
    });
    expect(p.factor_c).toBe(0);
  });

  it("includes full context at CL1", () => {
    const w = makeWitness({ clearingLevel: 1 });
    const p = w.witnessTrajectory({
      safetyValidated: true,
      waypointCount: 47,
      trajectoryHash: "abc123",
      cocTraceHash: "def456",
      cocNodeCount: 12,
      actionClass: "navigate",
      sensorSources: ["camera_front", "lidar_top", "radar"],
      modelId: "alpamayo-2-super",
    });
    expect(p.ai_model_id).toBe("alpamayo-2-super");
    expect(p.ai_context!.provider).toBe("trajectory");
    expect(p.ai_context!.waypoint_count).toBe(47);
    expect(p.ai_context!.trajectory_hash).toBe("abc123");
    expect(p.ai_context!.coc_trace_hash).toBe("def456");
    expect(p.ai_context!.coc_node_count).toBe(12);
    expect(p.ai_context!.action_class).toBe("navigate");
    expect(p.ai_context!.sensor_count).toBe(3);
    expect(p.ai_context!.sensor_sources).toEqual(["camera_front", "lidar_top", "radar"]);
  });

  it("strips context at CL2, keeps sensor_count", () => {
    const w = makeWitness({ clearingLevel: 2 });
    const p = w.witnessTrajectory({
      safetyValidated: true,
      sensorSources: ["camera_front", "lidar"],
      modelId: "test-model",
    });
    expect(p.ai_model_id).toBe("test-model");
    expect(p.ai_context!.provider_category).toBe("trajectory");
    expect(p.ai_context!.sensor_count).toBe(2);
    expect(p.ai_context!.sensor_sources).toBeUndefined();
  });

  it("hashes model_id at CL3", () => {
    const w = makeWitness({ clearingLevel: 3 });
    const p = w.witnessTrajectory({
      safetyValidated: true, modelId: "secret-model",
    });
    expect(p.ai_model_id).not.toBe("secret-model");
    expect(p.ai_model_id!.length).toBeLessThanOrEqual(16);
    expect(p.ai_context).toBeUndefined();
  });

  it("uses default model_id", () => {
    const w = makeWitness();
    const p = w.witnessTrajectory({ safetyValidated: true });
    expect(p.ai_model_id).toBe("trajectory-planner");
  });
});

// -- AI-MOB.7: wrapVLA ---------------------------------------------------

describe("wrapVLA", () => {
  it("wraps sync function and returns result", () => {
    const w = makeWitness();
    const predict = (frames: number[]) => frames.map(f => f * 2);
    const wrapped = w.wrapVLA(predict, "test-vla");
    const result = wrapped([1, 2, 3]);
    expect(result).toEqual([2, 4, 6]);
  });

  it("wraps async function and returns result", async () => {
    const w = makeWitness();
    const predict = async (frames: number[]) => frames.length;
    const wrapped = w.wrapVLA(predict, "async-vla");
    const result = await wrapped([1, 2]);
    expect(result).toBe(2);
  });

  it("propagates sync exceptions", () => {
    const w = makeWitness();
    const bad = () => { throw new Error("inference failed"); };
    const wrapped = w.wrapVLA(bad, "bad-vla");
    expect(() => wrapped()).toThrow("inference failed");
  });

  it("propagates async exceptions", async () => {
    const w = makeWitness();
    const bad = async () => { throw new Error("timeout"); };
    const wrapped = w.wrapVLA(bad, "bad-vla");
    await expect(wrapped()).rejects.toThrow("timeout");
  });

  it("accepts pre-computed frame hashes", () => {
    const w = makeWitness();
    const predict = (x: number) => x + 1;
    const wrapped = w.wrapVLA(predict, "hash-vla", ["h1", "h2"]);
    const result = wrapped(5);
    expect(result).toBe(6);
  });
});

// -- SAFETY_CLASSIFICATION_CODES -----------------------------------------

describe("SAFETY_CLASSIFICATION_CODES", () => {
  it("has all 6 codes", () => {
    expect(SAFETY_CLASSIFICATION_CODES.reserved).toBe(0);
    expect(SAFETY_CLASSIFICATION_CODES.nominal).toBe(1);
    expect(SAFETY_CLASSIFICATION_CODES.cautionary).toBe(2);
    expect(SAFETY_CLASSIFICATION_CODES.degraded).toBe(3);
    expect(SAFETY_CLASSIFICATION_CODES.emergency).toBe(4);
    expect(SAFETY_CLASSIFICATION_CODES.abort).toBe(5);
  });
});
