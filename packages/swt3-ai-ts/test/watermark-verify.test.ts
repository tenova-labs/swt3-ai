/**
 * Tests for AI-WATERMARK.1 Watermark Verification Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { DETECTION_METHOD_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessWatermarkVerification (AI-WATERMARK.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessWatermarkVerification({
      itemsChecked: 50, watermarksDetected: 45,
      detectionMethod: "c2pa_verify",
    });
    expect(p.procedure_id).toBe("AI-WATERMARK.1");
    expect(p.factor_a).toBe(50);
    expect(p.factor_b).toBe(45);
    expect(p.factor_c).toBe(DETECTION_METHOD_CODES["c2pa_verify"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all detection method codes", () => {
    const w = mkWitness();
    for (const [method, code] of Object.entries(DETECTION_METHOD_CODES)) {
      const p = w.witnessWatermarkVerification({
        itemsChecked: 10, watermarksDetected: 8, detectionMethod: method,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 4", () => {
    const w = mkWitness();
    const p = w.witnessWatermarkVerification({
      itemsChecked: 10, watermarksDetected: 8,
      detectionMethod: "unknown_method",
    });
    expect(p.factor_c).toBe(4);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessWatermarkVerification({
      itemsChecked: 50, watermarksDetected: 45,
      detectionMethod: "c2pa_verify",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.detection_method).toBe("c2pa_verify");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessWatermarkVerification({
      itemsChecked: 50, watermarksDetected: 45,
      detectionMethod: "c2pa_verify",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(50);
    expect(p.factor_b).toBe(45);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "watermark-verify-agent" });
    const p = w.witnessWatermarkVerification({
      itemsChecked: 10, watermarksDetected: 9,
      detectionMethod: "c2pa_verify",
    });
    expect(p.agent_id).toBe("watermark-verify-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessWatermarkVerification({
      itemsChecked: 1, watermarksDetected: 1,
      detectionMethod: "c2pa_verify",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
