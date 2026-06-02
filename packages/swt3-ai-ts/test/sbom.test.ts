/**
 * Tests for AI-SBOM.1 AI Bill of Materials Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { SBOM_FORMAT_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessSbom (AI-SBOM.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors for cyclonedx", () => {
    const w = mkWitness();
    const p = w.witnessSbom({
      totalComponents: 42, clustersDocumented: 7,
      format: "cyclonedx", bomHash: "abc123def456",
    });
    expect(p.procedure_id).toBe("AI-SBOM.1");
    expect(p.factor_a).toBe(42);
    expect(p.factor_b).toBe(7);
    expect(p.factor_c).toBe(0); // cyclonedx
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all SBOM format codes", () => {
    const w = mkWitness();
    for (const [format, code] of Object.entries(SBOM_FORMAT_CODES)) {
      const p = w.witnessSbom({
        totalComponents: 10, clustersDocumented: 3,
        format, bomHash: "hash123",
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown format defaults to 3", () => {
    const w = mkWitness();
    const p = w.witnessSbom({
      totalComponents: 5, clustersDocumented: 2,
      format: "proprietary_format", bomHash: "hash123",
    });
    expect(p.factor_c).toBe(3);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessSbom({
      totalComponents: 42, clustersDocumented: 7,
      format: "cyclonedx", bomHash: "abc123def456",
      version: "1.6.0", modelCount: 3, datasetCount: 5,
      infrastructureComponents: 12,
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.provider).toBe("ai-sbom");
    expect(p.ai_context!.bom_hash).toBe("abc123def456");
    expect(p.ai_context!.format).toBe("cyclonedx");
    expect(p.ai_context!.version).toBe("1.6.0");
    expect(p.ai_context!.model_count).toBe(3);
    expect(p.ai_context!.dataset_count).toBe(5);
    expect(p.ai_context!.infrastructure_components).toBe(12);
    expect(p.ai_model_id).toBe("sbom-cyclonedx");
  });

  it("omits optional context fields when not provided", () => {
    const w = mkWitness({ clearingLevel: 0 });
    const p = w.witnessSbom({
      totalComponents: 10, clustersDocumented: 4,
      format: "spdx", bomHash: "hash456",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.version).toBeUndefined();
    expect(p.ai_context!.model_count).toBeUndefined();
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessSbom({
      totalComponents: 42, clustersDocumented: 7,
      format: "cyclonedx", bomHash: "abc123",
      version: "1.6.0",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(42);
    expect(p.factor_b).toBe(7);
    expect(p.factor_c).toBe(0);
  });

  it("strips context at clearing level 3", () => {
    const w = mkWitness({ clearingLevel: 3 });
    const p = w.witnessSbom({
      totalComponents: 20, clustersDocumented: 5,
      format: "spdx", bomHash: "hash789",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(20);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "sbom-scanner-agent" });
    const p = w.witnessSbom({
      totalComponents: 15, clustersDocumented: 6,
      format: "cyclonedx", bomHash: "hash123",
    });
    expect(p.agent_id).toBe("sbom-scanner-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessSbom({
      totalComponents: 1, clustersDocumented: 1,
      format: "custom", bomHash: "h",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
