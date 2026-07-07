/**
 * SWT3 AI Witness SDK -- Provenance Chain References Tests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { normalizeReferences, extractPayloads } from "../src/clearing.js";
import type { InferenceRecord, AnchorReference } from "../src/types.js";

beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

function mkRecord(overrides: Partial<InferenceRecord> = {}): InferenceRecord {
  return {
    modelId: "gpt-4",
    modelHash: "abc123",
    promptHash: "p_hash",
    responseHash: "r_hash",
    latencyMs: 200,
    guardrailsActive: 1,
    guardrailsRequired: 1,
    guardrailPassed: true,
    hasRefusal: false,
    provider: "openai",
    guardrailNames: ["filter"],
    ...overrides,
  };
}

describe("normalizeReferences", () => {
  it("returns undefined for empty/null input", () => {
    expect(normalizeReferences(undefined)).toBeUndefined();
    expect(normalizeReferences([])).toBeUndefined();
  });

  it("normalizes string array to AnchorReference array", () => {
    const result = normalizeReferences(["abc123", "def456"]);
    expect(result).toEqual([
      { fingerprint: "abc123" },
      { fingerprint: "def456" },
    ]);
  });

  it("passes through structured references unchanged", () => {
    const refs: AnchorReference[] = [
      { fingerprint: "abc123", relationship: "model_source" },
      { fingerprint: "def456", provenance_token: "tok_xyz" },
    ];
    const result = normalizeReferences(refs);
    expect(result).toEqual(refs);
  });

  it("handles mixed input (strings + objects)", () => {
    const result = normalizeReferences([
      "abc123",
      { fingerprint: "def456", relationship: "training_data" },
    ]);
    expect(result).toEqual([
      { fingerprint: "abc123" },
      { fingerprint: "def456", relationship: "training_data" },
    ]);
  });
});

describe("references in extractPayloads", () => {
  it("references appear in payload when provided", () => {
    const refs: AnchorReference[] = [{ fingerprint: "upstream_fp_1" }];
    const payloads = extractPayloads(
      mkRecord(), "tenant_1", 1, 30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, refs,
    );
    expect(payloads.length).toBeGreaterThan(0);
    expect(payloads[0].references).toEqual(refs);
  });

  it("references absent from payload when not provided", () => {
    const payloads = extractPayloads(mkRecord(), "tenant_1", 1);
    expect(payloads.length).toBeGreaterThan(0);
    expect(payloads[0].references).toBeUndefined();
  });

  it("references survive clearing level 0 (analytics)", () => {
    const refs: AnchorReference[] = [{ fingerprint: "fp_0", relationship: "infra" }];
    const payloads = extractPayloads(
      mkRecord(), "t", 0, 30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, refs,
    );
    expect(payloads[0].references).toEqual(refs);
  });

  it("references survive clearing level 2 (sensitive)", () => {
    const refs: AnchorReference[] = [{ fingerprint: "fp_2" }];
    const payloads = extractPayloads(
      mkRecord(), "t", 2, 30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, refs,
    );
    expect(payloads[0].references).toEqual(refs);
  });

  it("references survive clearing level 3 (classified)", () => {
    const refs: AnchorReference[] = [{ fingerprint: "fp_3" }];
    const payloads = extractPayloads(
      mkRecord(), "t", 3, 30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, refs,
    );
    expect(payloads[0].references).toEqual(refs);
  });

  it("multiple references preserved in order", () => {
    const refs: AnchorReference[] = [
      { fingerprint: "first", relationship: "model_source" },
      { fingerprint: "second", relationship: "training_data" },
      { fingerprint: "third", provenance_token: "tok_abc" },
    ];
    const payloads = extractPayloads(
      mkRecord(), "t", 1, 30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, refs,
    );
    expect(payloads[0].references).toEqual(refs);
    expect(payloads[0].references).toHaveLength(3);
  });
});
