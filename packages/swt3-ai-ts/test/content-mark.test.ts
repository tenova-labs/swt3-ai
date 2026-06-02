/**
 * SWT3 AI Witness SDK -- AI-MARK.1 Content Provenance Tests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Witness } from "../src/witness.js";
import { CONTENT_TYPE_CODES } from "../src/types.js";

beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
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

describe("witnessContentMark (AI-MARK.1)", () => {
  it("mints correct procedure and factors for text with C2PA", () => {
    const w = mkWitness();
    const p = w.witnessContentMark({
      contentCount: 5,
      contentType: "text",
      markingMethod: "c2pa",
      hasMetadata: true,
    });
    expect(p.procedure_id).toBe("AI-MARK.1");
    expect(p.factor_a).toBe(5);
    expect(p.factor_b).toBe(1);
    expect(p.factor_c).toBe(0); // text
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps content type codes correctly", () => {
    const w = mkWitness();
    for (const [type, code] of Object.entries(CONTENT_TYPE_CODES)) {
      const p = w.witnessContentMark({
        contentCount: 1,
        contentType: type,
        markingMethod: "watermark",
        hasMetadata: false,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("sets factor_b=0 when no metadata attached", () => {
    const w = mkWitness();
    const p = w.witnessContentMark({
      contentCount: 1,
      contentType: "image",
      markingMethod: "watermark",
      hasMetadata: false,
    });
    expect(p.factor_b).toBe(0);
    expect(p.factor_c).toBe(1); // image
  });

  it("defaults unknown content type to 0", () => {
    const w = mkWitness();
    const p = w.witnessContentMark({
      contentCount: 1,
      contentType: "hologram",
      markingMethod: "manifest",
      hasMetadata: false,
    });
    expect(p.factor_c).toBe(0);
  });

  it("auto-hashes content string when contentHash not provided", () => {
    const w = mkWitness();
    const p = w.witnessContentMark({
      contentCount: 1,
      contentType: "text",
      markingMethod: "c2pa",
      hasMetadata: true,
      content: "Hello AI world",
    });
    expect(p.ai_context?.content_hash).toBeTruthy();
    expect(typeof p.ai_context?.content_hash).toBe("string");
  });

  it("uses provided contentHash over auto-hashing", () => {
    const w = mkWitness();
    const p = w.witnessContentMark({
      contentCount: 1,
      contentType: "text",
      markingMethod: "c2pa",
      hasMetadata: true,
      content: "ignored",
      contentHash: "abc123def456",
    });
    expect(p.ai_context?.content_hash).toBe("abc123def456");
  });

  it("includes standard and manifest_hash in ai_context", () => {
    const w = mkWitness();
    const p = w.witnessContentMark({
      contentCount: 1,
      contentType: "image",
      markingMethod: "c2pa",
      hasMetadata: true,
      manifestHash: "manifest_hash_value",
      standard: "C2PA-1.4",
    });
    expect(p.ai_context?.manifest_hash).toBe("manifest_hash_value");
    expect(p.ai_context?.standard).toBe("C2PA-1.4");
    expect(p.ai_context?.marking_method).toBe("c2pa");
  });

  it("strips ai_context at clearing_level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessContentMark({
      contentCount: 3,
      contentType: "video",
      markingMethod: "watermark",
      hasMetadata: true,
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(3);
    expect(p.factor_c).toBe(3); // video
  });
});
