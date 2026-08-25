/**
 * AI-PROV.1 Model Provenance Chain tests.
 *
 * Tests the witnessModelProvenance method and verifies fingerprint parity
 * with Python SDK test vectors. Also tests parentModelFingerprint on MDL.5-7.
 */
import { describe, it, expect } from "vitest";
import { Witness } from "../src/witness.js";
import { mintFingerprint } from "../src/fingerprint.js";
import vectors from "./test-vectors.json" with { type: "json" };

const BASE_CONFIG = {
  endpoint: "http://localhost",
  apiKey: "axm_test_key",
  tenantId: "ENCLAVE_PROD",
  clearingLevel: 1 as const,
  bufferSize: 100,
  flushInterval: 999,
  timeout: 1000,
  maxRetries: 0,
  latencyThresholdMs: 5000,
  guardrailsRequired: 0,
  guardrailNames: [],
};

describe("AI-PROV.1 Fingerprint Parity", () => {
  const provVectors = vectors.fingerprint_vectors.filter(
    (v: any) => v.procedure_id === "AI-PROV.1",
  );

  it("has AI-PROV.1 test vectors", () => {
    expect(provVectors.length).toBeGreaterThanOrEqual(2);
  });

  for (const vec of provVectors) {
    it(`vector ${vec.id}: ${vec.description}`, () => {
      const fp = mintFingerprint(
        vec.tenant_id, vec.procedure_id,
        vec.factor_a, vec.factor_b, vec.factor_c,
        vec.fingerprint_timestamp_ms,
      );
      expect(fp).toBe(vec.expected_fingerprint);
    });
  }
});

describe("AI-PROV.1 witnessModelProvenance", () => {
  it("mints AI-PROV.1 anchor with correct factors", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessModelProvenance({
      chainLength: 4,
      integrityVerified: true,
      linkType: "training",
    });
    expect(p.procedure_id).toBe("AI-PROV.1");
    expect(p.factor_a).toBe(4);
    expect(p.factor_b).toBe(1);
    expect(p.factor_c).toBe(0); // training
  });

  it("maps link type codes correctly", () => {
    const w = new Witness(BASE_CONFIG);
    const p1 = w.witnessModelProvenance({ chainLength: 1, integrityVerified: true, linkType: "fine_tuning" });
    expect(p1.factor_c).toBe(1);
    const p2 = w.witnessModelProvenance({ chainLength: 1, integrityVerified: true, linkType: "deployment" });
    expect(p2.factor_c).toBe(2);
    const p3 = w.witnessModelProvenance({ chainLength: 1, integrityVerified: true, linkType: "distillation" });
    expect(p3.factor_c).toBe(3);
  });

  it("sets factor_b=0 when integrity not verified", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessModelProvenance({
      chainLength: 3,
      integrityVerified: false,
      linkType: "deployment",
    });
    expect(p.factor_b).toBe(0);
  });

  it("includes context with parent model fingerprint at CL1", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessModelProvenance({
      chainLength: 4,
      integrityVerified: true,
      linkType: "fine_tuning",
      parentModelFingerprint: "abc123def456",
      modelId: "llama-3.1-70b-ft",
    });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.provider).toBe("model-provenance");
    expect(p.ai_context!.parent_model_fingerprint).toBe("abc123def456");
    expect(p.ai_context!.chain_length).toBe(4);
    expect(p.ai_model_id).toBe("llama-3.1-70b-ft");
  });

  it("strips context at clearing level 2", () => {
    const w = new Witness({ ...BASE_CONFIG, clearingLevel: 2 });
    const p = w.witnessModelProvenance({
      chainLength: 2,
      integrityVerified: true,
      linkType: "training",
    });
    expect(p.ai_context).toBeUndefined();
  });

  it("accepts governanceMetadata", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessModelProvenance({
      chainLength: 1,
      integrityVerified: true,
      linkType: "training",
      governanceMetadata: { audit_id: "AUD-2026-007" },
    });
    expect(p.ai_context!.audit_id).toBe("AUD-2026-007");
  });

  it("exposes PROVENANCE_LINK_TYPE_CODES static map", () => {
    expect(Witness.PROVENANCE_LINK_TYPE_CODES.training).toBe(0);
    expect(Witness.PROVENANCE_LINK_TYPE_CODES.distillation).toBe(3);
  });
});

describe("parentModelFingerprint on MDL.5-7", () => {
  it("MDL.5: includes parent_model_fingerprint in context", () => {
    const w = new Witness(BASE_CONFIG);
    const info = { fileHash: "abcdef123456", filePath: "/model.bin", fileSizeBytes: 1024, format: "safetensors" };
    const p = w.witnessModelWeights(info, { parentModelFingerprint: "parent_fp_123" });
    expect(p.ai_context!.parent_model_fingerprint).toBe("parent_fp_123");
  });

  it("MDL.6: includes parent_model_fingerprint in context", () => {
    const w = new Witness(BASE_CONFIG);
    const adapters = [{ name: "lora-v1", adapterHash: "hash123", baseModel: "llama-3" }];
    const p = w.witnessAdapterStack(adapters, "llama-3", { parentModelFingerprint: "parent_fp_456" });
    expect((p.ai_context as any).parent_model_fingerprint).toBe("parent_fp_456");
  });

  it("MDL.7: includes parent_model_fingerprint in context", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessQuantization("int8", { bits: 8, parentModelFingerprint: "parent_fp_789" });
    expect(p.ai_context!.parent_model_fingerprint).toBe("parent_fp_789");
  });
});
