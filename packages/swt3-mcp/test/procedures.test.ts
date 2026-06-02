import { describe, it, expect, vi } from "vitest";
import { handleProcedures } from "../src/tools/procedures.js";
import type { McpConfig } from "../src/config.js";
import type { AxiomClient } from "../src/client.js";

const mockConfig: McpConfig = {
  endpoint: "https://test.example.com",
  apiKey: "axm_live_test",
  tenantId: "TEST_ENCLAVE",
  clearingLevel: 1,
  demo: false,
};

const mockRegistry = {
  "AI-INF.1": {
    procedure_id: "AI-INF.1",
    title: "Inference Provenance",
    factors: {
      factor_a: { label: "required_hashes", description: "Always 1" },
      factor_b: { label: "hashes_present", description: "1 if both present" },
      factor_c: { label: "reserved", description: "Always 0" },
    },
  },
  "AI-MDL.1": {
    procedure_id: "AI-MDL.1",
    title: "Model Weight Integrity",
    factors: {
      factor_a: { label: "required", description: "Always 1" },
      factor_b: { label: "hash_present", description: "1 if model hash exists" },
      factor_c: { label: "reserved", description: "Always 0" },
    },
  },
  "AC-1.1": {
    procedure_id: "AC-1.1",
    title: "Access Control Policy Document",
    factors: {
      factor_a: { label: "max_policy_age_days" },
      factor_b: { label: "policy_age_days" },
      factor_c: { label: "difference" },
    },
  },
};

function mockClient(): AxiomClient {
  return {
    fetchRegistry: vi.fn().mockResolvedValue(mockRegistry),
  } as unknown as AxiomClient;
}

describe("list_procedures tool", () => {
  it("lists all procedures", async () => {
    const result = await handleProcedures({}, mockConfig, mockClient());
    expect(result).toContain("3 total");
    expect(result).toContain("AI-INF.1");
    expect(result).toContain("AI-MDL.1");
    expect(result).toContain("AC-1.1");
  });

  it("filters by AI namespace", async () => {
    const result = await handleProcedures({ namespace: "AI" }, mockConfig, mockClient());
    expect(result).toContain("2 found");
    expect(result).toContain("AI-INF.1");
    expect(result).toContain("AI-MDL.1");
    expect(result).not.toContain("AC-1.1");
  });

  it("filters by AC namespace", async () => {
    const result = await handleProcedures({ namespace: "AC" }, mockConfig, mockClient());
    expect(result).toContain("1 found");
    expect(result).toContain("AC-1.1");
    expect(result).not.toContain("AI-INF.1");
  });

  it("returns empty message for unknown namespace", async () => {
    const result = await handleProcedures({ namespace: "XYZ" }, mockConfig, mockClient());
    expect(result).toContain("No procedures found");
  });

  it("shows factor descriptions", async () => {
    const result = await handleProcedures({ namespace: "AI-INF" }, mockConfig, mockClient());
    expect(result).toContain("Factor A: required_hashes");
    expect(result).toContain("Factor B: hashes_present");
  });
});
