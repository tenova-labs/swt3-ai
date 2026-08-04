import { describe, it, expect, vi } from "vitest";
import { handleGateEvaluate } from "../src/tools/gate.js";
import type { McpConfig } from "../src/config.js";
import type { AxiomClient } from "../src/client.js";

const mockConfig: McpConfig = {
  endpoint: "https://test.example.com",
  apiKey: "axm_live_test",
  tenantId: "TEST_ENCLAVE",
  clearingLevel: 1,
  demo: false,
};

const demoConfig: McpConfig = { ...mockConfig, demo: true };

function mockClient(): AxiomClient {
  return {} as unknown as AxiomClient;
}

const VALID_YAML = `
version: "1.0"
name: "Test Policy"
strict: false
models:
  gpt-4o:
    risk: "high"
frameworks:
  eu-ai-act:
    risk_class: "high-risk"
    gates:
      - group: "Article 9: Risk Management"
        procedures:
          - procedure: AI-GRD.1
            required: true
            max_age: 24h
            critical: true
            ref: "Art. 9(2)"
          - procedure: AI-INF.1
            required: true
            max_age: 7d
            ref: "Art. 9(4)"
defaults:
  gates:
    - procedure: AI-LOG.1
      required: true
      max_age: 7d
`;

describe("gate_evaluate tool", () => {
  it("validates valid YAML config offline", async () => {
    const result = await handleGateEvaluate(
      { gate_yaml: VALID_YAML },
      mockConfig,
      mockClient(),
    );

    expect(result).toContain("Gate Config: Test Policy");
    expect(result).toContain("Version: 1.0");
    expect(result).toContain("Strict: false");
    expect(result).toContain("eu-ai-act: 2 gates (1 critical)");
    expect(result).toContain("Config valid");
  });

  it("filters by framework", async () => {
    const multiFramework = `
version: "1.0"
frameworks:
  eu-ai-act:
    gates:
      - group: "Art 9"
        procedures:
          - procedure: AI-GRD.1
            required: true
  sr-11-7:
    gates:
      - group: "Section III"
        procedures:
          - procedure: AI-MDL.5
            required: true
`;
    const result = await handleGateEvaluate(
      { gate_yaml: multiFramework, framework: "sr-11-7" },
      mockConfig,
      mockClient(),
    );

    expect(result).toContain("sr-11-7: 1 gates");
    expect(result).not.toContain("eu-ai-act");
  });

  it("rejects invalid YAML", async () => {
    const result = await handleGateEvaluate(
      { gate_yaml: "{{{{invalid yaml" },
      mockConfig,
      mockClient(),
    );

    expect(result).toContain("Error:");
  });

  it("rejects missing version", async () => {
    const result = await handleGateEvaluate(
      { gate_yaml: "name: test\nframeworks: {}" },
      mockConfig,
      mockClient(),
    );

    expect(result).toContain("Error:");
    expect(result).toContain("version");
  });

  it("shows warnings for unknown procedures", async () => {
    const yaml = `
version: "1.0"
frameworks:
  test:
    gates:
      - group: "test"
        procedures:
          - procedure: AI-FAKE.99
            required: true
`;
    const result = await handleGateEvaluate(
      { gate_yaml: yaml },
      mockConfig,
      mockClient(),
    );

    expect(result).toContain("Warning:");
    expect(result).toContain("AI-FAKE.99");
  });

  it("shows models in report", async () => {
    const result = await handleGateEvaluate(
      { gate_yaml: VALID_YAML },
      mockConfig,
      mockClient(),
    );

    expect(result).toContain("gpt-4o (high)");
  });

  it("shows defaults count", async () => {
    const result = await handleGateEvaluate(
      { gate_yaml: VALID_YAML },
      mockConfig,
      mockClient(),
    );

    expect(result).toContain("+ 1 defaults");
  });

  it("returns demo message for live evaluation in demo mode", async () => {
    const result = await handleGateEvaluate(
      { gate_yaml: VALID_YAML, evaluate_live: true },
      demoConfig,
      mockClient(),
    );

    expect(result).toContain("Config valid");
    expect(result).toContain("Live evaluation requires a connected account");
  });
});
