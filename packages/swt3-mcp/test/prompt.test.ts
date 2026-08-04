import { describe, it, expect } from "vitest";
import { buildComplianceCheckPrompt } from "../src/prompts/compliance-check.js";

describe("compliance-check prompt", () => {
  it("generates prompt with framework procedures", () => {
    const result = buildComplianceCheckPrompt({
      framework: "EU-AI-ACT",
    });

    expect(result).toContain("EU Artificial Intelligence Act");
    expect(result).toContain("start_audit_session");
    expect(result).toContain("end_audit_session");
    expect(result).toContain("witness_inference");
    expect(result).toContain("Applicable Procedures");
    expect(result).toContain("Available Tools");
  });

  it("includes model_id when provided", () => {
    const result = buildComplianceCheckPrompt({
      framework: "NIST-AI-RMF",
      model_id: "claude-sonnet-4",
    });

    expect(result).toContain("claude-sonnet-4");
  });

  it("includes context when provided", () => {
    const result = buildComplianceCheckPrompt({
      framework: "EU-AI-ACT",
      context: "RAG-based medical triage system",
    });

    expect(result).toContain("RAG-based medical triage system");
    expect(result).toContain("witness_rag_context");
  });

  it("falls back to core procedures for unknown framework", () => {
    const result = buildComplianceCheckPrompt({
      framework: "UNKNOWN-FRAMEWORK-999",
    });

    expect(result).toContain("witness_inference");
    expect(result).toContain("AI-INF.1");
    expect(result).toContain("Available Tools");
  });

  it("handles case-insensitive framework IDs", () => {
    const result = buildComplianceCheckPrompt({
      framework: "eu-ai-act",
    });

    expect(result).toContain("Applicable Procedures");
  });

  it("includes coverage_report guidance", () => {
    const result = buildComplianceCheckPrompt({
      framework: "SR-11-7",
    });

    expect(result).toContain("coverage_report");
    expect(result).toContain("gap report");
  });
});
