/**
 * Tests for AI-AUDIT.1 Audit Log Integrity Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { LOG_FORMAT_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessAuditIntegrity (AI-AUDIT.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessAuditIntegrity({
      entriesChecked: 5000, integrityVerified: true,
      logFormat: "jsonl",
    });
    expect(p.procedure_id).toBe("AI-AUDIT.1");
    expect(p.factor_a).toBe(5000);
    expect(p.factor_b).toBe(1); // true
    expect(p.factor_c).toBe(LOG_FORMAT_CODES["jsonl"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all log format codes", () => {
    const w = mkWitness();
    for (const [format, code] of Object.entries(LOG_FORMAT_CODES)) {
      const p = w.witnessAuditIntegrity({
        entriesChecked: 100, integrityVerified: true, logFormat: format,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 3", () => {
    const w = mkWitness();
    const p = w.witnessAuditIntegrity({
      entriesChecked: 100, integrityVerified: true,
      logFormat: "unknown_format",
    });
    expect(p.factor_c).toBe(3);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessAuditIntegrity({
      entriesChecked: 5000, integrityVerified: true,
      logFormat: "jsonl",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.log_format).toBe("jsonl");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessAuditIntegrity({
      entriesChecked: 5000, integrityVerified: true,
      logFormat: "jsonl",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(5000);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "audit-integrity-agent" });
    const p = w.witnessAuditIntegrity({
      entriesChecked: 100, integrityVerified: false,
      logFormat: "jsonl",
    });
    expect(p.agent_id).toBe("audit-integrity-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessAuditIntegrity({
      entriesChecked: 1, integrityVerified: true,
      logFormat: "syslog",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
