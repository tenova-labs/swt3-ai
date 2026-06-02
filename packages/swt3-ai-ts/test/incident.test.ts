/**
 * Tests for AI-INCIDENT.1 Incident Reporting Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { INCIDENT_TYPE_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessIncident (AI-INCIDENT.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessIncident({
      severityCode: 3, authorityNotified: true,
      incidentType: "safety",
    });
    expect(p.procedure_id).toBe("AI-INCIDENT.1");
    expect(p.factor_a).toBe(3);
    expect(p.factor_b).toBe(1); // true
    expect(p.factor_c).toBe(INCIDENT_TYPE_CODES["safety"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all incident type codes", () => {
    const w = mkWitness();
    for (const [type, code] of Object.entries(INCIDENT_TYPE_CODES)) {
      const p = w.witnessIncident({
        severityCode: 1, authorityNotified: false, incidentType: type,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 5", () => {
    const w = mkWitness();
    const p = w.witnessIncident({
      severityCode: 2, authorityNotified: false,
      incidentType: "unknown_incident_type",
    });
    expect(p.factor_c).toBe(5);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessIncident({
      severityCode: 3, authorityNotified: true,
      incidentType: "safety",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.incident_type).toBe("safety");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessIncident({
      severityCode: 3, authorityNotified: true,
      incidentType: "safety",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(3);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "incident-reporter-agent" });
    const p = w.witnessIncident({
      severityCode: 1, authorityNotified: false,
      incidentType: "safety",
    });
    expect(p.agent_id).toBe("incident-reporter-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessIncident({
      severityCode: 1, authorityNotified: false,
      incidentType: "safety",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
