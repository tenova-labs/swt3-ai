/**
 * Tests for AI-LIC.1 License Provenance Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { LICENSE_TYPE_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessLicenseProvenance (AI-LIC.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessLicenseProvenance({
      componentsChecked: 3, allCompliant: true, licenseType: "permissive",
    });
    expect(p.procedure_id).toBe("AI-LIC.1");
    expect(p.factor_a).toBe(3);
    expect(p.factor_b).toBe(1);
    expect(p.factor_c).toBe(0); // permissive
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all license type codes", () => {
    const w = mkWitness();
    for (const [licenseType, code] of Object.entries(LICENSE_TYPE_CODES)) {
      const p = w.witnessLicenseProvenance({
        componentsChecked: 1, allCompliant: true, licenseType,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("violation sets factor_b to zero", () => {
    const w = mkWitness();
    const p = w.witnessLicenseProvenance({
      componentsChecked: 2, allCompliant: false, licenseType: "copyleft",
    });
    expect(p.factor_b).toBe(0);
    expect(p.factor_c).toBe(1); // copyleft
  });

  it("unknown license type defaults to 5", () => {
    const w = mkWitness();
    const p = w.witnessLicenseProvenance({
      componentsChecked: 1, allCompliant: true, licenseType: "alien_license",
    });
    expect(p.factor_c).toBe(5);
  });

  it("openmdw code is 4", () => {
    const w = mkWitness();
    const p = w.witnessLicenseProvenance({
      componentsChecked: 1, allCompliant: true, licenseType: "openmdw",
    });
    expect(p.factor_c).toBe(4);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessLicenseProvenance({
      componentsChecked: 3, allCompliant: true, licenseType: "permissive",
      baseModelLicense: "Apache-2.0",
      adapterLicenses: ["CC-BY-4.0", "MIT"],
      spdxIds: ["Apache-2.0", "CC-BY-4.0", "MIT"],
      licenseHash: "abc123",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.provider).toBe("license-provenance");
    expect(p.ai_context!.license_type).toBe("permissive");
    expect(p.ai_context!.base_model_license).toBe("Apache-2.0");
    expect(p.ai_context!.adapter_licenses).toEqual(["CC-BY-4.0", "MIT"]);
    expect(p.ai_context!.spdx_ids).toEqual(["Apache-2.0", "CC-BY-4.0", "MIT"]);
    expect(p.ai_context!.license_hash).toBe("abc123");
    expect(p.ai_model_id).toBe("license-permissive");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessLicenseProvenance({
      componentsChecked: 3, allCompliant: true, licenseType: "openmdw",
      baseModelLicense: "OpenMDW-1.1",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(3);
    expect(p.factor_c).toBe(4); // openmdw
  });
});
