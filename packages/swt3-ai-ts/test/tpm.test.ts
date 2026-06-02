/**
 * TPM 2.0 Attestation Tests (AI-HW.3).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { parseTPMPcrOutput, ZERO_PCR_HASH } from "../src/hardware.js";
import type { TPMSnapshot, PcrRegister } from "../src/hardware.js";
import { sha256Truncated } from "../src/fingerprint.js";
import { Witness } from "../src/witness.js";

// ── Helpers ──────────────────────────────────────────────────────────

const RAW_PCR_0 = "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969";
const RAW_PCR_7 = "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c";
const ZERO_PCR_RAW = "0".repeat(64);

const MOCK_PCRREAD_OUTPUT = `sha256:
  0 : 0x${RAW_PCR_0}
  7 : 0x${RAW_PCR_7}
`;

const MOCK_PCRREAD_8_REGS = `sha256:
  0 : 0x${RAW_PCR_0}
  1 : 0x${RAW_PCR_7}
  2 : 0x${RAW_PCR_0}
  3 : 0x${RAW_PCR_7}
  4 : 0x${RAW_PCR_0}
  5 : 0x${RAW_PCR_7}
  6 : 0x${RAW_PCR_0}
  7 : 0x${RAW_PCR_7}
`;

const MOCK_PCRREAD_WITH_ZERO = `sha256:
  0 : 0x${RAW_PCR_0}
  7 : 0x${ZERO_PCR_RAW}
`;

function mkTPMSnapshot(pcrCount: number, includeZero = false): TPMSnapshot {
  const pcrs: PcrRegister[] = Array.from({ length: pcrCount }, (_, i) => ({
    index: i,
    bank: "sha256",
    digestHash: includeZero && i === pcrCount - 1
      ? ZERO_PCR_HASH
      : `pcrhash${i}`,
  }));
  return {
    available: pcrCount > 0,
    manufacturer: "mfghash",
    firmwareVersion: "fwhash",
    pcrs,
    endorsementKeyHash: "ekhash",
    hostnameHash: "hosthash",
  };
}

// ── parseTPMPcrOutput ─────────────────────────────────────────────────

describe("parseTPMPcrOutput", () => {
  it("parses standard tpm2_pcrread output", () => {
    const pcrs = parseTPMPcrOutput(MOCK_PCRREAD_OUTPUT);
    expect(pcrs).toHaveLength(2);
    expect(pcrs[0].index).toBe(0);
    expect(pcrs[0].bank).toBe("sha256");
    expect(pcrs[1].index).toBe(7);
  });

  it("hashes raw PCR values (never stores cleartext)", () => {
    const pcrs = parseTPMPcrOutput(MOCK_PCRREAD_OUTPUT);
    // Raw value must NOT appear in output
    expect(pcrs[0].digestHash).not.toBe(RAW_PCR_0);
    // Must be the SHA-256 truncated hash of the raw value
    expect(pcrs[0].digestHash).toBe(sha256Truncated(RAW_PCR_0));
    expect(pcrs[1].digestHash).toBe(sha256Truncated(RAW_PCR_7));
  });

  it("parses all 8 registers", () => {
    const pcrs = parseTPMPcrOutput(MOCK_PCRREAD_8_REGS);
    expect(pcrs).toHaveLength(8);
    expect(pcrs[0].index).toBe(0);
    expect(pcrs[7].index).toBe(7);
  });

  it("returns empty array for empty input", () => {
    expect(parseTPMPcrOutput("")).toHaveLength(0);
  });

  it("handles malformed lines gracefully", () => {
    const output = `sha256:
  0 : 0x${RAW_PCR_0}
  garbage line
  not_a_pcr
  7 : 0x${RAW_PCR_7}
`;
    const pcrs = parseTPMPcrOutput(output);
    expect(pcrs).toHaveLength(2);
  });
});

// ── ZERO_PCR_HASH ─────────────────────────────────────────────────────

describe("ZERO_PCR_HASH", () => {
  it("is the hash of 64 hex zeros", () => {
    expect(ZERO_PCR_HASH).toBe(sha256Truncated("0".repeat(64)));
  });

  it("differs from a real PCR hash", () => {
    expect(ZERO_PCR_HASH).not.toBe(sha256Truncated(RAW_PCR_0));
  });
});

// ── witnessTPMAttestation ────────────────────────────────────────────

describe("witnessTPMAttestation", () => {

  it("mints AI-HW.3 anchor with correct procedure_id", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(8) });
    expect(p.procedure_id).toBe("AI-HW.3");
  });

  it("factor_a = PCR count", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(8) });
    expect(p.factor_a).toBe(8);
  });

  it("factor_b = 1 when all PCRs non-zero", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(8) });
    expect(p.factor_b).toBe(1);
  });

  it("factor_b = 0 when a PCR is zero-valued", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(2, true) });
    expect(p.factor_b).toBe(0);
  });

  it("factor_b = 0 when no TPM available", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(0) });
    expect(p.factor_a).toBe(0);
    expect(p.factor_b).toBe(0);
  });

  it("factor_c = 0 (reserved)", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(8) });
    expect(p.factor_c).toBe(0);
  });

  it("clearing level 0 includes PCR context", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(2) });
    expect(p.ai_context).toBeDefined();
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.provider).toBe("tpm-2.0");
    expect(ctx.pcr_count).toBe(2);
    expect(ctx.all_non_zero).toBe(true);
    expect(ctx.manufacturer_hash).toBe("mfghash");
    expect(Array.isArray(ctx.pcrs)).toBe(true);
  });

  it("clearing level 1 includes context", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 1, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(2) });
    expect(p.ai_context).toBeDefined();
  });

  it("clearing level 2 strips context", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 2, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(8) });
    expect(p.ai_context).toBeUndefined();
  });

  it("clearing level 3 strips context", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 3, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(8) });
    expect(p.ai_context).toBeUndefined();
  });

  it("payload has valid fingerprint", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(8) });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });

  it("agent_id survives", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", agentId: "agent-x", clearingLevel: 0, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(2) });
    expect(p.agent_id).toBe("agent-x");
  });

  it("payload enqueued to buffer", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, flushInterval: 999999 });
    const p = w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(2) });
    expect(w.pending).toBeGreaterThanOrEqual(1);
  });
});

// ── Trust level integration ──────────────────────────────────────────

describe("trust credential with TPM", () => {

  it("AI-HW.3 alone sets hasHardwareAttestation=true", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, signingKey: "sk", flushInterval: 999999 });
    w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(8) });
    const cred = w.presentCredential();
    expect(cred.hasHardwareAttestation).toBe(true);
  });

  it("AI-HW.1 alone still sets hasHardwareAttestation=true", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, signingKey: "sk", flushInterval: 999999 });
    w.witnessHardware({
      snapshot: {
        gpus: [{ name: "H100", memoryMb: 80000, busIdHash: "b", uuidHash: "u" }],
        driverVersion: "535", cudaVersion: "", topology: "single",
        interconnect: "pcie", totalMemoryMb: 80000, hostnameHash: "h",
      },
    });
    const cred = w.presentCredential();
    expect(cred.hasHardwareAttestation).toBe(true);
  });

  it("both AI-HW.1 and AI-HW.3 sets hasHardwareAttestation=true", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, signingKey: "sk", flushInterval: 999999 });
    w.witnessHardware({
      snapshot: {
        gpus: [{ name: "H100", memoryMb: 80000, busIdHash: "b", uuidHash: "u" }],
        driverVersion: "535", cudaVersion: "", topology: "single",
        interconnect: "pcie", totalMemoryMb: 80000, hostnameHash: "h",
      },
    });
    w.witnessTPMAttestation({ snapshot: mkTPMSnapshot(8) });
    const cred = w.presentCredential();
    expect(cred.hasHardwareAttestation).toBe(true);
    expect(cred.procedures).toContain("AI-HW.1");
    expect(cred.procedures).toContain("AI-HW.3");
  });

  it("neither HW procedure = hasHardwareAttestation=false", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, signingKey: "sk", flushInterval: 999999 });
    const cred = w.presentCredential();
    expect(cred.hasHardwareAttestation).toBe(false);
  });
});

// ── Security invariant ──────────────────────────────────────────────

describe("security: raw PCR values never in payload", () => {
  it("raw PCR hex never appears in context", () => {
    const w = new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "t1", clearingLevel: 0, flushInterval: 999999 });

    const snapshot: TPMSnapshot = {
      available: true,
      manufacturer: sha256Truncated("INTC"),
      firmwareVersion: sha256Truncated("7.2.0"),
      pcrs: [
        { index: 0, bank: "sha256", digestHash: sha256Truncated(RAW_PCR_0) },
        { index: 7, bank: "sha256", digestHash: sha256Truncated(RAW_PCR_7) },
      ],
      endorsementKeyHash: sha256Truncated("ek-pub-key-data"),
      hostnameHash: sha256Truncated("myhost"),
    };

    const p = w.witnessTPMAttestation({ snapshot });
    const json = JSON.stringify(p);

    // Raw values must NEVER appear
    expect(json).not.toContain(RAW_PCR_0);
    expect(json).not.toContain(RAW_PCR_7);
    expect(json).not.toContain("INTC");
    expect(json).not.toContain("ek-pub-key-data");
    expect(json).not.toContain("myhost");
  });
});
