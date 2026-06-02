import { describe, it, expect, vi } from "vitest";
import { handleVerify } from "../src/tools/verify.js";
import type { McpConfig } from "../src/config.js";
import type { AxiomClient } from "../src/client.js";

const mockConfig: McpConfig = {
  endpoint: "https://test.example.com",
  apiKey: "axm_live_test",
  tenantId: "TEST_ENCLAVE",
  clearingLevel: 1,
  demo: false,
};

describe("verify_anchor tool", () => {
  it("returns verified result for valid anchor", async () => {
    const client = {
      verifyAnchor: vi.fn().mockResolvedValue({
        verified: true,
        status: "ANCHOR VERIFIED — Evidence integrity confirmed",
        claimed_fingerprint: "96b7d56c0245",
        recomputed_fingerprint: "96b7d56c0245",
        inputs: { procedure_id: "AI-INF.1", tenant_id: "TEST_ENCLAVE" },
      }),
    } as unknown as AxiomClient;

    const result = await handleVerify(
      { token: "SWT3-E-TEST-AI-AIINF1-PASS-1700000000-96b7d56c0245" },
      mockConfig,
      client,
    );

    expect(result).toContain("Verified: YES");
    expect(result).toContain("Evidence integrity confirmed");
    expect(result).toContain("96b7d56c0245");
  });

  it("returns not verified for tampered anchor", async () => {
    const client = {
      verifyAnchor: vi.fn().mockResolvedValue({
        verified: false,
        status: "ANCHOR TAMPERED — Fingerprint mismatch",
        claimed_fingerprint: "000000000000",
        recomputed_fingerprint: "96b7d56c0245",
      }),
    } as unknown as AxiomClient;

    const result = await handleVerify(
      { token: "SWT3-E-TEST-AI-AIINF1-PASS-1700000000-000000000000" },
      mockConfig,
      client,
    );

    expect(result).toContain("Verified: NO");
    expect(result).toContain("TAMPERED");
  });

  it("rejects tokens without SWT3- prefix", async () => {
    const client = {} as AxiomClient;
    const result = await handleVerify(
      { token: "INVALID-TOKEN" },
      mockConfig,
      client,
    );

    expect(result).toContain("Error: Token must start with 'SWT3-'");
  });
});
