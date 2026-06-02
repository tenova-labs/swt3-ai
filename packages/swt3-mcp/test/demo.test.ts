import { describe, it, expect, vi } from "vitest";
import { handleWitness } from "../src/tools/witness.js";
import { handleSignup } from "../src/tools/signup.js";
import type { McpConfig } from "../src/config.js";
import type { AxiomClient } from "../src/client.js";

describe("demo mode", () => {
  const demoConfig: McpConfig = {
    endpoint: "https://sovereign.tenova.io",
    apiKey: "axm_demo_local",
    tenantId: "DEMO_LOCAL",
    clearingLevel: 1,
    demo: true,
  };

  it("mints local anchors without network calls", async () => {
    const client = {
      postWitness: vi.fn(),
    } as unknown as AxiomClient;

    const result = await handleWitness(
      { model_id: "gpt-4o", prompt: "Hello", response: "Hi" },
      { ...demoConfig },
      client,
    );

    expect(result).toContain("DEMO MODE");
    expect(result).toContain("Verdict: PASS");
    expect(result).toContain("SWT3-DEMO-LOCAL");
    expect(result).toContain("signup tool");
    // Should NOT have called the API
    expect(client.postWitness).not.toHaveBeenCalled();
  });

  it("demo anchor includes fingerprint", async () => {
    const client = {} as AxiomClient;
    const result = await handleWitness(
      { model_id: "claude-sonnet-4" },
      { ...demoConfig },
      client,
    );

    expect(result).toContain("Fingerprint:");
    const fpLine = result.split("\n").find((l: string) => l.startsWith("Fingerprint:"));
    const fp = fpLine?.split(": ")[1];
    expect(fp).toHaveLength(12);
  });
});

describe("signup tool", () => {
  it("returns a signup URL with framework parameter", async () => {
    const config: McpConfig = {
      endpoint: "https://sovereign.tenova.io",
      apiKey: "axm_demo_local",
      tenantId: "DEMO_LOCAL",
      clearingLevel: 1,
      demo: true,
    };

    const result = await handleSignup({ framework: "EU-AI-ACT" }, config);

    expect(result).toContain("https://sovereign.tenova.io/signup");
    expect(result).toContain("ref=mcp");
    expect(result).toContain("EU-AI-ACT");
    expect(result).toContain("SWT3_API_KEY");
    // No credentials should appear
    expect(result).not.toContain("password");
    expect(result).not.toContain("email");
  });

  it("uses default framework when none specified", async () => {
    const config: McpConfig = {
      endpoint: "https://sovereign.tenova.io",
      apiKey: "axm_demo_local",
      tenantId: "DEMO_LOCAL",
      clearingLevel: 1,
      demo: true,
    };

    const result = await handleSignup({}, config);

    expect(result).toContain("NIST-800-53");
  });
});
