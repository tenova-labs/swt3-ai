import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { loadConfig } from "../src/config.js";

describe("loadConfig", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("loads valid config from env vars", () => {
    process.env.SWT3_API_KEY = "axm_live_test123";
    process.env.SWT3_TENANT_ID = "TEST_ENCLAVE";
    process.env.SWT3_ENDPOINT = "https://example.com/";
    process.env.SWT3_CLEARING_LEVEL = "2";
    process.env.SWT3_AGENT_ID = "agent-001";

    const bundle = loadConfig();
    expect(bundle.config.apiKey).toBe("axm_live_test123");
    expect(bundle.config.tenantId).toBe("TEST_ENCLAVE");
    expect(bundle.config.endpoint).toBe("https://example.com"); // trailing slash stripped
    expect(bundle.config.clearingLevel).toBe(2);
    expect(bundle.config.agentId).toBe("agent-001");
    expect(bundle.config.demo).toBe(false);
  });

  it("uses defaults for optional vars", () => {
    process.env.SWT3_API_KEY = "axm_live_test";
    process.env.SWT3_TENANT_ID = "MY_TENANT";

    const bundle = loadConfig();
    expect(bundle.config.endpoint).toBe("https://sovereign.tenova.io");
    expect(bundle.config.clearingLevel).toBe(1);
    expect(bundle.config.agentId).toBeUndefined();
    expect(bundle.config.signingKey).toBeUndefined();
    expect(bundle.config.demo).toBe(false);
  });

  it("enters demo mode with no env vars", () => {
    delete process.env.SWT3_API_KEY;
    delete process.env.SWT3_TENANT_ID;

    const bundle = loadConfig();
    expect(bundle.config.demo).toBe(true);
    expect(bundle.config.apiKey).toBe("axm_demo_local");
    expect(bundle.config.tenantId).toBe("DEMO_LOCAL");
  });

  it("auto-resolves tenant when only API key is set", () => {
    process.env.SWT3_API_KEY = "axm_live_test";
    delete process.env.SWT3_TENANT_ID;

    const bundle = loadConfig();
    expect(bundle.config.demo).toBe(false);
    expect(bundle.config.tenantId).toBe(""); // will be resolved from first API call
  });

  it("throws on invalid API key prefix", () => {
    process.env.SWT3_API_KEY = "sk_test_placeholder";
    process.env.SWT3_TENANT_ID = "MY_TENANT";
    expect(() => loadConfig()).toThrow("must start with 'axm_'");
  });

  it("throws on invalid clearing level", () => {
    process.env.SWT3_API_KEY = "axm_live_test";
    process.env.SWT3_TENANT_ID = "MY_TENANT";
    process.env.SWT3_CLEARING_LEVEL = "5";
    expect(() => loadConfig()).toThrow("must be 0, 1, 2, or 3");
  });
});
