import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { loadConfig } from "../src/config.js";

describe("chain-gate config integration", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("chainVerify defaults to false", () => {
    process.env.SWT3_API_KEY = "axm_test123";
    const { config } = loadConfig();
    expect(config.chainVerify).toBe(false);
  });

  it("chainVerify enabled via env var", () => {
    process.env.SWT3_API_KEY = "axm_test123";
    process.env.SWT3_CHAIN_VERIFY = "true";
    const { config } = loadConfig();
    expect(config.chainVerify).toBe(true);
  });

  it("chainVerify forced false in demo mode", () => {
    // No API key = demo mode
    delete process.env.SWT3_API_KEY;
    process.env.SWT3_CHAIN_VERIFY = "true";
    const { config } = loadConfig();
    expect(config.demo).toBe(true);
    expect(config.chainVerify).toBe(false);
  });

  it("redis config loads from env", () => {
    process.env.SWT3_API_KEY = "axm_test123";
    process.env.SWT3_REDIS_URL = "redis://custom:6380";
    process.env.SWT3_REDIS_STREAM = "custom:stream";
    process.env.SWT3_MAX_CHAIN_GAP = "120";
    const { config } = loadConfig();
    expect(config.redisUrl).toBe("redis://custom:6380");
    expect(config.redisStream).toBe("custom:stream");
    expect(config.maxChainGapSeconds).toBe(120);
  });

  it("redis config uses defaults when not set", () => {
    process.env.SWT3_API_KEY = "axm_test123";
    const { config } = loadConfig();
    expect(config.redisUrl).toBe("redis://localhost:6379");
    expect(config.redisStream).toBe("swt3:anchors");
    expect(config.maxChainGapSeconds).toBe(60);
  });
});
