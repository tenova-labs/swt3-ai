import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { loadDensityPolicy, evaluatePolicy, type ChainAnchor, type DensityPolicy } from "../src/density-policy.js";

describe("density-policy", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("loadDensityPolicy", () => {
    it("returns defaults when no env vars set", () => {
      delete process.env.SWT3_DENSITY_POLICY;
      delete process.env.SWT3_DENSITY_POLICY_FILE;
      const policy = loadDensityPolicy();
      expect(policy.min_anchors_per_1000_tokens).toBe(1);
      expect(policy.required_providers).toEqual([]);
      expect(policy.max_chain_gap_seconds).toBe(60);
      expect(policy.require_signing_key).toBe(false);
      expect(policy.min_trust_level).toBe(1);
    });

    it("parses inline JSON from SWT3_DENSITY_POLICY", () => {
      process.env.SWT3_DENSITY_POLICY = JSON.stringify({
        min_anchors_per_1000_tokens: 2,
        required_providers: ["vllm-native"],
        max_chain_gap_seconds: 30,
      });
      const policy = loadDensityPolicy();
      expect(policy.min_anchors_per_1000_tokens).toBe(2);
      expect(policy.required_providers).toEqual(["vllm-native"]);
      expect(policy.max_chain_gap_seconds).toBe(30);
      expect(policy.require_signing_key).toBe(false); // default preserved
    });

    it("falls back to defaults on invalid JSON", () => {
      process.env.SWT3_DENSITY_POLICY = "not-json{";
      const policy = loadDensityPolicy();
      expect(policy.min_anchors_per_1000_tokens).toBe(1);
    });
  });

  describe("evaluatePolicy", () => {
    const now = Math.floor(Date.now() / 1000);

    function makeAnchors(count: number, gapSeconds = 10, provider = "openai"): ChainAnchor[] {
      return Array.from({ length: count }, (_, i) => ({
        anchor_epoch: now - (count - 1 - i) * gapSeconds,
        provider,
        payload_signature: "sig_abc123",
      }));
    }

    const permissive: DensityPolicy = {
      min_anchors_per_1000_tokens: 0,
      required_providers: [],
      max_chain_gap_seconds: 9999,
      require_signing_key: false,
      min_trust_level: 0,
    };

    it("passes with permissive policy", () => {
      const result = evaluatePolicy(permissive, makeAnchors(3));
      expect(result.compliant).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it("fails anchor density check", () => {
      const policy: DensityPolicy = { ...permissive, min_anchors_per_1000_tokens: 1 };
      // 5000 tokens but only 2 anchors (need 5)
      const result = evaluatePolicy(policy, makeAnchors(2), 5000);
      expect(result.compliant).toBe(false);
      expect(result.violations[0].rule).toBe("anchor_density");
    });

    it("passes anchor density check", () => {
      const policy: DensityPolicy = { ...permissive, min_anchors_per_1000_tokens: 1 };
      // 3000 tokens, 5 anchors (need 3)
      const result = evaluatePolicy(policy, makeAnchors(5), 3000);
      expect(result.compliant).toBe(true);
    });

    it("skips density check when no token count provided", () => {
      const policy: DensityPolicy = { ...permissive, min_anchors_per_1000_tokens: 10 };
      const result = evaluatePolicy(policy, makeAnchors(1));
      expect(result.compliant).toBe(true);
    });

    it("fails required provider check", () => {
      const policy: DensityPolicy = { ...permissive, required_providers: ["vllm-native", "nvidia-triton"] };
      const result = evaluatePolicy(policy, makeAnchors(3, 10, "openai"));
      expect(result.compliant).toBe(false);
      expect(result.violations).toHaveLength(2);
      expect(result.violations[0].rule).toBe("required_provider");
    });

    it("passes required provider check", () => {
      const policy: DensityPolicy = { ...permissive, required_providers: ["vllm-native"] };
      const anchors = makeAnchors(3, 10, "vllm-native");
      const result = evaluatePolicy(policy, anchors);
      expect(result.compliant).toBe(true);
    });

    it("fails chain gap check", () => {
      const policy: DensityPolicy = { ...permissive, max_chain_gap_seconds: 15 };
      // Gap of 100 seconds between anchors
      const anchors: ChainAnchor[] = [
        { anchor_epoch: now - 200 },
        { anchor_epoch: now - 100 }, // 100s gap -- exceeds 15s
        { anchor_epoch: now },
      ];
      const result = evaluatePolicy(policy, anchors);
      expect(result.compliant).toBe(false);
      expect(result.violations[0].rule).toBe("chain_gap");
    });

    it("passes chain gap check with tight anchors", () => {
      const policy: DensityPolicy = { ...permissive, max_chain_gap_seconds: 15 };
      const result = evaluatePolicy(policy, makeAnchors(5, 10));
      expect(result.compliant).toBe(true);
    });

    it("fails signing requirement", () => {
      const policy: DensityPolicy = { ...permissive, require_signing_key: true };
      const anchors: ChainAnchor[] = [
        { anchor_epoch: now, payload_signature: "sig" },
        { anchor_epoch: now + 5 }, // no signature
      ];
      const result = evaluatePolicy(policy, anchors);
      expect(result.compliant).toBe(false);
      expect(result.violations[0].rule).toBe("signing_required");
    });

    it("fails trust level check", () => {
      const policy: DensityPolicy = { ...permissive, min_trust_level: 3 };
      const result = evaluatePolicy(policy, makeAnchors(3), undefined, 2);
      expect(result.compliant).toBe(false);
      expect(result.violations[0].rule).toBe("trust_level");
    });

    it("accumulates multiple violations", () => {
      const policy: DensityPolicy = {
        min_anchors_per_1000_tokens: 5,
        required_providers: ["triton"],
        max_chain_gap_seconds: 1,
        require_signing_key: true,
        min_trust_level: 4,
      };
      const anchors: ChainAnchor[] = [
        { anchor_epoch: now - 100 },
        { anchor_epoch: now },
      ];
      const result = evaluatePolicy(policy, anchors, 10000, 1);
      expect(result.compliant).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(4);
    });
  });
});
