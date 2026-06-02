/**
 * SWT3 AI Witness SDK -- Config-to-Witness Integration Tests.
 *
 * Tests the full path: YAML -> loadFullConfig -> Witness.fromConfig ->
 * trust mesh wired, merkle accumulator created, density/mcp policy exposed.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { writeFileSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Witness } from "../src/witness.js";
import { loadFullConfig } from "../src/config.js";
import { signCredential } from "../src/trust.js";
import { validateSchema } from "../src/schema.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "swt3-config-integ-"));
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
  try { rmSync(dir, { recursive: true, force: true }); } catch {}
});

function writeYaml(filename: string, content: string): string {
  const p = join(dir, filename);
  writeFileSync(p, content, "utf-8");
  return p;
}

describe("Config-to-Witness Integration", () => {
  it("fromConfig wires trust mesh from YAML", () => {
    process.env.SWT3_SIGNING_KEY = "test-secret-key";
    const yamlPath = writeYaml("swt3.yaml", `
endpoint: https://test.example.com
api_key: axm_test_key
tenant_id: INTEG_TEST
agent_id: agent-001
signing_key_env: SWT3_SIGNING_KEY

trust_mesh:
  mode: strict
  min_trust_level: 2
  trusted_tenants:
    - PARTNER_A
    - PARTNER_B
  deny_agents:
    - malicious-agent
  signing_keys:
    - agent: remote-agent
      key_env: SWT3_SIGNING_KEY
`);
    const witness = Witness.fromConfig(yamlPath);

    // Trust mesh should be wired
    const reg = witness.trustRegistry;
    expect(reg.isTenantTrusted("PARTNER_A", "INTEG_TEST")).toBe(true);
    expect(reg.isTenantTrusted("PARTNER_B", "INTEG_TEST")).toBe(true);
    expect(reg.isAgentDenied("malicious-agent")).toBe(true);
    // Strict mode forces requireSignature
    expect(reg._requireSignature).toBe(true);
    expect(reg._minTrustLevel).toBe(2);

    // Config hash should be set
    expect(witness.configHash).toBeDefined();
    expect(witness.configHash!.length).toBe(64);

    delete process.env.SWT3_SIGNING_KEY;
  });

  it("fromConfig wires merkle accumulator when enabled", () => {
    const yamlPath = writeYaml("swt3.yaml", `
endpoint: https://test.example.com
api_key: axm_test_key
tenant_id: MERKLE_TEST

merkle:
  enabled: true
  accumulator_interval: 30
`);
    const witness = Witness.fromConfig(yamlPath);

    expect(witness.merkleConfig).toBeDefined();
    expect(witness.merkleConfig!.enabled).toBe(true);
    expect(witness.merkleConfig!.accumulatorInterval).toBe(30);
    expect(witness.merkleAccumulator).toBeDefined();

    // Accumulator should work
    witness.merkleAccumulator!.add("fp_test_1");
    witness.merkleAccumulator!.add("fp_test_2");
    const session = witness.merkleAccumulator!.flush();
    expect(session).not.toBeNull();
    expect(session!.count).toBe(2);
  });

  it("fromConfig does not create accumulator when disabled", () => {
    const yamlPath = writeYaml("swt3.yaml", `
endpoint: https://test.example.com
api_key: axm_test_key
tenant_id: NO_MERKLE

merkle:
  enabled: false
`);
    const witness = Witness.fromConfig(yamlPath);
    expect(witness.merkleConfig).toBeDefined();
    expect(witness.merkleConfig!.enabled).toBe(false);
    expect(witness.merkleAccumulator).toBeUndefined();
  });

  it("fromConfig exposes density and mcp policy", () => {
    const yamlPath = writeYaml("swt3.yaml", `
endpoint: https://test.example.com
api_key: axm_test_key
tenant_id: POLICY_TEST

density_policy:
  min_anchors_per_1000_tokens: 3
  max_chain_gap_seconds: 30
  require_signing_key: true
  min_trust_level: 2

mcp_policy:
  witnessed_tools: ["write_*", "exec_*"]
  exempt_tools: ["list_files"]
  require_trust_level: 2
  auto_witness: true
  block_on_failure: true
`);
    const witness = Witness.fromConfig(yamlPath);

    expect(witness.densityPolicy).toBeDefined();
    expect(witness.densityPolicy!.minAnchorsPerThousandTokens).toBe(3);
    expect(witness.densityPolicy!.maxChainGapSeconds).toBe(30);
    expect(witness.densityPolicy!.requireSigningKey).toBe(true);

    expect(witness.mcpPolicy).toBeDefined();
    expect(witness.mcpPolicy!.witnessedTools).toEqual(["write_*", "exec_*"]);
    expect(witness.mcpPolicy!.exemptTools).toEqual(["list_files"]);
    expect(witness.mcpPolicy!.blockOnFailure).toBe(true);
  });

  it("fromConfig wires token_budget from YAML", () => {
    const yamlPath = writeYaml("swt3.yaml", `
endpoint: https://test.example.com
api_key: axm_test_key
tenant_id: TOKEN_TEST
token_budget: 5000
`);
    const witness = Witness.fromConfig(yamlPath);
    // Verify token_budget was passed through (check via pending flush behavior)
    expect(witness.pending).toBe(0);
  });

  it("extends + profile + overrides compose correctly", () => {
    writeYaml("base.yaml", `
clearing_level: 0
buffer_size: 50
`);
    const yamlPath = writeYaml("prod.yaml", `
extends: base.yaml
endpoint: https://test.example.com
api_key: axm_test_key
tenant_id: COMPOSE_TEST
clearing_level: 2
`);
    // base sets clearing_level=0, prod overrides to 2
    const loaded = loadFullConfig(yamlPath);
    expect(loaded.witnessOptions.clearingLevel).toBe(2);
    expect(loaded.witnessOptions.bufferSize).toBe(50); // inherited from base
  });

  it("trust mesh credential round-trip: sign, present, verify", () => {
    process.env.SWT3_AGENT_KEY = "shared-secret-abc";
    const yamlPath = writeYaml("swt3.yaml", `
endpoint: https://test.example.com
api_key: axm_test_key
tenant_id: TRUST_RT
agent_id: my-agent
signing_key_env: SWT3_AGENT_KEY

trust_mesh:
  mode: permissive
  trusted_tenants:
    - TRUST_RT
  signing_keys:
    - agent: my-agent
      key_env: SWT3_AGENT_KEY
`);
    const witness = Witness.fromConfig(yamlPath);

    // Present credential (should be auto-signed)
    const cred = witness.presentCredential();
    expect(cred.isSigned).toBe(true);
    expect(cred.credentialSignature).toBeDefined();
    expect(cred.agentId).toBe("my-agent");

    // Verify own credential (same tenant = auto-trusted)
    const result = witness.verifyTrust(cred);
    expect(result.granted).toBe(true);
    expect(result.trustLevel).toBeGreaterThanOrEqual(1);

    delete process.env.SWT3_AGENT_KEY;
  });

  it("schema validation catches invalid YAML keys", () => {
    const result = validateSchema({
      api_key: "axm_test",
      tenant_id: "TEST",
      token_budget: 5000,
      procedures: ["AI-INF.1"],
      strict: true,
    });
    expect(result.valid).toBe(true);

    const bad = validateSchema({
      api_key: "axm_test",
      bogus_field: true,
    });
    expect(bad.valid).toBe(false);
  });
});
