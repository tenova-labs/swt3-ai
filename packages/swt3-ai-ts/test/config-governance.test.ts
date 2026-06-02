import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { loadFullConfig, loadConfig, computeConfigHash } from "../src/config.js";

const TMP = join(process.cwd(), ".test-config-tmp");
const YAML_PATH = join(TMP, "swt3.yaml");

function writeYaml(content: string): void {
  mkdirSync(TMP, { recursive: true });
  writeFileSync(YAML_PATH, content, "utf-8");
}

describe("Declarative Governance Config", () => {
  beforeEach(() => mkdirSync(TMP, { recursive: true }));
  afterEach(() => rmSync(TMP, { recursive: true, force: true }));

  // ── trust_mesh parsing ──────────────────────────────────────────────

  it("parses trust_mesh with all fields", () => {
    process.env.TEST_PARTNER_KEY = "secret123";
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  mode: strict
  min_trust_level: 3
  require_signature: true
  freshness_window: 7200
  trusted_tenants:
    - PARTNER_A
    - PARTNER_B
  trusted_agents:
    - tenant: PARTNER_A
      agent: bot-1
  deny_agents:
    - bad-bot
  deny_tenants:
    - EVIL_CORP
  required_procedures:
    - AI-INF.1
    - AI-GRD.1
  signing_keys:
    - agent: bot-1
      key_env: TEST_PARTNER_KEY
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.trustMesh).not.toBeNull();
    expect(loaded.trustMesh!.mode).toBe("strict");
    expect(loaded.trustMesh!.minTrustLevel).toBe(3);
    expect(loaded.trustMesh!.requireSignature).toBe(true);
    expect(loaded.trustMesh!.freshnessWindow).toBe(7200);
    expect(loaded.trustMesh!.trustedTenants).toEqual(["PARTNER_A", "PARTNER_B"]);
    expect(loaded.trustMesh!.trustedAgents).toEqual([{ tenant: "PARTNER_A", agent: "bot-1" }]);
    expect(loaded.trustMesh!.denyAgents).toEqual(["bad-bot"]);
    expect(loaded.trustMesh!.denyTenants).toEqual(["EVIL_CORP"]);
    expect(loaded.trustMesh!.requiredProcedures).toEqual(["AI-INF.1", "AI-GRD.1"]);
    expect(loaded.trustMesh!.signingKeys).toEqual([{ agent: "bot-1", key: "secret123" }]);
    delete process.env.TEST_PARTNER_KEY;
  });

  it("rejects unknown trust_mesh keys", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  mode: strict
  typo_field: true
`);
    expect(() => loadFullConfig(YAML_PATH)).toThrow("unknown key");
  });

  it("rejects invalid trust_mesh mode", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  mode: aggressive
`);
    expect(() => loadFullConfig(YAML_PATH)).toThrow("must be strict, permissive, or monitor");
  });

  it("throws when signing_keys env var is missing", () => {
    delete process.env.NONEXISTENT_KEY;
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  signing_keys:
    - agent: bot-1
      key_env: NONEXISTENT_KEY
`);
    expect(() => loadFullConfig(YAML_PATH)).toThrow("NONEXISTENT_KEY");
  });

  it("validates trusted_agents structure", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  trusted_agents:
    - tenant: PARTNER_A
`);
    expect(() => loadFullConfig(YAML_PATH)).toThrow("must have 'tenant' and 'agent' fields");
  });

  // ── hardware parsing ────────────────────────────────────────────────

  it("parses hardware section", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
hardware:
  require_attestation: true
  attestation_freshness: 1800
  allowed_methods:
    - tpm_2.0
    - secure_enclave
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.hardware).not.toBeNull();
    expect(loaded.hardware!.requireAttestation).toBe(true);
    expect(loaded.hardware!.attestationFreshness).toBe(1800);
    expect(loaded.hardware!.allowedMethods).toEqual(["tpm_2.0", "secure_enclave"]);
  });

  it("rejects unknown hardware keys", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
hardware:
  require_attestation: true
  bogus_field: 42
`);
    expect(() => loadFullConfig(YAML_PATH)).toThrow("unknown key");
  });

  // ── density_policy parsing ──────────────────────────────────────────

  it("parses density_policy section", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
density_policy:
  min_anchors_per_1000_tokens: 2
  required_providers:
    - vllm-native
  max_chain_gap_seconds: 30
  require_signing_key: true
  min_trust_level: 3
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.densityPolicy).not.toBeNull();
    expect(loaded.densityPolicy!.minAnchorsPerThousandTokens).toBe(2);
    expect(loaded.densityPolicy!.requiredProviders).toEqual(["vllm-native"]);
    expect(loaded.densityPolicy!.maxChainGapSeconds).toBe(30);
    expect(loaded.densityPolicy!.requireSigningKey).toBe(true);
    expect(loaded.densityPolicy!.minTrustLevel).toBe(3);
  });

  // ── profile loading ─────────────────────────────────────────────────

  it("loads profile and deep-merges user overrides", () => {
    writeYaml(`
profile: minimal
endpoint: https://example.com
api_key: axm_live_test
tenant_id: OVERRIDE_TENANT
clearing_level: 2
`);
    const loaded = loadFullConfig(YAML_PATH);
    // Profile sets clearing_level: 0, user overrides to 2
    expect(loaded.witnessOptions.clearingLevel).toBe(2);
    // Profile sets trust_mesh.mode: monitor
    expect(loaded.trustMesh).not.toBeNull();
    expect(loaded.trustMesh!.mode).toBe("monitor");
  });

  it("rejects unknown profile name", () => {
    writeYaml(`
profile: nonexistent-profile
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
`);
    expect(() => loadFullConfig(YAML_PATH)).toThrow("Unknown profile: 'nonexistent-profile'");
  });

  it("user config overrides profile arrays entirely", () => {
    writeYaml(`
profile: eu-ai-act-high-risk
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
agent_id: my-agent
jurisdiction: DE
signing_key: test-key-123
trust_mesh:
  required_procedures:
    - AI-INF.1
`);
    const loaded = loadFullConfig(YAML_PATH);
    // User specified only AI-INF.1, should NOT inherit profile's list
    expect(loaded.trustMesh!.requiredProcedures).toEqual(["AI-INF.1"]);
  });

  // ── config hash ─────────────────────────────────────────────────────

  it("produces deterministic config hash", () => {
    const content = "endpoint: https://example.com\napi_key: axm_live_test\ntenant_id: TEST\n";
    const hash1 = computeConfigHash(content);
    const hash2 = computeConfigHash(content);
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });

  it("config hash differs for different content", () => {
    const h1 = computeConfigHash("clearing_level: 1");
    const h2 = computeConfigHash("clearing_level: 2");
    expect(h1).not.toBe(h2);
  });

  it("configHash is present in loadFullConfig result", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.configHash).toHaveLength(64);
  });

  // ── backward compatibility ──────────────────────────────────────────

  it("loadConfig returns WitnessOptions without trust_mesh", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
trust_mesh:
  mode: strict
`);
    const opts = loadConfig(YAML_PATH) as Record<string, unknown>;
    // Should not have trustMesh, hardware, configHash
    expect(opts.trustMesh).toBeUndefined();
    expect(opts.configHash).toBeUndefined();
    // Should have normal witness fields
    expect(opts.endpoint).toBe("https://example.com");
    expect(opts.tenantId).toBe("TEST");
  });

  // ── mcp_policy ──────────────────────────────────────────────────────

  it("parses mcp_policy with all fields", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_test
tenant_id: TEST
mcp_policy:
  witnessed_tools: ["write_*", "search_*"]
  exempt_tools: ["list_files"]
  require_trust_level: 3
  auto_witness: true
  block_on_failure: true
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.mcpPolicy).not.toBeNull();
    expect(loaded.mcpPolicy!.witnessedTools).toEqual(["write_*", "search_*"]);
    expect(loaded.mcpPolicy!.exemptTools).toEqual(["list_files"]);
    expect(loaded.mcpPolicy!.requireTrustLevel).toBe(3);
    expect(loaded.mcpPolicy!.autoWitness).toBe(true);
    expect(loaded.mcpPolicy!.blockOnFailure).toBe(true);
  });

  it("rejects unknown mcp_policy keys", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_test
tenant_id: TEST
mcp_policy:
  witnessed_tools: ["*"]
  bogus_key: true
`);
    expect(() => loadFullConfig(YAML_PATH)).toThrow("unknown key");
  });

  it("defaults mcp_policy fields when omitted", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_test
tenant_id: TEST
mcp_policy:
  witnessed_tools: ["*"]
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.mcpPolicy!.exemptTools).toEqual([]);
    expect(loaded.mcpPolicy!.requireTrustLevel).toBe(0);
    expect(loaded.mcpPolicy!.autoWitness).toBe(true);
    expect(loaded.mcpPolicy!.blockOnFailure).toBe(false);
  });

  it("returns null mcpPolicy when section absent", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_test
tenant_id: TEST
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.mcpPolicy).toBeNull();
  });

  it("mcp_policy merges from profile", () => {
    writeYaml(`
profile: eu-ai-act-high-risk
api_key: axm_test
tenant_id: TEST
agent_id: test-agent
jurisdiction: DE
signing_key: test-key-123
mcp_policy:
  block_on_failure: false
`);
    const loaded = loadFullConfig(YAML_PATH);
    // Profile sets witnessed_tools: ["*"], user overrides block_on_failure
    expect(loaded.mcpPolicy!.witnessedTools).toEqual(["*"]);
    expect(loaded.mcpPolicy!.blockOnFailure).toBe(false);
  });

  // ── extends ─────────────────────────────────────────────────────────

  it("extends: single file", () => {
    const basePath = join(TMP, "base.yaml");
    writeFileSync(basePath, `
endpoint: https://base.example.com
api_key: axm_base
tenant_id: BASE
clearing_level: 2
`, "utf-8");
    writeYaml(`
extends: base.yaml
tenant_id: CHILD
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.witnessOptions.endpoint).toBe("https://base.example.com");
    expect(loaded.witnessOptions.tenantId).toBe("CHILD");
    expect(loaded.witnessOptions.clearingLevel).toBe(2);
  });

  it("extends: array of two files", () => {
    writeFileSync(join(TMP, "corp.yaml"), `
endpoint: https://corp.example.com
api_key: axm_corp
tenant_id: CORP
`, "utf-8");
    writeFileSync(join(TMP, "team.yaml"), `
clearing_level: 2
agent_id: team-agent
`, "utf-8");
    writeYaml(`
extends:
  - corp.yaml
  - team.yaml
tenant_id: PROJECT
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.witnessOptions.endpoint).toBe("https://corp.example.com");
    expect(loaded.witnessOptions.clearingLevel).toBe(2);
    expect(loaded.witnessOptions.tenantId).toBe("PROJECT");
  });

  it("extends: deep merges sections across chain", () => {
    writeFileSync(join(TMP, "parent.yaml"), `
endpoint: https://parent.example.com
api_key: axm_parent
tenant_id: PARENT
trust_mesh:
  mode: strict
  min_trust_level: 2
`, "utf-8");
    writeYaml(`
extends: parent.yaml
trust_mesh:
  min_trust_level: 3
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.trustMesh!.mode).toBe("strict");
    expect(loaded.trustMesh!.minTrustLevel).toBe(3);
  });

  it("extends: detects circular references", () => {
    writeFileSync(join(TMP, "a.yaml"), `
extends: b.yaml
api_key: axm_a
`, "utf-8");
    writeFileSync(join(TMP, "b.yaml"), `
extends: a.yaml
api_key: axm_b
`, "utf-8");
    const aPath = join(TMP, "a.yaml");
    expect(() => loadFullConfig(aPath)).toThrow("Circular extends detected");
  });

  it("extends: enforces depth limit", () => {
    // Create chain of 12 files (exceeds limit of 10)
    for (let i = 11; i >= 1; i--) {
      const content = i < 11
        ? `extends: chain${i + 1}.yaml\napi_key: axm_c${i}\n`
        : `api_key: axm_leaf\ntenant_id: LEAF\n`;
      writeFileSync(join(TMP, `chain${i}.yaml`), content, "utf-8");
    }
    writeYaml(`extends: chain1.yaml\ntenant_id: ROOT\n`);
    expect(() => loadFullConfig(YAML_PATH)).toThrow("Extends depth limit exceeded");
  });

  it("extends: resolves relative paths from config dir", () => {
    const subdir = join(TMP, "sub");
    mkdirSync(subdir, { recursive: true });
    writeFileSync(join(TMP, "shared.yaml"), `
endpoint: https://shared.example.com
api_key: axm_shared
tenant_id: SHARED
`, "utf-8");
    const childPath = join(subdir, "child.yaml");
    writeFileSync(childPath, `
extends: ../shared.yaml
tenant_id: CHILD_SUB
`, "utf-8");
    const loaded = loadFullConfig(childPath);
    expect(loaded.witnessOptions.endpoint).toBe("https://shared.example.com");
    expect(loaded.witnessOptions.tenantId).toBe("CHILD_SUB");
  });

  it("extends: works with absolute paths", () => {
    const absBase = join(TMP, "abs-base.yaml");
    writeFileSync(absBase, `
endpoint: https://abs.example.com
api_key: axm_abs
tenant_id: ABS
`, "utf-8");
    writeYaml(`
extends: ${absBase}
tenant_id: CHILD_ABS
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.witnessOptions.endpoint).toBe("https://abs.example.com");
    expect(loaded.witnessOptions.tenantId).toBe("CHILD_ABS");
  });

  it("extends: config hash includes all files", () => {
    writeFileSync(join(TMP, "hash-base.yaml"), `
endpoint: https://hash.example.com
api_key: axm_hash
tenant_id: HASH_BASE
`, "utf-8");
    writeYaml(`
extends: hash-base.yaml
tenant_id: HASH_CHILD
`);
    const loaded = loadFullConfig(YAML_PATH);
    // Hash without extends
    const soloYaml = join(TMP, "solo.yaml");
    writeFileSync(soloYaml, `
tenant_id: HASH_CHILD
api_key: axm_hash
endpoint: https://hash.example.com
`, "utf-8");
    const solo = loadFullConfig(soloYaml);
    // Hashes should differ because extends concatenates multiple file contents
    expect(loaded.configHash).not.toBe(solo.configHash);
    expect(loaded.configHash).toHaveLength(64);
  });

  // ── all sections optional ───────────────────────────────────────────

  it("works with bare minimum YAML (no sections)", () => {
    writeYaml(`
endpoint: https://example.com
api_key: axm_live_test
tenant_id: TEST
`);
    const loaded = loadFullConfig(YAML_PATH);
    expect(loaded.trustMesh).toBeNull();
    expect(loaded.hardware).toBeNull();
    expect(loaded.densityPolicy).toBeNull();
    expect(loaded.mcpPolicy).toBeNull();
    expect(loaded.witnessOptions.endpoint).toBe("https://example.com");
  });
});
