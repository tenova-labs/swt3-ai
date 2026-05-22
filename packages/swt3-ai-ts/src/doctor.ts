/**
 * SWT3 Doctor -- diagnostic checks for config health.
 */

import { existsSync, readFileSync, realpathSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { execSync } from "node:child_process";
import { resolve, dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { validateSchema } from "./schema.js";

export interface DoctorCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
  tip?: string;
}

function findConfigPath(): string | null {
  for (const name of ["swt3.yaml", ".swt3.yaml"]) {
    if (existsSync(name)) return name;
  }
  return null;
}

function checkYamlFound(): DoctorCheck {
  const path = findConfigPath();
  if (path) {
    return { name: "Config file", status: "pass", message: `./${path}` };
  }
  return {
    name: "Config file",
    status: "fail",
    message: "not found",
    tip: "Run: swt3 init",
  };
}

function checkYamlValid(path: string): DoctorCheck {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yaml = require("yaml");
    const content = readFileSync(path, "utf-8");
    const raw = yaml.parse(content);
    if (!raw || typeof raw !== "object") {
      return { name: "YAML syntax", status: "fail", message: "not a valid YAML mapping" };
    }
    return { name: "YAML syntax", status: "pass", message: "valid" };
  } catch (err) {
    return { name: "YAML syntax", status: "fail", message: (err as Error).message };
  }
}

function checkEnvVars(path: string): DoctorCheck {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yaml = require("yaml");
    const raw = yaml.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
    const missing: string[] = [];

    if (raw.api_key_env) {
      const varName = raw.api_key_env as string;
      if (!process.env[varName]) missing.push(varName);
    }
    if (raw.signing_key_env) {
      const varName = raw.signing_key_env as string;
      if (!process.env[varName]) missing.push(varName);
    }

    if (missing.length === 0 && !raw.api_key_env && !raw.api_key) {
      return { name: "Environment", status: "warn", message: "no api_key or api_key_env configured" };
    }
    if (missing.length > 0) {
      return {
        name: "Environment",
        status: "warn",
        message: `${missing.join(", ")} not set (local mode only)`,
        tip: `export ${missing[0]}=axm_... (get a free key at https://sovereign.tenova.io/signup)`,
      };
    }
    return { name: "Environment", status: "pass", message: "all env vars resolved" };
  } catch {
    return { name: "Environment", status: "warn", message: "could not parse config" };
  }
}

function checkProfile(path: string): DoctorCheck {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yaml = require("yaml");
    const raw = yaml.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
    const profile = raw.profile as string | undefined;
    if (!profile) {
      return { name: "Profile", status: "pass", message: "none (custom config)" };
    }
    const valid = ["eu-ai-act-high-risk", "nist-ai-rmf", "minimal"];
    if (valid.includes(profile)) {
      return { name: "Profile", status: "pass", message: profile };
    }
    return { name: "Profile", status: "fail", message: `unknown: ${profile}` };
  } catch {
    return { name: "Profile", status: "warn", message: "could not parse" };
  }
}

function checkSections(path: string): DoctorCheck {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yaml = require("yaml");
    const raw = yaml.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
    const result = validateSchema(raw);
    if (result.valid) {
      const sections = ["policy", "trust_mesh", "hardware", "density_policy", "mcp_policy", "merkle"]
        .filter((s) => s in raw);
      return {
        name: "Sections",
        status: "pass",
        message: sections.length > 0 ? sections.join(", ") : "none configured",
      };
    }
    const first = result.errors[0];
    return {
      name: "Sections",
      status: "fail",
      message: `${first.path}: ${first.message}`,
    };
  } catch {
    return { name: "Sections", status: "warn", message: "could not validate" };
  }
}

function checkExtends(path: string): DoctorCheck {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yaml = require("yaml");
    const raw = yaml.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
    const ext = raw.extends as string | string[] | undefined;
    if (!ext) {
      return { name: "Extends", status: "pass", message: "none" };
    }
    const files = Array.isArray(ext) ? ext : [ext];
    const configDir = dirname(resolve(path));
    const missing: string[] = [];
    for (const f of files) {
      const resolved = f.startsWith("/") ? f : join(configDir, f);
      if (!existsSync(resolved)) missing.push(f);
    }
    if (missing.length > 0) {
      return { name: "Extends", status: "fail", message: `missing: ${missing.join(", ")}` };
    }
    return { name: "Extends", status: "pass", message: `${files.length} file(s) resolved` };
  } catch {
    return { name: "Extends", status: "warn", message: "could not check" };
  }
}

function checkTpm(): DoctorCheck {
  if (process.platform !== "linux") {
    return { name: "Hardware", status: "warn", message: `${process.platform} (TPM check skipped)` };
  }
  const hasDev = existsSync("/dev/tpm0");
  let hasTools = false;
  try {
    execSync("which tpm2_pcrread", { timeout: 2_000, stdio: ["pipe", "pipe", "pipe"] });
    hasTools = true;
  } catch { /* not installed */ }

  if (hasDev && hasTools) {
    return { name: "Hardware", status: "pass", message: "/dev/tpm0 + tpm2-tools detected" };
  }
  if (hasDev) {
    return { name: "Hardware", status: "warn", message: "/dev/tpm0 detected, tpm2-tools missing",
      tip: "Install: apt install tpm2-tools" };
  }
  if (hasTools) {
    return { name: "Hardware", status: "warn", message: "tpm2-tools installed, /dev/tpm0 not detected" };
  }
  return { name: "Hardware", status: "warn", message: "/dev/tpm0 not detected" };
}

function checkRuntimeProfile(configPath: string): DoctorCheck {
  try {
    const yaml = require("yaml");
    const raw = yaml.parse(readFileSync(configPath, "utf-8"));
    const hw = raw?.hardware;
    if (!hw?.runtime_profile) {
      return { name: "Runtime Profile", status: "pass", message: "not configured (optional)" };
    }
    const rp = hw.runtime_profile;
    const fields = Object.keys(rp).filter((k: string) =>
      ["expected_topology", "min_gpu_count", "min_memory_mb", "expected_accelerator", "max_temperature_celsius", "max_power_watts"].includes(k),
    );
    return { name: "Runtime Profile", status: "pass", message: `${fields.length} constraint(s): ${fields.join(", ")}` };
  } catch {
    return { name: "Runtime Profile", status: "warn", message: "could not parse config" };
  }
}

function checkMcpConfig(): DoctorCheck {
  if (process.env.SWT3_CONFIG_FILE) {
    return { name: "MCP", status: "pass", message: `SWT3_CONFIG_FILE=${process.env.SWT3_CONFIG_FILE}` };
  }
  return {
    name: "MCP",
    status: "warn",
    message: "SWT3_CONFIG_FILE not set",
    tip: "export SWT3_CONFIG_FILE=./swt3.yaml",
  };
}

export function runDoctorChecks(configPath?: string): DoctorCheck[] {
  const checks: DoctorCheck[] = [];

  let path: string | null;
  if (configPath) {
    if (existsSync(configPath)) {
      checks.push({ name: "Config file", status: "pass", message: configPath });
      path = configPath;
    } else {
      checks.push({ name: "Config file", status: "fail", message: `not found: ${configPath}`, tip: "Run: swt3 init" });
      return checks;
    }
  } else {
    const yamlCheck = checkYamlFound();
    checks.push(yamlCheck);
    path = yamlCheck.status === "pass" ? yamlCheck.message.replace("./", "") : null;
  }

  if (!path) {
    return checks;
  }

  checks.push(checkYamlValid(path));
  checks.push(checkEnvVars(path));
  checks.push(checkProfile(path));
  checks.push(checkSections(path));
  checks.push(checkExtends(path));
  checks.push(checkTpm());
  checks.push(checkRuntimeProfile(path));
  checks.push(checkMcpConfig());

  return checks;
}

export function printDoctorResults(checks: DoctorCheck[], json: boolean = false): void {
  if (json) {
    console.log(JSON.stringify(checks, null, 2));
    return;
  }

  const VERSION = "0.5.2";
  console.log(`\n  SWT3 Doctor v${VERSION}\n`);

  const icons = { pass: "\x1b[32m[PASS]\x1b[0m", warn: "\x1b[33m[WARN]\x1b[0m", fail: "\x1b[31m[FAIL]\x1b[0m" };

  for (const check of checks) {
    const icon = icons[check.status];
    console.log(`  ${icon} ${check.name}: ${check.message}`);
    if (check.tip) {
      console.log(`         Tip: ${check.tip}`);
    }
  }

  const pass = checks.filter((c) => c.status === "pass").length;
  const warn = checks.filter((c) => c.status === "warn").length;
  const fail = checks.filter((c) => c.status === "fail").length;
  console.log(`\n  ${pass} passed, ${warn} warnings, ${fail} failures\n`);

  console.log("  \x1b[33mNew in v0.5.2:\x1b[0m Trust Mesh -- agents verify each other before exchanging data.");
  console.log("  Configure: \x1b[36mswt3 init --profile eu-ai-act-high-risk\x1b[0m");
  console.log("  Docs: https://www.npmjs.com/package/@tenova/swt3-mcp\n");
}

// ── Friction Test ───────────────────────────────────────────────────────

export interface FrictionStep {
  name: string;
  status: "pass" | "fail";
  durationMs: number;
  error?: string;
}

export async function runFrictionTest(): Promise<FrictionStep[]> {
  const steps: FrictionStep[] = [];
  const tmpDir = mkdtempSync(join(tmpdir(), "swt3-friction-"));
  const configPath = join(tmpDir, "swt3.yaml");

  function step(name: string, fn: () => void): void {
    const start = performance.now();
    try {
      fn();
      steps.push({ name, status: "pass", durationMs: Math.round(performance.now() - start) });
    } catch (err: any) {
      steps.push({ name, status: "fail", durationMs: Math.round(performance.now() - start), error: err.message });
    }
  }

  // 1. Config discovery
  step("Config discovery", () => {
    writeFileSync(configPath, [
      "clearing_level: 1",
      "tenant_id: FRICTION_TEST",
      "agent_id: test-agent",
      "api_key: test_key_friction",
      "mcp_policy:",
      "  tool_blocklist: [\"dangerous_tool\"]",
      "  max_tokens_per_session: 500",
      "  fail_secure: true",
    ].join("\n"), "utf-8");
    if (!existsSync(configPath)) throw new Error("Config file not created");
  });

  // 2. fromConfig loads
  step("fromConfig() loads", () => {
    const { loadFullConfig } = require("./config.js");
    const loaded = loadFullConfig(configPath);
    if (!loaded.mcpPolicy) throw new Error("mcpPolicy not parsed");
    if (!loaded.mcpPolicy.toolBlocklist?.length) throw new Error("toolBlocklist empty");
  });

  // 3. ChainEnforcer created
  step("ChainEnforcer created", () => {
    const { ChainEnforcer } = require("./witness.js");
    const enforcer = new ChainEnforcer({
      witnessedTools: [], exemptTools: [], requireTrustLevel: 0,
      autoWitness: true, blockOnFailure: false,
      toolBlocklist: ["dangerous_tool"], failSecure: true,
    });
    const result = enforcer.check("safe_tool");
    if (result !== null) throw new Error("Safe tool was blocked");
  });

  // 4. wrapTool blocks on violation
  step("Blocklist enforcement", () => {
    const { ChainEnforcer, PolicyViolationError } = require("./witness.js");
    const enforcer = new ChainEnforcer({
      witnessedTools: [], exemptTools: [], requireTrustLevel: 0,
      autoWitness: true, blockOnFailure: false,
      toolBlocklist: ["dangerous_tool"], failSecure: true,
    });
    const violation = enforcer.check("dangerous_tool");
    if (!violation) throw new Error("Blocklist did not trigger");
    if (violation.action !== "blocked") throw new Error("Action should be blocked");
  });

  // 5. Token budget enforcement
  step("Token budget enforcement", () => {
    const { ChainEnforcer } = require("./witness.js");
    const enforcer = new ChainEnforcer({
      witnessedTools: [], exemptTools: [], requireTrustLevel: 0,
      autoWitness: true, blockOnFailure: false,
      maxTokensPerSession: 100, failSecure: true,
    });
    enforcer.recordTokens(150);
    const violation = enforcer.check("any_tool");
    if (!violation) throw new Error("Token budget did not trigger");
    if (violation.rule !== "token_budget") throw new Error(`Wrong rule: ${violation.rule}`);
  });

  // 6. Audit report generation
  step("Audit report generation", () => {
    const { ChainMonitorExporter } = require("./exporters/chain-monitor.js");
    const exporter = new ChainMonitorExporter({ walDir: tmpDir, tenantId: "FRICTION_TEST" });
    const html = exporter.exportHtml();
    if (!html.includes("SWT3 Exploit Chain Monitor")) throw new Error("HTML missing title");
    if (!html.includes("Self-Signed")) throw new Error("HTML missing watermark");
  });

  // 7. Error message clarity
  step("Error message clarity", () => {
    const { PolicyViolationError } = require("./witness.js");
    const violation = {
      rule: "blocklist", toolName: "dangerous_tool", action: "blocked",
      reason: 'Tool "dangerous_tool" is on the blocklist', timestamp: Date.now(),
    };
    const err = new PolicyViolationError(violation);
    if (!err.message.includes("dangerous_tool")) throw new Error("Error missing tool name");
    if (!err.message.includes("blocklist")) throw new Error("Error missing reason");
  });

  // Cleanup
  try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }

  return steps;
}

export function printFrictionResults(steps: FrictionStep[]): void {
  const VERSION = "0.5.3";
  console.log(`\n  SWT3 Friction Test v${VERSION}\n`);

  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    const icon = s.status === "pass" ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
    const dots = ".".repeat(Math.max(1, 36 - s.name.length));
    console.log(`  ${i + 1}. ${s.name} ${dots} ${icon}  (${s.durationMs}ms)`);
    if (s.error) {
      console.log(`     \x1b[31m${s.error}\x1b[0m`);
    }
  }

  const passed = steps.filter((s) => s.status === "pass").length;
  const total = steps.length;
  const totalMs = steps.reduce((sum, s) => sum + s.durationMs, 0);
  console.log(`\n  ${passed}/${total} passed. Total: ${totalMs}ms.\n`);
}
