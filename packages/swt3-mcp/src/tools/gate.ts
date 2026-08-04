/**
 * SWT3 MCP Server: gate_evaluate tool.
 *
 * Parses and validates .swt3-gate.yml content. Optionally evaluates
 * against live anchors via the server API.
 * Read-only -- no anchor minting.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient } from "../client.js";
import {
  parseGateDict,
  validateProcedures,
  allProcedures,
  crosswalkProcedures as procedures,
} from "@tenova/swt3-ai";
import type { GateConfig, FrameworkGate } from "@tenova/swt3-ai";

interface GateEvaluateArgs {
  gate_yaml: string;
  framework?: string;
  model_id?: string;
  evaluate_live?: boolean;
}

function countGates(fw: FrameworkGate): [number, number] {
  let total = 0, critical = 0;
  for (const g of fw.gates) {
    total += g.procedures.length;
    critical += g.procedures.filter((p) => p.critical).length;
  }
  return [total, critical];
}

function renderOfflineReport(config: GateConfig, framework?: string): string {
  const lines: string[] = [];
  const name = config.name || "(unnamed)";

  lines.push(`Gate Config: ${name}`);
  lines.push(`Version: ${config.version} | Strict: ${config.strict}`);

  // Models
  const modelEntries = Object.entries(config.models);
  if (modelEntries.length > 0) {
    const modelsStr = modelEntries
      .map(([m, v]) => `${m} (${v.risk || "unspecified"})`)
      .join(", ");
    lines.push(`Models: ${modelsStr}`);
  }

  // Frameworks
  const fwEntries = framework
    ? Object.entries(config.frameworks).filter(([k]) => k.toLowerCase() === framework.toLowerCase())
    : Object.entries(config.frameworks);

  if (fwEntries.length > 0) {
    lines.push(``);
    lines.push(`Frameworks:`);
    for (const [fwName, fw] of fwEntries) {
      const [total, critical] = countGates(fw);
      const riskStr = fw.riskClass ? `  risk: ${fw.riskClass}` : "";
      const critStr = critical > 0 ? ` (${critical} critical)` : "";
      lines.push(`  ${fwName}: ${total} gates${critStr}${riskStr}`);

      // Show groups
      for (const group of fw.gates) {
        if (group.group) {
          lines.push(`    ${group.group}: ${group.procedures.length} procedures`);
        }
      }
    }
  }

  // Totals
  const defaultCount = config.defaults?.gates.length ?? 0;
  let totalFwGates = 0;
  for (const fw of Object.values(config.frameworks)) {
    for (const g of fw.gates) totalFwGates += g.procedures.length;
  }
  const defaultStr = defaultCount > 0 ? ` + ${defaultCount} defaults` : "";
  lines.push(``);
  lines.push(`Total: ${totalFwGates} framework gates${defaultStr}`);

  // Warnings
  if (config.warnings.length > 0) {
    lines.push(``);
    for (const w of config.warnings) {
      lines.push(`Warning: ${w}`);
    }
  }

  lines.push(``);
  lines.push(`Config valid.`);

  return lines.join("\n");
}

export async function handleGateEvaluate(
  args: GateEvaluateArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  // Parse YAML
  let raw: unknown;
  try {
    const yamlLib = await import("yaml");
    raw = yamlLib.parse(args.gate_yaml);
  } catch (err) {
    if ((err as Error).message?.includes("Cannot find")) {
      return "Error: YAML parser not available. Install with: npm install yaml";
    }
    return `Error: Invalid YAML syntax -- ${(err as Error).message}`;
  }

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return `Error: Gate config must be a YAML mapping, got ${typeof raw}`;
  }

  let gateConfig: GateConfig;
  try {
    gateConfig = parseGateDict(raw as Record<string, unknown>);
  } catch (err) {
    return `Error: ${(err as Error).message}`;
  }

  // Validate procedures against bundled registry
  try {
    const known = new Set(Object.keys(procedures()));
    const procWarnings = validateProcedures(gateConfig, known);
    gateConfig.warnings.push(...procWarnings);
  } catch {
    // crosswalk data not available -- skip validation
  }

  // Offline mode (default)
  if (!args.evaluate_live) {
    return renderOfflineReport(gateConfig, args.framework);
  }

  // Live evaluation
  if (config.demo) {
    return [
      renderOfflineReport(gateConfig, args.framework),
      ``,
      `Live evaluation requires a connected account.`,
      `Use the signup tool to create a free account, then set SWT3_API_KEY.`,
    ].join("\n");
  }

  // POST to server API
  const url = `${config.endpoint.replace(/\/$/, "")}/api/v1/gate/evaluate`;
  const payload: Record<string, unknown> = {
    config: raw,
    framework: args.framework,
  };
  if (args.model_id) payload.model_id = args.model_id;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);

    const result = await res.json() as Record<string, unknown>;
    if (!res.ok) {
      return `Error: API returned ${res.status} -- ${(result.error as string) ?? res.statusText}`;
    }

    // Format live evaluation result
    const gate = result.gate as string;
    const summary = result.summary as Record<string, number>;
    const results = result.results as Array<Record<string, unknown>>;
    const warnings = result.warnings as string[];

    const lines: string[] = [];
    lines.push(`Gate Evaluation: ${gate}`);
    lines.push(`Framework: ${result.framework}`);
    if (result.model_id) lines.push(`Model: ${result.model_id}`);
    lines.push(`${summary.passed} passed, ${summary.warned} warned, ${summary.failed} failed${summary.missing ? `, ${summary.missing} missing` : ""}`);
    lines.push(``);

    for (const r of results) {
      const icon = r.gate === "PASS" ? "+" : r.gate === "WARN" ? "~" : "-";
      const refStr = r.ref ? ` (${r.ref})` : "";
      lines.push(`  ${icon} ${(r.procedure as string).padEnd(16)} ${(r.gate as string).padEnd(5)} ${r.reason}${refStr}`);
    }

    if (warnings?.length > 0) {
      lines.push(``);
      for (const w of warnings) lines.push(`Warning: ${w}`);
    }

    return lines.join("\n");
  } catch (err) {
    return `Error: Connection failed -- ${(err as Error).message}`;
  }
}
