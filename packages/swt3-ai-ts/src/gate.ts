/**
 * SWT3 Governance Gate configuration parser.
 *
 * Parses .swt3-gate.yml files into typed data structures for policy evaluation.
 * Spec version: 1.0 (locked after 2 red team passes, July 24 2026)
 */

import { readFileSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";

const GATE_FILENAMES = [".swt3-gate.yml", "swt3-gate.yml", ".swt3-gate.yaml", "swt3-gate.yaml"];
const VALID_TOP_LEVEL_KEYS = new Set(["version", "name", "strict", "metadata", "models", "defaults", "frameworks"]);
const MAX_AGE_PATTERN = /^(\d+)\s*(d|h|m)$/i;
const MAX_AGE_MULTIPLIERS: Record<string, number> = { d: 86400, h: 3600, m: 60 };

export interface GateProcedure {
  procedure: string;
  required: boolean;
  maxAge?: string;
  maxAgeSeconds?: number;
  ref?: string;
  critical: boolean;
  description?: string;
  hint?: string;
  mustNotExist: boolean;
}

export interface GateGroup {
  group: string;
  procedures: GateProcedure[];
}

export interface FrameworkGate {
  riskClass?: string;
  crosswalkHash?: string;
  gates: GateGroup[];
}

export interface GateModel {
  risk?: string;
}

export interface GateDefaults {
  gates: GateProcedure[];
}

export interface GateConfig {
  version: string;
  name?: string;
  strict: boolean;
  metadata?: Record<string, unknown>;
  models: Record<string, GateModel>;
  defaults?: GateDefaults;
  frameworks: Record<string, FrameworkGate>;
  sourcePath?: string;
  warnings: string[];
}

export function parseMaxAge(ageStr: string): number {
  const trimmed = ageStr.trim();
  const m = MAX_AGE_PATTERN.exec(trimmed);
  if (!m) {
    throw new Error(`Invalid max_age format: "${ageStr}". Use Nd, Nh, or Nm (e.g., 7d, 24h, 30m)`);
  }
  const value = parseInt(m[1], 10);
  const unit = m[2].toLowerCase();
  return value * MAX_AGE_MULTIPLIERS[unit];
}

function parseProcedure(raw: Record<string, unknown>): GateProcedure {
  const procedure = raw.procedure;
  if (!procedure || typeof procedure !== "string") {
    throw new Error(`Gate procedure entry missing 'procedure' field: ${JSON.stringify(raw)}`);
  }

  const maxAge = typeof raw.max_age === "string" ? raw.max_age : undefined;
  let maxAgeSeconds: number | undefined;
  if (maxAge) {
    maxAgeSeconds = parseMaxAge(maxAge);
  }

  return {
    procedure,
    required: Boolean(raw.required ?? false),
    maxAge,
    maxAgeSeconds,
    ref: typeof raw.ref === "string" ? raw.ref : undefined,
    critical: Boolean(raw.critical ?? false),
    description: typeof raw.description === "string" ? raw.description : undefined,
    hint: typeof raw.hint === "string" ? raw.hint : undefined,
    mustNotExist: Boolean(raw.must_not_exist ?? false),
  };
}

function parseGates(rawGates: unknown, warnings: string[]): GateGroup[] {
  if (!Array.isArray(rawGates)) return [];

  const groups: GateGroup[] = [];
  const flatProcedures: GateProcedure[] = [];

  for (const item of rawGates) {
    if (!item || typeof item !== "object") continue;
    const obj = item as Record<string, unknown>;

    if ("group" in obj && "procedures" in obj) {
      const procs = Array.isArray(obj.procedures)
        ? obj.procedures
            .filter((p): p is Record<string, unknown> => typeof p === "object" && p !== null)
            .map(parseProcedure)
        : [];
      groups.push({ group: String(obj.group), procedures: procs });
    } else if ("procedure" in obj) {
      flatProcedures.push(parseProcedure(obj));
    }
  }

  if (flatProcedures.length > 0) {
    groups.push({ group: "", procedures: flatProcedures });
  }

  return groups;
}

export function findGateFile(path?: string): string | null {
  if (path) {
    const resolved = resolve(path);
    return existsSync(resolved) ? resolved : null;
  }

  let current = process.cwd();
  for (let i = 0; i < 10; i++) {
    for (const name of GATE_FILENAMES) {
      const candidate = join(current, name);
      if (existsSync(candidate)) return candidate;
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

export function parseGateDict(raw: Record<string, unknown>, sourcePath?: string): GateConfig {
  const warnings: string[] = [];

  // Version check
  const version = raw.version;
  if (!version) {
    throw new Error("Gate config missing required 'version' field");
  }

  // Unknown keys
  for (const key of Object.keys(raw)) {
    if (!VALID_TOP_LEVEL_KEYS.has(key)) {
      warnings.push(`Unknown top-level key: "${key}"`);
    }
  }

  // Models
  const models: Record<string, GateModel> = {};
  const rawModels = raw.models;
  if (rawModels && typeof rawModels === "object" && !Array.isArray(rawModels)) {
    for (const [name, val] of Object.entries(rawModels as Record<string, unknown>)) {
      if (val && typeof val === "object") {
        models[name] = { risk: (val as Record<string, unknown>).risk as string | undefined };
      } else {
        models[name] = {};
      }
    }
  }

  // Defaults
  let defaults: GateDefaults | undefined;
  const rawDefaults = raw.defaults;
  if (rawDefaults && typeof rawDefaults === "object") {
    const rd = rawDefaults as Record<string, unknown>;
    const rawDefaultGates = rd.gates;
    const defaultProcs: GateProcedure[] = [];
    if (Array.isArray(rawDefaultGates)) {
      for (const item of rawDefaultGates) {
        if (item && typeof item === "object" && "procedure" in (item as Record<string, unknown>)) {
          defaultProcs.push(parseProcedure(item as Record<string, unknown>));
        }
      }
    }
    defaults = { gates: defaultProcs };
  }

  // Frameworks
  const frameworks: Record<string, FrameworkGate> = {};
  const rawFrameworks = raw.frameworks;
  if (rawFrameworks && typeof rawFrameworks === "object" && !Array.isArray(rawFrameworks)) {
    for (const [fwName, fwVal] of Object.entries(rawFrameworks as Record<string, unknown>)) {
      if (!fwVal || typeof fwVal !== "object") continue;
      const fw = fwVal as Record<string, unknown>;
      const parsedGates = parseGates(fw.gates, warnings);
      if (parsedGates.length === 0) {
        warnings.push(`Framework "${fwName}" has no gates defined`);
      }
      frameworks[fwName] = {
        riskClass: typeof fw.risk_class === "string" ? fw.risk_class : undefined,
        crosswalkHash: typeof fw.crosswalk_hash === "string" ? fw.crosswalk_hash : undefined,
        gates: parsedGates,
      };
    }
  }

  return {
    version: String(version),
    name: typeof raw.name === "string" ? raw.name : undefined,
    strict: Boolean(raw.strict ?? false),
    metadata: raw.metadata && typeof raw.metadata === "object" ? raw.metadata as Record<string, unknown> : undefined,
    models,
    defaults,
    frameworks,
    sourcePath,
    warnings,
  };
}

export function loadGateConfig(path?: string): GateConfig {
  let yamlParse: (content: string) => unknown;
  try {
    const yamlLib = require("yaml");
    yamlParse = (content: string) => yamlLib.parse(content);
  } catch {
    throw new Error("YAML parser required. Install with: npm install yaml");
  }

  const filePath = findGateFile(path);
  if (!filePath) {
    const searched = path || GATE_FILENAMES.join(", ");
    throw new Error(`No gate config found. Searched for: ${searched}`);
  }

  const content = readFileSync(filePath, "utf-8");
  const raw = yamlParse(content);

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`Gate config must be a YAML mapping, got ${typeof raw}`);
  }

  return parseGateDict(raw as Record<string, unknown>, filePath);
}

export function validateProcedures(config: GateConfig, known: Set<string>): string[] {
  const warnings: string[] = [];

  const check = (procId: string, context: string) => {
    if (!known.has(procId)) {
      warnings.push(`Unknown procedure "${procId}" in ${context}`);
    }
  };

  if (config.defaults) {
    for (const gp of config.defaults.gates) {
      check(gp.procedure, "defaults");
    }
  }

  for (const [fwName, fw] of Object.entries(config.frameworks)) {
    for (const group of fw.gates) {
      for (const gp of group.procedures) {
        check(gp.procedure, `frameworks.${fwName}`);
      }
    }
  }

  return warnings;
}

export function allProcedures(config: GateConfig): Array<[string, GateProcedure]> {
  const result: Array<[string, GateProcedure]> = [];
  if (config.defaults) {
    for (const gp of config.defaults.gates) {
      result.push(["defaults", gp]);
    }
  }
  for (const [fwName, fw] of Object.entries(config.frameworks)) {
    for (const group of fw.gates) {
      for (const gp of group.procedures) {
        result.push([fwName, gp]);
      }
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Gate init generator
// ---------------------------------------------------------------------------

const CRITICAL_PROCEDURES = new Set([
  "AI-FAIR.1", "AI-FAIR.2", "AI-HITL.1", "AI-EXPL.1",
  "AI-GRD.1", "AI-SEC.1", "AI-AUDIT.1", "AI-SAFE.1",
]);

const MAX_AGE_DEFAULTS: Record<string, string> = {
  critical: "24h",
  high: "7d",
  medium: "30d",
  low: "90d",
};

const FRAMEWORK_RISK_CLASSES: Record<string, string> = {
  "EU-AI-ACT": "high-risk",
  "SR-11-7": "model-risk",
  "NIST-AI-RMF": "moderate",
  "NIST-800-53": "moderate",
  "ISO-42001": "conformity",
  "FIVE-EYES-AGENTIC": "agentic",
  "OWASP-AGENTIC": "agentic",
  "GDPR": "data-protection",
};

const PROCEDURE_HINTS: Record<string, string> = {
  "AI-INF.1": "wrap", "AI-INF.2": "wrap", "AI-INF.3": "wrap",
  "AI-GRD.1": "wrap", "AI-GRD.2": "wrap", "AI-CHAIN.1": "wrap", "AI-VIO.1": "wrap",
  "AI-TOOL.1": "wrapTool", "AI-TOOL.2": "witnessToolPermissions",
  "AI-ACC.1": "wrapAccess", "AI-ID.1": "new Witness({ agentId: '...' })",
  "AI-REV.1": "revoke",
  "AI-EXPL.1": "witnessExplanation", "AI-EXPL.2": "witnessExplanation",
  "AI-DATA.1": "witnessDataProvenance", "AI-DATA.2": "witnessDataQuality",
  "AI-DATA.3": "witnessDataProvenance", "AI-DATA.4": "witnessTrainingPiiLifecycle",
  "AI-FAIR.1": "witnessFairness", "AI-FAIR.2": "witnessFairness", "AI-FAIR.3": "witnessBiasAssessment",
  "AI-HITL.1": "witnessHumanOversight", "AI-HITL.2": "witnessHumanOversight",
  "AI-HITL.3": "witnessReviewerIdentity",
  "AI-MDL.1": "witnessModelWeights", "AI-MDL.5": "witnessModelWeights",
  "AI-MDL.6": "witnessAdapterStack", "AI-MDL.7": "witnessQuantization",
  "AI-RAG.1": "witnessRagContext", "AI-RAG.2": "witnessRagContext",
  "AI-SKILL.1": "witnessSkillManifest", "AI-SKILL.2": "witnessMemoryContext",
  "AI-SKILL.3": "witnessRewardModel",
  "AI-DRIFT.1": "witnessDrift", "AI-DRIFT.2": "witnessDrift",
  "AI-DEL.1": "witnessDelegationTree", "AI-COST.1": "witnessResourceConsumption",
  "AI-SEC.1": "witnessSecurityScan", "AI-SEC.2": "witnessSecurityScan",
  "AI-CYBER.1": "witnessCybersecurity",
  "AI-HW.1": "witnessHardware", "AI-HW.3": "witnessTpmAttestation",
  "AI-TRUST.1": "verifyTrust", "AI-TRUST.2": "presentCredential",
  "AI-AUDIT.1": "witnessAuditIntegrity", "AI-AUDIT.2": "witnessTimestampAttestation",
  "AI-CONSENT.1": "witnessConsent", "AI-DPIA.1": "witnessDpia",
  "AI-SBOM.1": "witnessSbom",
  "AI-TRANS.1": "witnessTransparency", "AI-MARK.1": "witnessContentMark",
  "AI-WATERMARK.1": "witnessWatermarkVerification",
  "AI-AUTO.1": "witnessAutomatedDecision", "AI-AUTO.2": "witnessGenerationDepth",
  "AI-EMRG.1": "witnessEmergencyOverride", "AI-ASSESS.1": "witnessAssessment",
  "AI-LCM.1": "witnessLifecycle", "AI-INCIDENT.1": "witnessIncident",
  "AI-PMM.1": "witnessPostMarketMonitoring",
  "AI-ENV.1": "witnessEnvironment", "AI-ENV.2": "witnessEnergyDraw",
  "AI-BASE.1": "witnessAgentBaseline", "AI-CHR.1": "witnessCharter",
  "AI-DUALUSE.1": "witnessDualUse", "AI-SAFE.1": "witnessSafeState",
  "AI-REDTEAM.1": "witnessRedTeam", "AI-SUPPLY.1": "witnessSupplyChainRisk",
  "AI-MULTI.1": "witnessMultiAgentDelegation", "AI-ROBUST.1": "witnessRobustness",
  "AI-PERF.1": "witnessPerformance", "AI-LIC.1": "witnessLicenseProvenance",
  "AI-JUR.1": "witnessRouting", "AI-FIN.1": "witnessTransaction",
  "AI-METAGOV.1": "witnessGovernanceConfig",
  "AI-RISK.1": "witnessRiskAssessment",
  "AI-GOV.1": "witnessGovernanceFramework", "AI-GOV.2": "witnessGovernanceReview",
  "AI-GOV.3": "witnessGovernanceEscalation", "AI-GOV.4": "witnessGovernanceUpdate",
  "AI-GOV.5": "witnessGovernanceAccountability", "AI-GOV.6": "witnessRiskScope",
  "AI-IMPACT.1": "witnessImpactAssessment",
  "AI-LOG.1": "witnessLogCompleteness", "AI-IR.1": "witnessIncidentResponse",
};

const ARTICLE_LABELS: Record<string, Record<string, string>> = {
  "EU-AI-ACT": {
    "Art. 9": "Article 9: Risk Management",
    "Art. 10": "Article 10: Data Governance",
    "Art. 11": "Article 11: Technical Documentation",
    "Art. 12": "Article 12: Record-Keeping",
    "Art. 13": "Article 13: Transparency",
    "Art. 14": "Article 14: Human Oversight",
    "Art. 15": "Article 15: Accuracy, Robustness, Cybersecurity",
    "Art. 26": "Article 26: Deployer Obligations",
    "Art. 27": "Article 27: FRIA",
    "Art. 50": "Article 50: Transparency (GPAI)",
    "Art. 52": "Article 52: Transparency (Legacy)",
    "Art. 53": "Article 53: GPAI Obligations",
    "Art. 55": "Article 55: GPAI Systemic Risk",
    "Art. 72": "Article 72: Post-Market Monitoring",
  },
  "SR-11-7": {
    "II": "II: Board and Senior Management",
    "III": "III: Model Development and Implementation",
    "IV": "IV: Model Validation",
    "V": "V: Governance, Policies, and Controls",
  },
  "NIST-AI-RMF": {
    "GOVERN 1": "GOVERN 1: Policies and Procedures",
    "GOVERN 2": "GOVERN 2: Accountability",
    "GOVERN 3": "GOVERN 3: Workforce Diversity",
    "GOVERN 4": "GOVERN 4: Organizational Practices",
    "GOVERN 5": "GOVERN 5: Processes",
    "GOVERN 6": "GOVERN 6: Policies",
    "MAP 1": "MAP 1: Context",
    "MAP 2": "MAP 2: Categorize",
    "MAP 3": "MAP 3: Benefits and Costs",
    "MAP 5": "MAP 5: Impacts",
    "MEASURE 1": "MEASURE 1: Metrics",
    "MEASURE 2": "MEASURE 2: Evaluation",
    "MEASURE 3": "MEASURE 3: Tracking",
    "MEASURE 4": "MEASURE 4: Feedback",
    "MANAGE 1": "MANAGE 1: Risk Treatment",
    "MANAGE 2": "MANAGE 2: Risk Resources",
    "MANAGE 3": "MANAGE 3: Risk Responses",
    "MANAGE 4": "MANAGE 4: Risk Communication",
  },
};

function groupKey(ref: string): string {
  let m: RegExpMatchArray | null;
  // EU AI Act: Art. X(...)
  m = ref.match(/^(Art\.\s*\d+)/);
  if (m) return m[1];
  // Roman numeral sections: III.A -> III
  m = ref.match(/^([IVX]+)\b/);
  if (m) return m[1];
  // NIST RMF: GOVERN 1.1 -> GOVERN 1
  m = ref.match(/^([A-Z]+\s+\d+)/);
  if (m) return m[1];
  // ISO: A.8.4 -> A.8
  m = ref.match(/^(A\.\d+)/);
  if (m) return m[1];
  // FE-15 -> FE
  m = ref.match(/^([A-Z]+)-/);
  if (m) return m[1];
  return ref;
}

export async function generateGateYaml(
  frameworkId: string,
  options: { name?: string; strict?: boolean } = {},
): Promise<string> {
  const { resolveFramework, frameworks: fwFn, procedures: procFn, crosswalkVersion } = await import("./crosswalk.js");

  const allFw = fwFn();
  const fwMeta = allFw[frameworkId] as FrameworkMeta | undefined;
  if (!fwMeta) {
    const available = Object.entries(allFw)
      .filter(([, v]) => (v as FrameworkMeta).procedure_count > 0)
      .map(([k]) => k)
      .sort();
    throw new Error(`Unknown framework: "${frameworkId}". Available: ${available.join(", ")}`);
  }

  const allProcs = procFn();
  const byReq: Record<string, string[]> = resolveFramework(frameworkId);
  if (Object.keys(byReq).length === 0) {
    throw new Error(`Framework "${frameworkId}" has no procedure mappings in bundled crosswalks.`);
  }

  const riskClass = FRAMEWORK_RISK_CLASSES[frameworkId];
  const policyName = options.name || `${fwMeta.name || frameworkId} Governance Policy`;
  const fwLabels = ARTICLE_LABELS[frameworkId] ?? {};

  // Group procedures by article/section
  const groups = new Map<string, Array<{ ref: string; procId: string; title: string }>>();
  const seenProcs = new Set<string>();

  for (const ref of Object.keys(byReq).sort()) {
    const gk = groupKey(ref);
    if (!groups.has(gk)) groups.set(gk, []);
    for (const procId of [...byReq[ref]].sort()) {
      if (seenProcs.has(procId)) continue;
      seenProcs.add(procId);
      const title = allProcs[procId]?.title ?? procId;
      groups.get(gk)!.push({ ref, procId, title });
    }
  }

  const now = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const cwVer = crosswalkVersion();

  const lines: string[] = [
    `# Generated by: swt3 gate --init --framework ${frameworkId}`,
    `# Crosswalk version: ${cwVer}`,
    `# Generated at: ${now}`,
    `# Docs: https://sovereign.tenova.io/guides/developer-gate-config-guide.html`,
    `#`,
    `# Review and customize thresholds before committing to your repository.`,
    `# Run: swt3 gate --validate  to check this file.`,
    ``,
    `version: "1.0"`,
    `name: "${policyName}"`,
    `strict: ${options.strict ? "true" : "false"}`,
    ``,
    `metadata:`,
    `  generated_at: "${now}"`,
    `  crosswalk_version: "${cwVer}"`,
    `  framework: "${frameworkId}"`,
    ``,
    `models:`,
    `  # Add your model IDs here:`,
    `  # my-model-v1:`,
    `  #   risk: "high"`,
    ``,
    `frameworks:`,
    `  ${frameworkId.toLowerCase()}:`,
  ];

  if (riskClass) lines.push(`    risk_class: "${riskClass}"`);
  lines.push(`    gates:`);

  for (const gk of Array.from(groups.keys()).sort()) {
    const items = groups.get(gk)!;
    const label = fwLabels[gk] ?? gk;
    lines.push(`      - group: "${label}"`);
    lines.push(`        procedures:`);

    for (const { ref, procId, title } of items) {
      const isCritical = CRITICAL_PROCEDURES.has(procId);
      const maxAge = isCritical ? MAX_AGE_DEFAULTS.critical : MAX_AGE_DEFAULTS.high;
      const hint = PROCEDURE_HINTS[procId];

      lines.push(`          - procedure: ${procId}`);
      lines.push(`            ref: "${ref}"`);
      lines.push(`            description: "${title}"`);
      lines.push(`            required: true`);
      lines.push(`            max_age: ${maxAge}`);
      if (isCritical) lines.push(`            critical: true`);
      if (hint) lines.push(`            hint: "witness.${hint}()"`);
    }
  }

  lines.push(``);
  lines.push(`defaults:`);
  lines.push(`  gates:`);
  lines.push(`    - procedure: AI-LOG.1`);
  lines.push(`      required: true`);
  lines.push(`      description: "Log completeness attestation"`);
  lines.push(`      max_age: 7d`);
  lines.push(`    - procedure: AI-AUDIT.1`);
  lines.push(`      required: true`);
  lines.push(`      description: "Audit trail integrity"`);
  lines.push(`      max_age: 7d`);
  lines.push(``);

  return lines.join("\n");
}

interface FrameworkMeta { name: string; procedure_count: number; [k: string]: unknown; }

export async function listFrameworks(): Promise<Array<{ id: string; name: string; procedures: number }>> {
  const { frameworks: fwFn } = await import("./crosswalk.js");
  const allFw = fwFn();
  return Object.entries(allFw)
    .filter(([, v]) => ((v as FrameworkMeta).procedure_count ?? 0) > 0)
    .map(([id, v]) => ({ id, name: (v as FrameworkMeta).name, procedures: (v as FrameworkMeta).procedure_count }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

// ---------------------------------------------------------------------------
// CLI handler
// ---------------------------------------------------------------------------

function countGates(fw: FrameworkGate): [number, number] {
  let total = 0, critical = 0;
  for (const g of fw.gates) {
    total += g.procedures.length;
    critical += g.procedures.filter(p => p.critical).length;
  }
  return [total, critical];
}

function renderValidateText(config: GateConfig): void {
  const name = config.name || "(unnamed)";
  const strict = config.strict ? "true" : "false";
  console.log(`\n  SWT3 Gate Config: ${name}`);
  console.log(`  Version: ${config.version} | Strict: ${strict}`);

  const modelEntries = Object.entries(config.models);
  if (modelEntries.length > 0) {
    const modelsStr = modelEntries.map(([m, v]) => `${m} (${v.risk || "unspecified"})`).join(", ");
    console.log(`  Models: ${modelsStr}`);
  }

  const fwEntries = Object.entries(config.frameworks);
  if (fwEntries.length > 0) {
    console.log(`\n  Frameworks:`);
    for (const [fwName, fw] of fwEntries) {
      const [total, critical] = countGates(fw);
      const riskStr = fw.riskClass ? `  risk: ${fw.riskClass}` : "";
      const critStr = critical > 0 ? ` (${critical} critical)` : "";
      console.log(`    ${fwName.padEnd(20)} ${total} gates${critStr}${riskStr}`);
    }
  }

  const defaultCount = config.defaults?.gates.length ?? 0;
  let totalFwGates = 0;
  for (const fw of Object.values(config.frameworks)) {
    for (const g of fw.gates) totalFwGates += g.procedures.length;
  }
  const defaultStr = defaultCount > 0 ? ` + ${defaultCount} defaults` : "";
  console.log(`\n  Total: ${totalFwGates} framework gates${defaultStr}`);

  if (config.sourcePath) console.log(`  Source: ${config.sourcePath}`);
  console.log(`  \x1b[32mConfig valid.\x1b[0m\n`);
}

function renderValidateJson(config: GateConfig): void {
  const fwSummary: Record<string, unknown> = {};
  for (const [fwName, fw] of Object.entries(config.frameworks)) {
    const [total, critical] = countGates(fw);
    fwSummary[fwName] = { gates: total, critical, riskClass: fw.riskClass };
  }
  const result = {
    valid: true,
    version: config.version,
    name: config.name,
    strict: config.strict,
    models: Object.fromEntries(Object.entries(config.models).map(([m, v]) => [m, { risk: v.risk }])),
    frameworks: fwSummary,
    defaults: config.defaults?.gates.length ?? 0,
    warnings: config.warnings,
    source: config.sourcePath,
  };
  console.log(JSON.stringify(result, null, 2));
}

async function handleInit(args: string[]): Promise<void> {
  const flagVal = (flag: string): string | undefined => {
    const idx = args.indexOf(flag);
    return idx !== -1 && args[idx + 1] ? args[idx + 1] : undefined;
  };

  const fw = flagVal("--framework");
  const name = flagVal("--name");
  const output = flagVal("--output") ?? ".swt3-gate.yml";
  const strict = args.includes("--strict");
  const useJson = args.includes("--json");
  const force = args.includes("--force");

  if (!fw) {
    const fws = await listFrameworks();
    if (useJson) {
      console.log(JSON.stringify(fws, null, 2));
    } else {
      console.log(`\n  Available frameworks for gate --init:\n`);
      for (const f of fws) {
        console.log(`    ${f.id.padEnd(24)} ${String(f.procedures).padStart(3)} procedures  ${f.name}`);
      }
      console.log(`\n  Usage: swt3 gate --init --framework EU-AI-ACT`);
      console.log(`         swt3 gate --init --framework SR-11-7 --output my-gate.yml\n`);
    }
    return;
  }

  let yamlContent: string;
  try {
    yamlContent = await generateGateYaml(fw, { name, strict });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (useJson) {
      console.log(JSON.stringify({ error: msg }));
    } else {
      console.error(`\n  \x1b[31mError:\x1b[0m ${msg}\n`);
    }
    process.exit(1);
  }

  if (existsSync(output) && !force) {
    if (useJson) {
      console.log(JSON.stringify({ error: `${output} already exists. Use --force to overwrite.` }));
    } else {
      console.error(`\n  \x1b[31m${output} already exists.\x1b[0m Use --force to overwrite.\n`);
    }
    process.exit(1);
  }

  const { writeFileSync } = await import("node:fs");
  writeFileSync(output, yamlContent, "utf-8");

  if (useJson) {
    try {
      const yamlLib = require("yaml");
      const parsed = parseGateDict(yamlLib.parse(yamlContent), resolve(output));
      let total = 0;
      for (const fwg of Object.values(parsed.frameworks)) {
        for (const g of fwg.gates) total += g.procedures.length;
      }
      console.log(JSON.stringify({
        created: output,
        framework: fw,
        gates: total,
        defaults: parsed.defaults?.gates.length ?? 0,
      }));
    } catch {
      console.log(JSON.stringify({ created: output, framework: fw }));
    }
  } else {
    console.log(`\n  \x1b[32mCreated:\x1b[0m ${output}`);
    console.log(`  Framework: ${fw}`);
    console.log(`\n  Next steps:`);
    console.log(`    1. Add your model IDs to the 'models' section`);
    console.log(`    2. Review and adjust max_age thresholds`);
    console.log(`    3. Commit to your repository`);
    console.log(`    4. Run: swt3 gate --validate\n`);
  }
}

export async function handleGate(args: string[]): Promise<void> {
  // Handle --init before config loading
  if (args.includes("--init")) {
    await handleInit(args);
    return;
  }

  const flagVal = (flag: string): string | undefined => {
    const idx = args.indexOf(flag);
    return idx !== -1 && args[idx + 1] ? args[idx + 1] : undefined;
  };

  const configPath = flagVal("--config");
  const validateOnly = args.includes("--validate");
  const useJson = args.includes("--json");

  let config: GateConfig;
  try {
    config = loadGateConfig(configPath);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (useJson) {
      console.log(JSON.stringify({ valid: false, error: msg }));
    } else {
      const isNotFound = msg.includes("No gate config");
      if (isNotFound) {
        console.error(`\n  \x1b[31mGate config not found.\x1b[0m`);
        console.error(`  Searched for: .swt3-gate.yml, swt3-gate.yml`);
        console.error(`  Generate one: swt3 gate --init --framework eu-ai-act\n`);
      } else {
        console.error(`\n  \x1b[31mGate config error:\x1b[0m ${msg}\n`);
      }
    }
    process.exit(1);
  }

  // Show warnings
  if (!useJson) {
    for (const w of config.warnings) {
      console.log(`  \x1b[33mwarning:\x1b[0m ${w}`);
    }
  }

  // Validate procedures against bundled registry
  try {
    const { procedures } = await import("./crosswalk.js");
    const known = new Set(Object.keys(procedures()));
    const procWarnings = validateProcedures(config, known);
    if (!useJson) {
      for (const w of procWarnings) {
        console.log(`  \x1b[33mwarning:\x1b[0m ${w}`);
      }
    }
    config.warnings.push(...procWarnings);
  } catch { /* crosswalk data not available */ }

  if (validateOnly) {
    if (useJson) renderValidateJson(config);
    else renderValidateText(config);
    return;
  }

  // Live evaluation mode -- POST config to API
  let framework = flagVal("--framework");
  const modelId = flagVal("--model");

  if (!framework) {
    const fwKeys = Object.keys(config.frameworks);
    if (fwKeys.length === 1) {
      framework = fwKeys[0];
    } else if (fwKeys.length === 0) {
      if (useJson) console.log(JSON.stringify({ error: "No frameworks in config" }));
      else console.error(`\n  \x1b[31mNo frameworks defined in gate config.\x1b[0m\n`);
      process.exit(1);
    } else {
      if (useJson) {
        console.log(JSON.stringify({ error: `Multiple frameworks. Use --framework: ${fwKeys.join(", ")}` }));
      } else {
        console.error(`\n  \x1b[31mMultiple frameworks in config.\x1b[0m Use --framework to select:`);
        for (const k of fwKeys) console.error(`    swt3 gate --framework ${k}`);
        console.error();
      }
      process.exit(1);
    }
  }

  await evaluateLive(config, framework, modelId, useJson);
}

function configToDict(config: GateConfig): Record<string, unknown> {
  const d: Record<string, unknown> = { version: config.version };
  if (config.name) d.name = config.name;
  if (config.strict) d.strict = true;
  if (config.metadata) d.metadata = config.metadata;
  if (Object.keys(config.models).length > 0) {
    d.models = Object.fromEntries(
      Object.entries(config.models).map(([m, v]) => [m, { risk: v.risk }]),
    );
  }
  if (config.defaults) {
    d.defaults = {
      gates: config.defaults.gates.map((g) => {
        const entry: Record<string, unknown> = { procedure: g.procedure };
        if (g.required) entry.required = true;
        if (g.maxAge) entry.max_age = g.maxAge;
        if (g.critical) entry.critical = true;
        if (g.mustNotExist) entry.must_not_exist = true;
        return entry;
      }),
    };
  }
  if (Object.keys(config.frameworks).length > 0) {
    const fws: Record<string, unknown> = {};
    for (const [fwName, fw] of Object.entries(config.frameworks)) {
      const fwDict: Record<string, unknown> = {};
      if (fw.riskClass) fwDict.risk_class = fw.riskClass;
      if (fw.crosswalkHash) fwDict.crosswalk_hash = fw.crosswalkHash;
      fwDict.gates = fw.gates.map((group) => {
        const gDict: Record<string, unknown> = {};
        if (group.group) gDict.group = group.group;
        gDict.procedures = group.procedures.map((p) => {
          const entry: Record<string, unknown> = { procedure: p.procedure };
          if (p.required) entry.required = true;
          if (p.maxAge) entry.max_age = p.maxAge;
          if (p.critical) entry.critical = true;
          if (p.ref) entry.ref = p.ref;
          if (p.description) entry.description = p.description;
          if (p.hint) entry.hint = p.hint;
          if (p.mustNotExist) entry.must_not_exist = true;
          return entry;
        });
        return gDict;
      });
      fws[fwName] = fwDict;
    }
    d.frameworks = fws;
  }
  return d;
}

async function resolveApiCredentials(): Promise<{ apiKey: string; endpoint: string }> {
  let apiKey = process.env.SWT3_API_KEY ?? "";
  let endpoint = process.env.SWT3_ENDPOINT ?? "https://sovereign.tenova.io";

  try {
    const { loadFullConfig } = await import("./config.js");
    const cfg = loadFullConfig();
    const opts = cfg.witnessOptions as Record<string, unknown>;
    if (opts.apiKey) apiKey = opts.apiKey as string;
    if (opts.endpoint) endpoint = opts.endpoint as string;
  } catch { /* no config file */ }

  return { apiKey, endpoint };
}

function renderEvaluateText(result: Record<string, unknown>): void {
  const gate = result.gate as string;
  const summary = result.summary as Record<string, number>;
  const results = result.results as Array<Record<string, unknown>>;
  const warnings = result.warnings as string[];
  const ungoverned = result.ungoverned_models as string[];

  const gateColor = gate === "PASS" ? "\x1b[32m" : gate === "WARN" ? "\x1b[33m" : "\x1b[31m";
  const fw = result.framework as string;
  const model = result.model_id as string | null;
  const name = result.config_name as string;

  console.log(`\n  ${gateColor}${gate}\x1b[0m  ${name || "Gate Evaluation"}`);
  console.log(`  Framework: ${fw}${model ? `  Model: ${model}` : ""}`);
  console.log(`  ${summary.passed} passed, ${summary.warned} warned, ${summary.failed} failed${summary.missing ? `, ${summary.missing} missing` : ""}`);
  console.log();

  for (const r of results) {
    const proc = r.procedure as string;
    const rgate = r.gate as string;
    const reason = r.reason as string;
    const ref = r.ref as string | null;

    const icon = rgate === "PASS" ? "\x1b[32m+\x1b[0m" : rgate === "WARN" ? "\x1b[33m~\x1b[0m" : "\x1b[31m-\x1b[0m";
    const refStr = ref ? ` (${ref})` : "";
    console.log(`  ${icon} ${proc.padEnd(16)} ${rgate.padEnd(5)} ${reason}${refStr}`);
  }

  if (ungoverned?.length > 0) {
    console.log(`\n  \x1b[31mUngoverned models:\x1b[0m ${ungoverned.join(", ")}`);
  }
  for (const w of warnings ?? []) {
    console.log(`  \x1b[33mwarning:\x1b[0m ${w}`);
  }

  const hash = result.config_hash as string;
  if (hash) console.log(`\n  Config hash: ${hash.slice(0, 16)}...`);
  console.log(`  Portal: https://sovereign.tenova.io/command\n`);
}

async function evaluateLive(
  config: GateConfig,
  framework: string,
  modelId: string | undefined,
  useJson: boolean,
): Promise<void> {
  const { apiKey, endpoint } = await resolveApiCredentials();
  if (!apiKey) {
    if (useJson) {
      console.log(JSON.stringify({ error: "No API key. Set SWT3_API_KEY or configure swt3.yaml" }));
    } else {
      console.error(`\n  \x1b[31mNo API key found.\x1b[0m`);
      console.error(`  Set SWT3_API_KEY or add apiKey to swt3.config.yaml`);
      console.error(`  Use --validate for offline config validation.\n`);
    }
    process.exit(1);
  }

  const url = `${endpoint.replace(/\/$/, "")}/api/v1/gate/evaluate`;
  const payload: Record<string, unknown> = {
    config: configToDict(config),
    framework,
  };
  if (modelId) payload.model_id = modelId;

  let result: Record<string, unknown>;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(payload),
    });
    result = await res.json() as Record<string, unknown>;
    if (!res.ok) {
      const msg = (result.error as string) ?? `HTTP ${res.status}`;
      if (useJson) console.log(JSON.stringify({ error: msg }));
      else console.error(`\n  \x1b[31mAPI error:\x1b[0m ${msg}\n`);
      process.exit(1);
    }
  } catch (err) {
    const msg = (err as Error).message;
    if (useJson) console.log(JSON.stringify({ error: `Connection failed: ${msg}` }));
    else {
      console.error(`\n  \x1b[31mConnection failed:\x1b[0m ${msg}`);
      console.error(`  Endpoint: ${endpoint}\n`);
    }
    process.exit(1);
  }

  if (useJson) {
    console.log(JSON.stringify(result, null, 2));
    if (result.gate === "FAIL") process.exit(1);
    return;
  }

  renderEvaluateText(result);
  if (result.gate === "FAIL") process.exit(1);
}
