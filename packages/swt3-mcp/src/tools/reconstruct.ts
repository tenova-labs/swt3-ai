/**
 * SWT3 MCP Server: reconstruct_timeline tool.
 *
 * Fetches forensic timeline from the server API and formats it for display.
 * Read-only -- no anchor minting.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient } from "../client.js";

interface ReconstructArgs {
  cycle_id?: string;
  agent_id?: string;
  fingerprint?: string;
  chain_id?: string;
  last?: string;
}

const PROC_LABELS: Record<string, string> = {
  "AI-INF.1": "Inference",
  "AI-INF.2": "Latency Check",
  "AI-TOOL.1": "Tool Call",
  "AI-ID.1": "Agent Identity",
  "AI-ACC.1": "Resource Access",
  "AI-REV.1": "Revocation",
  "AI-DEL.1": "Delegation",
  "AI-COST.1": "Cost Witness",
  "AI-DRIFT.2": "Drift Detection",
  "AI-EMRG.1": "Emergency Override",
  "AI-ASSESS.1": "Assessment",
  "AI-GRD.1": "Guardrail Check",
  "AI-GRD.3": "Gatekeeper Gate",
  "AI-CHAIN.1": "Chain Witness",
  "AI-RAG.1": "RAG Provenance",
  "AI-RAG.2": "RAG Relevance",
  "AI-HITL.1": "Human Review",
  "AI-HITL.3": "Reviewer Identity",
  "AI-FAIR.1": "Fairness Assessment",
  "AI-MDL.5": "Model Integrity",
  "AI-MDL.6": "Adapter Stack",
  "AI-SKILL.1": "Skill Manifest",
  "AI-SKILL.2": "Memory Context",
  "AI-VIO.1": "Violation Report",
  "AI-TRUST.1": "Trust Verification",
  "AI-GOV.1": "Governance Framework",
  "AI-RISK.1": "Risk Register",
  "AI-IMPACT.1": "Impact Assessment",
  "AI-LOG.1": "Logging Attestation",
  "AI-IR.1": "Incident Response",
  "AI-AUTO.1": "Automated Decision",
  "AI-SAFE.1": "Safe State",
  "AI-EXPL.1": "Explanation",
  "AI-DATA.1": "Data Provenance",
};

const LAST_PATTERN = /^(\d+)(h|d|m)$/i;
const LAST_MULTIPLIERS: Record<string, number> = { h: 3600, d: 86400, m: 60 };

function parseLastWindow(last: string): { from: string; to: string } {
  const match = LAST_PATTERN.exec(last.trim());
  if (!match) {
    throw new Error(`Invalid time window: "${last}". Use Nh, Nd, or Nm (e.g., 1h, 7d, 30m).`);
  }
  const seconds = parseInt(match[1], 10) * LAST_MULTIPLIERS[match[2].toLowerCase()];
  const now = new Date();
  const from = new Date(now.getTime() - seconds * 1000);
  return { from: from.toISOString(), to: now.toISOString() };
}

function fmtTime(iso: string): string {
  try {
    return new Date(iso).toISOString().slice(11, 19);
  } catch {
    return iso.slice(0, 8);
  }
}

interface TimelineEntry {
  timestamp_server: string;
  agent_id: string | null;
  procedure_id: string;
  verdict: string;
  fingerprint: string;
  swt3_anchor: string;
  clearing_level: number;
  detail: Record<string, unknown>;
  is_drift?: boolean;
  is_override?: boolean;
  is_delegation?: boolean;
  is_cost?: boolean;
  is_violation?: boolean;
  lifecycle_stage?: string | null;
  lifecycle_chain_id?: string | null;
}

function formatTimeline(entries: TimelineEntry[], queryDesc: string): string {
  if (entries.length === 0) {
    return `No anchors found for ${queryDesc}.`;
  }

  const lines: string[] = [];
  lines.push(`Timeline: ${queryDesc}`);
  lines.push(`Anchors: ${entries.length}`);
  lines.push(``);

  // Unique agents
  const agents = new Set(entries.map((e) => e.agent_id).filter(Boolean));
  if (agents.size > 0) {
    lines.push(`Agents: ${Array.from(agents).join(", ")}`);
    lines.push(``);
  }

  for (const entry of entries) {
    const time = fmtTime(entry.timestamp_server);
    const label = PROC_LABELS[entry.procedure_id] || entry.procedure_id;
    const verdict = entry.verdict;
    const agent = entry.agent_id ? ` [${entry.agent_id}]` : "";
    const flags: string[] = [];
    if (entry.is_drift) flags.push("DRIFT");
    if (entry.is_override) flags.push("OVERRIDE");
    if (entry.is_violation) flags.push("VIOLATION");
    if (entry.is_delegation) flags.push("DELEGATION");
    if (entry.is_cost) flags.push("COST");
    const flagStr = flags.length > 0 ? ` [${flags.join(",")}]` : "";

    lines.push(`${time}  ${verdict.padEnd(5)} ${entry.procedure_id.padEnd(14)} ${label}${agent}${flagStr}`);

    // Show key details at lower clearing levels
    const d = entry.detail;
    if (d.model_id) lines.push(`         model: ${d.model_id}`);
    if (d.tokens_in != null || d.tokens_out != null) {
      lines.push(`         tokens: ${d.tokens_in ?? "?"} in / ${d.tokens_out ?? "?"} out`);
    }
    if (d.cost_cents != null && (d.cost_cents as number) >= 0) {
      lines.push(`         cost: $${((d.cost_cents as number) / 100).toFixed(2)}`);
    }
    if (d.revocation_target) lines.push(`         revoked: ${d.revocation_target}`);

    lines.push(`         fp: ${entry.fingerprint}`);
  }

  // Summary
  const passCount = entries.filter((e) => e.verdict === "PASS").length;
  const failCount = entries.filter((e) => e.verdict === "FAIL").length;
  lines.push(``);
  lines.push(`Summary: ${passCount} PASS, ${failCount} FAIL, ${entries.length} total`);

  return lines.join("\n");
}

export async function handleReconstructTimeline(
  args: ReconstructArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  // Demo mode rejection
  if (config.demo) {
    return "Timeline reconstruction requires a live account. Use the signup tool to create a free account.";
  }

  // Must have at least one query parameter
  if (!args.cycle_id && !args.agent_id && !args.fingerprint && !args.chain_id && !args.last) {
    return "Error: Provide at least one query parameter (cycle_id, agent_id, fingerprint, chain_id, or last).";
  }

  // Build query params
  const params = new URLSearchParams();
  if (args.cycle_id) params.set("cycle_id", args.cycle_id);
  if (args.agent_id) params.set("agent_id", args.agent_id);
  if (args.fingerprint) params.set("fingerprint", args.fingerprint);
  if (args.chain_id) params.set("chain_id", args.chain_id);

  if (args.last) {
    try {
      const { from, to } = parseLastWindow(args.last);
      params.set("from", from);
      params.set("to", to);
    } catch (err) {
      return (err as Error).message;
    }
  }

  // Build query description for display
  const queryDesc = args.cycle_id
    ? `cycle ${args.cycle_id}`
    : args.chain_id
    ? `chain ${args.chain_id}`
    : args.fingerprint
    ? `fingerprint ${args.fingerprint}`
    : args.agent_id
    ? `agent ${args.agent_id}${args.last ? ` (last ${args.last})` : ""}`
    : `last ${args.last}`;

  try {
    const timeline = await client.fetchTimeline(params);
    const entries = (timeline.entries ?? timeline.timeline ?? []) as TimelineEntry[];
    return formatTimeline(entries, queryDesc);
  } catch (err) {
    return `Error: ${(err as Error).message}`;
  }
}
