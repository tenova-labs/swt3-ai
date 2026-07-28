/**
 * SWT3 Reconstruct -- forensic timeline reconstruction.
 *
 * Run with:
 *   swt3 reconstruct --cycle CYCLE_ID
 *   swt3 reconstruct --agent AGENT_ID --last 1h
 *   swt3 reconstruct --fingerprint abc123def456
 *   swt3 reconstruct --chain LC-abc123def4567890
 *   swt3 reconstruct --last 1h
 *   swt3 reconstruct --json
 */

import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

// ── Colors ──

const isTTY = process.stdout.isTTY ?? false;
const RESET = isTTY ? "\x1b[0m" : "";
const BOLD = isTTY ? "\x1b[1m" : "";
const DIM = isTTY ? "\x1b[2m" : "";
const RED = isTTY ? "\x1b[31m" : "";
const GREEN = isTTY ? "\x1b[32m" : "";
const AMBER = isTTY ? "\x1b[33m" : "";
const CYAN = isTTY ? "\x1b[36m" : "";

const AGENT_COLORS = isTTY
  ? [CYAN, AMBER, GREEN, "\x1b[35m", "\x1b[34m", "\x1b[91m"]
  : ["", "", "", "", "", ""];

function agentColor(agentId: string): string {
  if (!agentId) return "";
  const sum = [...agentId].reduce((s, c) => s + c.charCodeAt(0), 0);
  return AGENT_COLORS[sum % AGENT_COLORS.length];
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
  "AI-GOV.1": "Governance Framework",
  "AI-RISK.1": "Risk Register",
  "AI-IMPACT.1": "Impact Assessment",
  "AI-LOG.1": "Logging Attestation",
  "AI-IR.1": "Incident Response",
};

function fmtTime(iso: string): string {
  try {
    return new Date(iso).toISOString().slice(11, 19);
  } catch {
    return iso.slice(0, 8);
  }
}

function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  const rem = Math.floor(s % 60);
  return `${m}m ${rem}s`;
}

function fmtCost(cents: number): string {
  if (cents < 0) return "unknown";
  return `$${(cents / 100).toFixed(2)}`;
}

function verdictColor(v: string): string {
  if (v === "PASS") return GREEN;
  if (v === "FAIL") return RED;
  return AMBER;
}

// ── Types ──

interface TimelineEntry {
  timestamp_server: string;
  timestamp_client: number;
  clock_skew_ms: number;
  agent_id: string | null;
  procedure_id: string;
  verdict: string;
  fingerprint: string;
  swt3_anchor: string;
  clearing_level: number;
  detail: Record<string, unknown>;
  is_drift: boolean;
  is_override: boolean;
  is_delegation: boolean;
  is_cost: boolean;
  is_violation: boolean;
}

interface ReconstructionResponse {
  query: { type: string; id: string };
  summary: {
    anchor_count: number;
    agent_count: number;
    agents: string[];
    duration_ms: number;
    start_time: string | null;
    end_time: string | null;
    total_tokens: number;
    total_cost_cents: number;
    has_failures: boolean;
    has_drift: boolean;
    has_override: boolean;
    cycle_complete: boolean;
    procedures_used: string[];
  };
  delegation_tree: {
    root_agent: string;
    grants: Array<{
      delegator: string;
      scope_hash: string;
      depth: number;
      cascade: boolean;
      time_bound_minutes: number;
      fingerprint: string;
      witnessed_at: string;
    }>;
  } | null;
  timeline: TimelineEntry[];
}

// ── Parse duration shorthand ──

function parseDuration(s: string): number {
  const val = parseInt(s);
  if (s.endsWith("h")) return val * 3600;
  if (s.endsWith("m")) return val * 60;
  if (s.endsWith("d")) return val * 86400;
  if (s.endsWith("s")) return val;
  return val;
}

function flagVal(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
}

// ── Render text ──

function renderText(data: ReconstructionResponse): string {
  const lines: string[] = [];
  const s = data.summary;

  lines.push("");
  lines.push(`  ${BOLD}RECONSTRUCTION:${RESET} ${data.query.id}`);
  if (s.start_time && s.end_time) {
    lines.push(
      `  ${DIM}Duration: ${fmtDuration(s.duration_ms)} | ` +
      `Agents: ${s.agent_count} | Anchors: ${s.anchor_count} | ` +
      `Cost: ${fmtCost(s.total_cost_cents)}${RESET}`,
    );
    const flags: string[] = [];
    if (s.has_failures) flags.push(`${RED}FAILURES${RESET}`);
    if (s.has_drift) flags.push(`${AMBER}DRIFT${RESET}`);
    if (s.has_override) flags.push(`${RED}OVERRIDE${RESET}`);
    if (flags.length > 0) {
      lines.push(`  ${DIM}Flags:${RESET} ${flags.join(" | ")}`);
    }
  }
  lines.push("");

  // Delegation tree
  const dt = data.delegation_tree;
  if (dt && dt.grants.length > 0) {
    lines.push(`  ${BOLD}Delegation Tree:${RESET}`);
    lines.push(`    ${agentColor(dt.root_agent)}${dt.root_agent}${RESET} ${DIM}(root)${RESET}`);
    for (const g of dt.grants) {
      const cas = g.cascade ? `${GREEN}cascade${RESET}` : `${DIM}no-cascade${RESET}`;
      const ttl = g.time_bound_minutes ? ` ${DIM}ttl=${g.time_bound_minutes}m${RESET}` : "";
      lines.push(`    +-- ${DIM}scope=${g.scope_hash.slice(0, 8)}...${RESET} depth=${g.depth} ${cas}${ttl}`);
    }
    lines.push("");
  }

  // Timeline
  for (const e of data.timeline) {
    const ts = fmtTime(e.timestamp_server);
    const proc = e.procedure_id;
    const label = PROC_LABELS[proc] ?? proc;
    const vc = verdictColor(e.verdict);
    const ag = e.agent_id
      ? `${agentColor(e.agent_id)}${e.agent_id.slice(0, 20).padEnd(20)}${RESET} `
      : `${DIM}${"".padEnd(20)}${RESET} `;
    const vStr = `${vc}${e.verdict.padEnd(4)}${RESET}`;
    const pStr = `${CYAN}${proc.padEnd(14)}${RESET}`;

    const d = e.detail;
    const parts: string[] = [];
    if (e.is_delegation) {
      parts.push(`scope=${String(d.scope_hash ?? "?").slice(0, 8)}...`);
      if (d.cascade_revocation) parts.push("cascade");
    } else if (e.is_cost) {
      parts.push(`${d.tokens_in ?? "?"} in + ${d.tokens_out ?? "?"} out`);
      if (typeof d.cost_cents === "number" && (d.cost_cents as number) >= 0) {
        parts.push(`$${((d.cost_cents as number) / 100).toFixed(2)}`);
      }
    } else if (e.is_drift) {
      parts.push(`${d.drift_metric ?? "?"} ${d.drift_value ?? "?"} > ${d.threshold ?? "?"}`);
      if (d.consequence_category) parts.push(`consequence: ${d.consequence_category}`);
    } else if (e.is_override) {
      parts.push(`trigger: ${d.override_trigger ?? "?"} | auth: ${d.authorization_level ?? "?"} | state: ${d.fallback_state ?? "?"}`);
    } else {
      if (d.model_id) {
        const mp = [d.model_id as string];
        if (d.tokens_in) mp.push(`${d.tokens_in}+${d.tokens_out} tok`);
        if (d.latency_ms) mp.push(`${d.latency_ms}ms`);
        parts.push(mp.join(" "));
      }
      if (d.tool_name) parts.push(`tool: ${d.tool_name}`);
    }
    const detailStr = parts.length > 0 ? ` ${DIM}(${parts.join(", ")})${RESET}` : "";
    const skewStr = e.clock_skew_ms > 2000 ? ` ${AMBER}[skew ${e.clock_skew_ms}ms]${RESET}` : "";

    lines.push(`  ${DIM}${ts}${RESET}  ${ag}${pStr} ${vStr}  ${label}${detailStr}${skewStr}`);

    if (e.is_drift) lines.push(`  ${"".padEnd(10)}${"".padEnd(20)}${AMBER}${"".padEnd(14)} ^^^^ DRIFT DETECTED${RESET}`);
    if (e.is_override) lines.push(`  ${"".padEnd(10)}${"".padEnd(20)}${RED}${"".padEnd(14)} ^^^^ OVERRIDE: cycle terminated${RESET}`);
    if (e.is_violation) lines.push(`  ${"".padEnd(10)}${"".padEnd(20)}${RED}${"".padEnd(14)} ^^^^ POLICY VIOLATION${RESET}`);
  }

  lines.push("");
  if (!s.cycle_complete && s.anchor_count > 0) {
    lines.push(`  ${AMBER}CYCLE INCOMPLETE${RESET} ${DIM}-- last anchor ${fmtTime(s.end_time ?? "")}, no terminal event recorded${RESET}`);
    lines.push("");
  }
  lines.push(`  ${DIM}Verify any anchor: swt3 verify <fingerprint>${RESET}`);
  lines.push("");

  return lines.join("\n");
}

// ── Render HTML ──

const CL_LABELS: Record<number, string> = { 0: "L0 Analytics", 1: "L1 Standard", 2: "L2 Sensitive", 3: "L3 Classified" };
const CL_COLORS: Record<number, string> = { 0: "#6b6b80", 1: "#00d4aa", 2: "#f0ad4e", 3: "#ff3b3b" };
const AGENT_HTML_COLORS = ["#22d3ee", "#fbbf24", "#34d399", "#a78bfa", "#60a5fa", "#fb7185"];

function esc(s: string | number | null | undefined): string {
  if (s == null) return "";
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function agentHtmlColor(agentId: string): string {
  if (!agentId) return "#6b6b80";
  const sum = [...agentId].reduce((s, c) => s + c.charCodeAt(0), 0);
  return AGENT_HTML_COLORS[sum % AGENT_HTML_COLORS.length];
}

function renderHtml(data: ReconstructionResponse, source: "api" | "local" = "api"): string {
  const s = data.summary;
  const generated = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  const lines: string[] = [];
  const p = (l: string) => lines.push(l);

  const css = `
:root {
  --bg:#060611;--surface:#0d0d1f;--border:rgba(0,212,170,0.12);
  --accent:#00d4aa;--accent-dim:rgba(0,212,170,0.6);
  --fail:#ff3b3b;--fail-dim:rgba(255,59,59,0.15);--warn:#f0ad4e;--pass:#22c55e;
  --text:#e0e0e8;--text-muted:#6b6b80;
  --mono:'SF Mono','Cascadia Code','Fira Code','Consolas',monospace;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--sans);background:var(--bg);color:var(--text);line-height:1.5;padding:40px;max-width:1000px;margin:0 auto}
h1{font-size:22px;font-weight:700;color:var(--accent);letter-spacing:-0.5px;margin-bottom:4px}
.subtitle{font-size:13px;color:var(--text-muted);font-family:var(--mono)}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:24px 0}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center}
.kpi-value{font-size:20px;font-weight:700;font-family:var(--mono);color:var(--accent)}
.kpi-label{font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1.5px;margin-top:2px}
.section{margin:28px 0}
.section-title{font-size:13px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.delegation{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;font-family:var(--mono);font-size:12px;line-height:2}
.del-root{color:var(--text)}.del-grant{margin-left:20px;color:var(--text-muted)}
.timeline-row{display:grid;grid-template-columns:70px 1fr;gap:0;border-left:2px solid rgba(255,255,255,0.08);padding:0;position:relative}
.timeline-row.drift{border-left-color:var(--warn);background:rgba(240,173,78,0.04)}
.timeline-row.override{border-left-color:var(--fail);background:rgba(255,59,59,0.04)}
.timeline-row.violation{background:rgba(255,59,59,0.03)}
.tl-time{font-family:var(--mono);font-size:11px;color:var(--text-muted);padding:10px 8px 10px 12px}
.tl-body{padding:10px 12px 10px 0;border-bottom:1px solid rgba(255,255,255,0.04)}
.tl-main{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.tl-agent{font-size:11px;font-family:var(--mono);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tl-proc{font-size:11px;font-family:var(--mono);color:var(--accent);font-weight:600}
.tl-verdict{font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;letter-spacing:0.5px}
.tl-verdict.pass{background:rgba(34,197,94,0.12);color:var(--pass)}
.tl-verdict.fail{background:rgba(255,59,59,0.12);color:var(--fail)}
.tl-label{font-size:11px;color:var(--text-muted)}.tl-detail{font-size:10px;color:var(--text-muted);opacity:0.7}
.tl-skew{font-size:9px;color:var(--warn);margin-left:auto}
.tl-marker{font-size:10px;font-weight:600;margin-top:4px;padding:2px 0}
.tl-marker.drift-marker{color:var(--warn)}.tl-marker.override-marker{color:var(--fail)}.tl-marker.violation-marker{color:var(--fail)}
.tl-expand{margin-top:8px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:6px;padding:10px 12px;font-size:10px;font-family:var(--mono)}
.tl-expand div{display:flex;gap:12px;padding:2px 0}.tl-expand .exp-label{color:var(--text-muted);min-width:100px}
.tl-expand .exp-value{color:var(--text);word-break:break-all}
.tl-expand a{color:var(--accent-dim);text-decoration:none}.tl-expand a:hover{color:var(--accent)}
.cl-badge{font-size:9px;font-family:var(--mono);padding:1px 5px;border-radius:3px;border:1px solid}
.warning-box{background:rgba(240,173,78,0.08);border:1px solid rgba(240,173,78,0.3);border-radius:6px;padding:10px 14px;font-size:11px;color:var(--warn);margin-top:16px}
.flag-badges{display:flex;gap:8px;margin:12px 0}
.flag-badge{font-size:10px;font-weight:600;padding:3px 8px;border-radius:4px}
.flag-badge.failures{background:var(--fail-dim);color:var(--fail)}
.flag-badge.drift-flag{background:rgba(240,173,78,0.15);color:var(--warn)}
.flag-badge.override-flag{background:var(--fail-dim);color:var(--fail)}
.legend{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0}
.legend-item{display:flex;align-items:center;gap:5px;font-size:11px}
.legend-dot{width:8px;height:8px;border-radius:50%}
.footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--border);font-size:10px;color:var(--text-muted);font-family:var(--mono);text-align:center}
.attestation-banner{background:rgba(240,173,78,0.08);border:1px solid rgba(240,173,78,0.3);border-radius:6px;padding:12px 16px;margin-bottom:24px;font-size:11px;line-height:1.6}
.attestation-banner strong{color:var(--warn)}.attestation-banner .attest-note{color:var(--text-muted);font-size:10px;margin-top:4px}
.dot{width:10px;height:10px;border-radius:50%;position:absolute;left:-6px;top:14px;border:2px solid}
.dot.pass-dot{background:rgba(34,197,94,0.2);border-color:rgba(34,197,94,0.5)}
.dot.fail-dot{background:rgba(255,59,59,0.2);border-color:rgba(255,59,59,0.5)}
.dot.drift-dot{background:rgba(240,173,78,0.2);border-color:rgba(240,173,78,0.5)}
.dot.override-dot{background:rgba(255,59,59,0.3);border-color:rgba(255,59,59,0.6)}
@media print{
  body{background:#fff;color:#111;padding:20px}
  :root{--bg:#fff;--surface:#f8f8f8;--border:#ddd;--text:#111;--text-muted:#666;--accent:#007a5e;--accent-dim:#007a5e;--fail:#cc0000;--warn:#b87900;--pass:#1a7a3a}
  .tl-expand{background:#f5f5f5;border-color:#ddd}
  .timeline-row.drift{background:rgba(240,173,78,0.08)}.timeline-row.override{background:rgba(255,59,59,0.06)}
}`;

  p(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`);
  p(`<title>SWT3 Reconstruction: ${esc(data.query.id)}</title><style>${css}</style></head><body>`);

  // Header
  p(`<h1>Forensic Timeline Reconstruction</h1>`);
  p(`<div class="subtitle">${esc(data.query.type)}: ${esc(data.query.id)}</div>`);
  p(`<div class="subtitle">Generated ${generated}</div>`);

  // Attestation Banner
  p(`<div class="attestation-banner">`);
  if (source === "local") {
    p(`<strong>Self-Attested Export</strong> -- This report was reconstructed from the local witness log (WAL). `);
    p(`Anchors have not been verified against the server ledger. `);
    p(`For verified timelines, connect to the SWT3 endpoint or request an <a href="https://sovereign.tenova.io" style="color:var(--accent)">Audit Portal</a> share link.`);
  } else {
    p(`<strong>Client-Generated Export</strong> -- Each anchor in this report was retrieved from the SWT3 compliance ledger and can be independently verified. `);
    p(`This HTML document is a convenience export generated by the system owner -- it is not a signed audit artifact. `);
    p(`For an interactive, auditor-authenticated timeline, request an <a href="https://sovereign.tenova.io" style="color:var(--accent)">Audit Portal</a> share link from the system owner.`);
  }
  p(`</div>`);

  // Flags
  if (s.has_failures || s.has_drift || s.has_override) {
    p(`<div class="flag-badges">`);
    if (s.has_failures) p(`<span class="flag-badge failures">FAILURES</span>`);
    if (s.has_drift) p(`<span class="flag-badge drift-flag">DRIFT</span>`);
    if (s.has_override) p(`<span class="flag-badge override-flag">OVERRIDE</span>`);
    p(`</div>`);
  }

  // KPIs
  const statusText = s.has_override ? "OVERRIDE" : s.has_drift ? "DRIFT" : s.cycle_complete ? "COMPLETE" : "INCOMPLETE";
  const statusColor = s.has_override ? "var(--fail)" : s.has_drift ? "var(--warn)" : s.cycle_complete ? "var(--pass)" : "var(--warn)";

  p(`<div class="kpi-grid">`);
  p(`<div class="kpi"><div class="kpi-value">${fmtDuration(s.duration_ms)}</div><div class="kpi-label">Duration</div></div>`);
  p(`<div class="kpi"><div class="kpi-value">${s.anchor_count}</div><div class="kpi-label">Anchors</div></div>`);
  p(`<div class="kpi"><div class="kpi-value">${s.agent_count}</div><div class="kpi-label">Agents</div></div>`);
  p(`<div class="kpi"><div class="kpi-value">${s.total_tokens.toLocaleString()}</div><div class="kpi-label">Tokens</div></div>`);
  p(`<div class="kpi"><div class="kpi-value">${fmtCost(s.total_cost_cents)}</div><div class="kpi-label">Cost</div></div>`);
  p(`<div class="kpi"><div class="kpi-value" style="color:${statusColor}">${statusText}</div><div class="kpi-label">Status</div></div>`);
  p(`</div>`);

  // Agent Legend
  if (s.agents.length > 0) {
    p(`<div class="legend">`);
    for (const ag of s.agents) {
      const c = agentHtmlColor(ag);
      const short = ag.length > 24 ? ag.slice(0, 24) + "..." : ag;
      p(`<span class="legend-item"><span class="legend-dot" style="background:${c}"></span><span style="color:${c}">${esc(short)}</span></span>`);
    }
    p(`</div>`);
  }

  // Delegation Tree
  const dt = data.delegation_tree;
  if (dt && dt.grants.length > 0) {
    p(`<div class="section"><div class="section-title">Delegation Tree</div><div class="delegation">`);
    const rc = agentHtmlColor(dt.root_agent);
    p(`<div class="del-root"><span style="color:${rc}">${esc(dt.root_agent)}</span> <span style="color:var(--text-muted)">(root)</span></div>`);
    for (const g of dt.grants) {
      const cas = g.cascade ? `<span style="color:var(--pass)">cascade</span>` : `<span style="color:var(--text-muted)">no-cascade</span>`;
      const ttl = g.time_bound_minutes ? ` <span style="color:var(--text-muted)">ttl=${g.time_bound_minutes}m</span>` : "";
      p(`<div class="del-grant">+-- scope=${esc(g.scope_hash.slice(0, 8))}... depth=${g.depth} ${cas}${ttl}</div>`);
    }
    p(`</div></div>`);
  }

  // Timeline
  p(`<div class="section"><div class="section-title">Timeline</div>`);

  for (const e of data.timeline) {
    const ts = fmtTime(e.timestamp_server);
    const proc = e.procedure_id;
    const label = PROC_LABELS[proc] ?? proc;
    const d = e.detail;

    let rowClass = "timeline-row";
    if (e.is_override) rowClass += " override";
    else if (e.is_drift) rowClass += " drift";
    else if (e.is_violation) rowClass += " violation";

    let dotClass = "dot";
    if (e.verdict === "PASS") dotClass += " pass-dot";
    if (e.verdict === "FAIL") dotClass += " fail-dot";
    if (e.is_drift) dotClass += " drift-dot";
    if (e.is_override) dotClass += " override-dot";

    const verdictClass = e.verdict === "PASS" ? "pass" : e.verdict === "FAIL" ? "fail" : "";

    // Detail
    const parts: string[] = [];
    if (e.is_delegation) {
      parts.push(`scope=${esc(String(d.scope_hash ?? "?").slice(0, 8))}... depth=${d.depth ?? "?"}`);
      if (d.cascade_revocation) parts.push("cascade");
    } else if (e.is_cost) {
      parts.push(`${d.tokens_in ?? "?"}+${d.tokens_out ?? "?"} tok`);
      if (typeof d.cost_cents === "number" && (d.cost_cents as number) >= 0) parts.push(`$${((d.cost_cents as number) / 100).toFixed(2)}`);
    } else if (e.is_drift) {
      parts.push(`${d.drift_metric ?? "?"} ${d.drift_value ?? "?"} &gt; ${d.threshold ?? "?"}`);
      if (d.consequence_category) parts.push(`consequence: ${esc(String(d.consequence_category))}`);
    } else if (e.is_override) {
      parts.push(`trigger: ${esc(String(d.override_trigger ?? "?"))}`);
      parts.push(`auth: ${esc(String(d.authorization_level ?? "?"))}`);
      parts.push(`state: ${esc(String(d.fallback_state ?? "?"))}`);
    } else {
      if (d.model_id) {
        const mp = [esc(String(d.model_id))];
        if (d.tokens_in) mp.push(`${d.tokens_in}+${d.tokens_out ?? 0} tok`);
        if (d.latency_ms) mp.push(`${d.latency_ms}ms`);
        parts.push(mp.join(" "));
      }
      if (d.tool_name) parts.push(`tool: ${esc(String(d.tool_name))}`);
    }
    const detailStr = parts.length > 0 ? `<span class="tl-detail">(${parts.join(", ")})</span>` : "";
    const skewStr = e.clock_skew_ms > 2000 ? `<span class="tl-skew">[skew ${e.clock_skew_ms}ms]</span>` : "";

    let agentStr = "";
    if (e.agent_id) {
      const ac = agentHtmlColor(e.agent_id);
      agentStr = `<span class="tl-agent" style="color:${ac}">${esc(e.agent_id.slice(0, 20))}</span>`;
    }

    const cl = e.clearing_level;
    const clColor = CL_COLORS[cl] ?? "#6b6b80";
    const clLabel = CL_LABELS[cl] ?? `L${cl}`;
    const fp = e.fingerprint;
    const verifyUrl = `https://sovereign.tenova.io/verify?fp=${fp}`;

    p(`<div class="${rowClass}">`);
    p(`  <div class="${dotClass}"></div>`);
    p(`  <div class="tl-time">${esc(ts)}</div>`);
    p(`  <div class="tl-body">`);
    p(`    <div class="tl-main">${agentStr}<span class="tl-proc">${esc(proc)}</span><span class="tl-verdict ${verdictClass}">${esc(e.verdict)}</span><span class="tl-label">${esc(label)}</span>${detailStr}<span class="cl-badge" style="color:${clColor};border-color:${clColor}">${clLabel}</span>${skewStr}</div>`);
    if (e.is_drift) p(`    <div class="tl-marker drift-marker">&#9650; DRIFT DETECTED</div>`);
    if (e.is_override) p(`    <div class="tl-marker override-marker">&#9650; OVERRIDE: cycle terminated</div>`);
    if (e.is_violation) p(`    <div class="tl-marker violation-marker">&#9650; POLICY VIOLATION</div>`);
    p(`    <div class="tl-expand">`);
    p(`      <div><span class="exp-label">Anchor:</span><span class="exp-value">${esc(e.swt3_anchor)}</span></div>`);
    p(`      <div><span class="exp-label">Fingerprint:</span><span class="exp-value" style="color:var(--accent)">${esc(fp)}</span></div>`);
    p(`      <div><span class="exp-label">Clearing:</span><span class="exp-value">${clLabel}</span></div>`);
    for (const [k, v] of Object.entries(d)) {
      p(`      <div><span class="exp-label">${esc(k)}:</span><span class="exp-value">${esc(String(v))}</span></div>`);
    }
    p(`      <div><a href="${verifyUrl}" target="_blank" rel="noopener">Verify independently &#8594;</a></div>`);
    p(`    </div>`);
    p(`  </div>`);
    p(`</div>`);
  }

  // Incomplete cycle warning
  if (!s.cycle_complete && s.anchor_count > 0) {
    p(`<div class="warning-box">CYCLE INCOMPLETE -- last anchor ${fmtTime(s.end_time ?? "")}, no terminal event recorded</div>`);
  }
  p(`</div>`);

  // Footer with content hash
  const bodyForHash = lines.join("\n");
  const contentHash = createHash("sha256").update(bodyForHash).digest("hex").slice(0, 12);
  const dataSource = source === "local" ? "Local WAL (self-attested)" : "Ledger API (server-verified anchors)";
  p(`<div class="footer">${s.anchor_count} anchors, ${s.procedures_used.length} procedures<br>Data source: ${dataSource}<br>Content hash: ${contentHash}<br>SWT3 Sovereign Engine -- sovereign.tenova.io</div>`);
  p(`</body></html>`);
  return lines.join("\n");
}

// ── Entry point ──

export async function handleReconstruct(args: string[]): Promise<void> {
  const cycleId = flagVal(args, "--cycle");
  const agentId = flagVal(args, "--agent");
  const fingerprint = flagVal(args, "--fingerprint");
  const chainId = flagVal(args, "--chain");
  const lastStr = flagVal(args, "--last");
  const useJson = args.includes("--json");
  const useHtml = args.includes("--html");
  const outputPath = flagVal(args, "--output");

  if (!cycleId && !agentId && !fingerprint && !chainId && !lastStr) {
    console.error(`${RED}Error: Specify --cycle, --agent, --fingerprint, --chain, or --last${RESET}`);
    console.log(`${DIM}Examples:${RESET}`);
    console.log(`  swt3 reconstruct --cycle cycle-2026-07-21-001`);
    console.log(`  swt3 reconstruct --agent orchestrator-main --last 1h`);
    console.log(`  swt3 reconstruct --fingerprint a1b2c3d4e5f6`);
    console.log(`  swt3 reconstruct --chain LC-abc123def4567890`);
    console.log(`  swt3 reconstruct --last 30m`);
    console.log(`  swt3 reconstruct --cycle CYCLE_ID --html`);
    console.log(`  swt3 reconstruct --cycle CYCLE_ID --html --output report.html`);
    process.exit(1);
  }

  const endpoint = process.env.SWT3_ENDPOINT ?? "";
  const apiKey = process.env.SWT3_API_KEY ?? "";

  if (!endpoint || !apiKey) {
    console.error(`${RED}Error: SWT3_ENDPOINT and SWT3_API_KEY environment variables required${RESET}`);
    process.exit(1);
  }

  const params = new URLSearchParams();
  if (cycleId) params.set("cycle_id", cycleId);
  if (agentId) params.set("agent_id", agentId);
  if (fingerprint) params.set("fingerprint", fingerprint);
  if (chainId) params.set("chain_id", chainId);
  if (lastStr) {
    const secs = parseDuration(lastStr);
    const from = new Date(Date.now() - secs * 1000).toISOString();
    params.set("from", from);
  }

  const url = `${endpoint.replace(/\/$/, "")}/api/v1/reconstruct?${params.toString()}`;

  try {
    const resp = await fetch(url, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: "application/json",
      },
    });

    if (!resp.ok) {
      const body = await resp.text();
      console.error(`${RED}Error: API returned ${resp.status}: ${body}${RESET}`);
      process.exit(1);
    }

    const data = (await resp.json()) as ReconstructionResponse;

    if (data.summary.anchor_count === 0) {
      console.log(`\n  ${DIM}No anchors found for query: ${data.query.id}${RESET}\n`);
      process.exit(0);
    }

    if (useHtml) {
      const html = renderHtml(data);
      const dest = outputPath ?? `reconstruct-${data.query.id.replace(/\//g, "-")}-${Math.floor(Date.now() / 1000)}.html`;
      writeFileSync(dest, html, "utf-8");
      console.log(`  ${GREEN}HTML written to ${dest}${RESET}`);
    } else if (useJson) {
      console.log(JSON.stringify(data, null, 2));
    } else {
      console.log(renderText(data));
    }
  } catch (err) {
    console.error(`${RED}Error: Could not reach reconstruction API: ${err}${RESET}`);
    process.exit(1);
  }
}
