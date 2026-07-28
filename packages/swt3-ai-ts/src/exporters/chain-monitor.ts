/**
 * SWT3 AI Witness SDK -- Exploit Chain Monitor Exporter.
 *
 * Reads WAL entries and chain enforcer violation history to produce
 * forensic timelines for incident response and auditor review.
 *
 * Usage:
 *   swt3 audit --format html
 *   swt3 audit --format json --wal-path /tmp/swt3-wal
 */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { ChainPolicyViolation } from "../types.js";

export interface ChainMonitorOptions {
  walDir?: string;
  tenantId?: string;
  agentId?: string;
  modelId?: string;
  clearingLevel?: number;
  violations?: readonly ChainPolicyViolation[];
  merkleRoot?: string;
}

interface WalEntry {
  seq: number;
  fingerprint: string;
  payload: Record<string, unknown>;
}

export interface TimelineEntry {
  seq: number;
  timestamp: number;
  fingerprint: string;
  procedureId: string;
  toolName?: string;
  modelId?: string;
  tokens?: number;
  isViolation: boolean;
  violationReason?: string;
}

export interface AuditReport {
  metadata: {
    generatedAt: string;
    sdkVersion: string;
    tenantId: string;
    agentId: string;
    modelId: string;
    clearingLevel: number;
    entryCount: number;
    violationCount: number;
    merkleRoot?: string;
  };
  timeline: TimelineEntry[];
  violations: ChainPolicyViolation[];
}

export class ChainMonitorExporter {
  private options: ChainMonitorOptions;

  constructor(options: ChainMonitorOptions = {}) {
    this.options = options;
  }

  private readWal(): WalEntry[] {
    const dir = this.options.walDir ?? join(tmpdir(), "swt3-wal");
    const tenantId = this.options.tenantId ?? "UNKNOWN";
    const safe = tenantId.replace(/[^a-zA-Z0-9_-]/g, "_");
    const walPath = join(dir, `${safe}.wal`);

    if (!existsSync(walPath)) return [];

    const raw = readFileSync(walPath, "utf-8");
    const entries: WalEntry[] = [];
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      try {
        entries.push(JSON.parse(line));
      } catch { /* skip corrupted lines */ }
    }
    return entries;
  }

  buildReport(): AuditReport {
    const entries = this.readWal();
    const violations = [...(this.options.violations ?? [])];

    const timeline: TimelineEntry[] = entries.map((e) => {
      const p = e.payload;
      const isChainEnforcer = p.provider === "chain-enforcer";
      return {
        seq: e.seq,
        timestamp: (p.fingerprint_timestamp_ms as number) ?? 0,
        fingerprint: e.fingerprint,
        procedureId: (p.procedure_id as string) ?? "unknown",
        toolName: (p.ai_model_id as string) ?? undefined,
        modelId: isChainEnforcer ? undefined : (p.ai_model_id as string) ?? undefined,
        tokens: ((p.ai_input_tokens as number) ?? 0) + ((p.ai_output_tokens as number) ?? 0) || undefined,
        isViolation: isChainEnforcer,
        violationReason: isChainEnforcer ? "Chain policy violation" : undefined,
      };
    });

    timeline.sort((a, b) => a.timestamp - b.timestamp);

    return {
      metadata: {
        generatedAt: new Date().toISOString(),
        sdkVersion: "0.6.1",
        tenantId: this.options.tenantId ?? "UNKNOWN",
        agentId: this.options.agentId ?? "UNKNOWN",
        modelId: this.options.modelId ?? "UNKNOWN",
        clearingLevel: this.options.clearingLevel ?? 1,
        entryCount: timeline.length,
        violationCount: violations.length + timeline.filter((t) => t.isViolation).length,
        merkleRoot: this.options.merkleRoot,
      },
      timeline,
      violations,
    };
  }

  exportJson(): string {
    return JSON.stringify(this.buildReport(), null, 2);
  }

  exportHtml(): string {
    const report = this.buildReport();
    const m = report.metadata;
    const ts = m.generatedAt.replace("T", " ").slice(0, 19);

    const timelineRows = report.timeline.map((t) => {
      const time = t.timestamp ? new Date(t.timestamp).toISOString().slice(11, 23) : "--";
      const status = t.isViolation
        ? '<span style="color:#EF4444">VIOLATION</span>'
        : '<span style="color:#4ADE80">OK</span>';
      const tool = t.toolName ? escapeHtml(t.toolName) : "--";
      const tokens = t.tokens ? String(t.tokens) : "--";
      const reason = t.violationReason ? `<br><span style="color:#EF4444;font-size:.75rem">${escapeHtml(t.violationReason)}</span>` : "";
      return `<tr><td>${t.seq}</td><td>${time}</td><td>${escapeHtml(t.procedureId)}</td><td>${tool}</td><td style="font-family:monospace;font-size:.8rem">${escapeHtml(t.fingerprint.slice(0, 12))}</td><td>${tokens}</td><td>${status}${reason}</td></tr>`;
    }).join("\n");

    const violationRows = report.violations.map((v) => {
      const time = v.timestamp ? new Date(v.timestamp).toISOString().slice(11, 23) : "--";
      return `<tr style="color:#EF4444"><td>${escapeHtml(v.rule)}</td><td>${escapeHtml(v.toolName)}</td><td>${escapeHtml(v.reason)}</td><td>${time}</td><td>${v.action}</td></tr>`;
    }).join("\n");

    const merkleSection = m.merkleRoot
      ? `<h2>Cryptographic Seal</h2><pre>Merkle Root: ${escapeHtml(m.merkleRoot)}</pre>`
      : "";

    const watermark = "Self-Signed / Unnotarized";

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SWT3 Exploit Chain Monitor</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#070504;color:#E0D9D1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:2.5rem;line-height:1.6}
.c{max-width:960px;margin:0 auto}
h1{color:#E8A87C;font-size:1.5rem;margin-bottom:.25rem}
h2{color:#E8A87C;font-size:1.1rem;margin:1.5rem 0 .75rem}
.meta{color:#6B7280;font-size:.8rem;margin-bottom:1.5rem}
.stats{display:flex;gap:2rem;margin:1rem 0}
.stat{text-align:center}
.stat .num{font-size:2rem;font-weight:800}
.stat .label{font-size:.75rem;color:#6B7280;text-transform:uppercase;letter-spacing:.1em}
.pass{color:#4ADE80}
.fail{color:#EF4444}
table{width:100%;border-collapse:collapse;margin:.75rem 0;font-size:.85rem}
th{text-align:left;padding:.5rem .75rem;color:#E8A87C;border-bottom:1px solid #222;font-size:.7rem;text-transform:uppercase;letter-spacing:.1em}
td{padding:.5rem .75rem;border-bottom:1px solid #151312}
pre{background:#111;padding:1rem;border-radius:8px;overflow-x:auto;font-size:.8rem;color:#9CA3AF;margin:.75rem 0;border:1px solid #222}
.sep{border:none;border-top:1px solid #222;margin:1.5rem 0}
.watermark{color:#6B7280;font-size:.75rem;margin-top:2.5rem;padding-top:1.5rem;border-top:1px solid #222;text-align:center}
.watermark .badge{display:inline-block;padding:.25rem .75rem;border:1px solid #FBBF24;color:#FBBF24;border-radius:4px;font-size:.7rem;font-weight:600;letter-spacing:.05em;margin-bottom:.5rem}
</style>
</head>
<body>
<div class="c">
<h1>SWT3 Exploit Chain Monitor</h1>
<p class="meta">Generated ${ts} UTC | SWT3 SDK v${escapeHtml(m.sdkVersion)} | Clearing Level ${m.clearingLevel}</p>

<div class="stats">
<div class="stat"><div class="num pass">${m.entryCount}</div><div class="label">Events</div></div>
<div class="stat"><div class="num ${m.violationCount > 0 ? "fail" : "pass"}">${m.violationCount}</div><div class="label">Violations</div></div>
</div>

<h2>Session</h2>
<table>
<tr><td style="color:#6B7280">Tenant</td><td>${escapeHtml(m.tenantId)}</td></tr>
<tr><td style="color:#6B7280">Agent</td><td>${escapeHtml(m.agentId)}</td></tr>
<tr><td style="color:#6B7280">Model</td><td>${escapeHtml(m.modelId)}</td></tr>
</table>

<h2>Timeline</h2>
${report.timeline.length > 0 ? `<table>
<tr><th>#</th><th>Time</th><th>Procedure</th><th>Tool</th><th>Fingerprint</th><th>Tokens</th><th>Status</th></tr>
${timelineRows}
</table>` : '<p style="color:#6B7280">No WAL entries found.</p>'}

${report.violations.length > 0 ? `<hr class="sep">
<h2>Chain Density Violations</h2>
<table>
<tr><th>Rule</th><th>Tool</th><th>Reason</th><th>Time</th><th>Action</th></tr>
${violationRows}
</table>` : ""}

${merkleSection}

<div class="watermark">
<div class="badge">${watermark}</div>
<p>SWT3 Protocol | Patent Pending | Apache 2.0</p>
<p>TeNova: Defining the AI Accountability Standard.</p>
<p style="margin-top:.5rem">This report was generated locally. No data was transmitted to external services.</p>
</div>
</div>
</body>
</html>`;
  }
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
