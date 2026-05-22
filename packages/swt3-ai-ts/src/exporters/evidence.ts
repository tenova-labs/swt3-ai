/**
 * SWT3 AI Witness SDK -- Evidence Bundle Exporter.
 *
 * Produces self-contained evidence bundles for sandbox environments
 * and auditor handoff. Reads WAL entries and Merkle session roots,
 * applies a watermark tier (demo/connected/sovereign), and exports
 * as JSON or HTML.
 *
 * Patent pending.
 */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { SessionRoot } from "../merkle.js";

export interface EvidenceBundleOptions {
  walDir?: string;
  tenantId?: string;
  agentId?: string;
  clearingLevel?: number;
  apiKey?: string;
  signingKey?: string;
  hasHardwareAttestation?: boolean;
  merkleRoots?: SessionRoot[];
}

export interface EvidenceBundleMetadata {
  generatedAt: string;
  sdkVersion: string;
  tenantId: string;
  agentId: string;
  clearingLevel: number;
  anchorCount: number;
  watermark: "demo" | "connected" | "sovereign";
  exportTimestamp: number;
}

export interface EvidenceBundle {
  metadata: EvidenceBundleMetadata;
  anchors: Array<{
    seq: number;
    fingerprint: string;
    procedureId: string;
    factorA: number;
    factorB: number;
    factorC: number;
    epoch: number;
    timestampMs: number;
  }>;
  merkleRoots: Array<{
    root: string;
    count: number;
    timestamp: string;
  }>;
}

interface WalEntry {
  seq: number;
  fingerprint: string;
  payload: Record<string, unknown>;
}

export class EvidenceExporter {
  private options: EvidenceBundleOptions;

  constructor(options: EvidenceBundleOptions = {}) {
    this.options = options;
  }

  private computeWatermark(): "demo" | "connected" | "sovereign" {
    if (this.options.signingKey && this.options.hasHardwareAttestation) {
      return "sovereign";
    }
    if (this.options.apiKey) {
      return "connected";
    }
    return "demo";
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

  buildBundle(): EvidenceBundle {
    const entries = this.readWal();
    const watermark = this.computeWatermark();

    const anchors = entries.map((e) => {
      const p = e.payload;
      return {
        seq: e.seq,
        fingerprint: e.fingerprint,
        procedureId: (p.procedure_id as string) ?? "unknown",
        factorA: (p.factor_a as number) ?? 0,
        factorB: (p.factor_b as number) ?? 0,
        factorC: (p.factor_c as number) ?? 0,
        epoch: (p.anchor_epoch as number) ?? 0,
        timestampMs: (p.fingerprint_timestamp_ms as number) ?? 0,
      };
    });

    anchors.sort((a, b) => a.timestampMs - b.timestampMs);

    const merkleRoots = (this.options.merkleRoots ?? []).map((r) => ({
      root: r.root,
      count: r.count,
      timestamp: r.timestamp,
    }));

    return {
      metadata: {
        generatedAt: new Date().toISOString(),
        sdkVersion: "0.5.3",
        tenantId: this.options.tenantId ?? "UNKNOWN",
        agentId: this.options.agentId ?? "UNKNOWN",
        clearingLevel: this.options.clearingLevel ?? 1,
        anchorCount: anchors.length,
        watermark,
        exportTimestamp: Date.now(),
      },
      anchors,
      merkleRoots,
    };
  }

  exportJson(): string {
    return JSON.stringify(this.buildBundle(), null, 2);
  }

  exportHtml(): string {
    const bundle = this.buildBundle();
    const m = bundle.metadata;
    const ts = m.generatedAt.replace("T", " ").slice(0, 19);

    const watermarkColors: Record<string, { bg: string; fg: string; label: string }> = {
      demo: { bg: "#FEF3C7", fg: "#92400E", label: "DEMO / UNVERIFIED" },
      connected: { bg: "#D1FAE5", fg: "#065F46", label: "CONNECTED" },
      sovereign: { bg: "#FEF9C3", fg: "#854D0E", label: "SOVEREIGN" },
    };
    const wm = watermarkColors[m.watermark];

    const anchorRows = bundle.anchors.map((a) => {
      const time = a.timestampMs ? new Date(a.timestampMs).toISOString().slice(11, 23) : "--";
      return `<tr><td>${a.seq}</td><td>${time}</td><td>${esc(a.procedureId)}</td><td style="font-family:monospace;font-size:.8rem">${esc(a.fingerprint)}</td><td>${a.factorA}</td><td>${a.factorB}</td><td>${a.factorC}</td></tr>`;
    }).join("\n");

    const merkleSection = bundle.merkleRoots.length > 0
      ? `<h2>Merkle Session Roots</h2><table><tr><th>Root</th><th>Anchors</th><th>Timestamp</th></tr>${
        bundle.merkleRoots.map((r) =>
          `<tr><td style="font-family:monospace;font-size:.75rem">${esc(r.root.slice(0, 24))}...</td><td>${r.count}</td><td>${esc(r.timestamp.slice(0, 19))}</td></tr>`
        ).join("\n")
      }</table>`
      : "";

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SWT3 Evidence Bundle</title>
<style>
  body{background:#0F172A;color:#E2E8F0;font-family:system-ui,sans-serif;margin:0;padding:2rem}
  h1{color:#F8FAFC;font-size:1.5rem}
  h2{color:#94A3B8;font-size:1.1rem;margin-top:2rem}
  table{border-collapse:collapse;width:100%;margin:.5rem 0}
  th,td{border:1px solid #334155;padding:.4rem .6rem;text-align:left;font-size:.85rem}
  th{background:#1E293B;color:#94A3B8}
  .watermark{display:inline-block;padding:.3rem .8rem;border-radius:4px;font-weight:700;font-size:.9rem;margin-bottom:1rem;background:${wm.bg};color:${wm.fg}}
  .meta{color:#94A3B8;font-size:.85rem;margin:.2rem 0}
  pre{background:#1E293B;padding:1rem;border-radius:4px;font-size:.8rem;overflow-x:auto}
  .footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #334155;color:#64748B;font-size:.75rem}
</style>
</head>
<body>
<h1>SWT3 Evidence Bundle</h1>
<div class="watermark">${wm.label}</div>
<p class="meta">Generated: ${ts} UTC</p>
<p class="meta">Tenant: ${esc(m.tenantId)} | Agent: ${esc(m.agentId)} | Clearing Level: ${m.clearingLevel}</p>
<p class="meta">Anchors: ${m.anchorCount} | Merkle Roots: ${bundle.merkleRoots.length}</p>

<h2>Witness Anchors</h2>
${bundle.anchors.length > 0 ? `<table>
<tr><th>#</th><th>Time</th><th>Procedure</th><th>Fingerprint</th><th>A</th><th>B</th><th>C</th></tr>
${anchorRows}
</table>` : "<p>No anchors in WAL.</p>"}

${merkleSection}

<div class="footer">
  <p>SWT3 AI Witness SDK v${esc(m.sdkVersion)} | ${wm.label} | Patent pending</p>
  <p>Verify any fingerprint: echo -n "WITNESS:{tenant}:{proc}:{a}:{b}:{c}:{ts_ms}" | sha256sum | cut -c1-12</p>
</div>
</body>
</html>`;
  }
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
