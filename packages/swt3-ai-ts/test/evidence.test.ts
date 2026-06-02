/**
 * SWT3 AI Witness SDK -- Evidence Bundle Exporter Tests.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EvidenceExporter } from "../src/exporters/evidence.js";
import type { EvidenceBundle } from "../src/exporters/evidence.js";

function makeWalDir(): string {
  return mkdtempSync(join(tmpdir(), "swt3-evidence-test-"));
}

function writeWalEntries(walDir: string, tenantId: string, entries: object[]): void {
  const safe = tenantId.replace(/[^a-zA-Z0-9_-]/g, "_");
  const walPath = join(walDir, `${safe}.wal`);
  const content = entries.map((e) => JSON.stringify(e)).join("\n") + "\n";
  writeFileSync(walPath, content, "utf-8");
}

describe("EvidenceExporter", () => {
  let walDir: string;

  beforeEach(() => {
    walDir = makeWalDir();
  });

  afterEach(() => {
    rmSync(walDir, { recursive: true, force: true });
  });

  // -- Watermark tier logic --

  it("returns demo watermark with no credentials", () => {
    const exporter = new EvidenceExporter({ walDir, tenantId: "T1" });
    const bundle = exporter.buildBundle();
    expect(bundle.metadata.watermark).toBe("demo");
  });

  it("returns connected watermark with API key", () => {
    const exporter = new EvidenceExporter({ walDir, tenantId: "T1", apiKey: "axm_test" });
    const bundle = exporter.buildBundle();
    expect(bundle.metadata.watermark).toBe("connected");
  });

  it("returns sovereign watermark with signing key + hardware attestation", () => {
    const exporter = new EvidenceExporter({
      walDir, tenantId: "T1", signingKey: "sk_test", hasHardwareAttestation: true,
    });
    const bundle = exporter.buildBundle();
    expect(bundle.metadata.watermark).toBe("sovereign");
  });

  it("returns connected (not sovereign) with signing key but no hardware attestation", () => {
    const exporter = new EvidenceExporter({
      walDir, tenantId: "T1", apiKey: "axm_test", signingKey: "sk_test",
    });
    const bundle = exporter.buildBundle();
    expect(bundle.metadata.watermark).toBe("connected");
  });

  // -- Empty WAL --

  it("produces empty bundle when WAL does not exist", () => {
    const exporter = new EvidenceExporter({ walDir, tenantId: "NONEXISTENT" });
    const bundle = exporter.buildBundle();
    expect(bundle.anchors).toHaveLength(0);
    expect(bundle.metadata.anchorCount).toBe(0);
  });

  // -- WAL reading --

  it("reads WAL entries and populates anchors", () => {
    const entries = [
      {
        seq: 1, fingerprint: "abc123def456",
        payload: { procedure_id: "AI-INF.1", factor_a: 0.9, factor_b: 100, factor_c: 50, anchor_epoch: 1, fingerprint_timestamp_ms: 1000 },
      },
      {
        seq: 2, fingerprint: "def789abc012",
        payload: { procedure_id: "AI-GRD.1", factor_a: 1, factor_b: 1, factor_c: 1, anchor_epoch: 2, fingerprint_timestamp_ms: 2000 },
      },
    ];
    writeWalEntries(walDir, "T1", entries);

    const exporter = new EvidenceExporter({ walDir, tenantId: "T1" });
    const bundle = exporter.buildBundle();
    expect(bundle.anchors).toHaveLength(2);
    expect(bundle.metadata.anchorCount).toBe(2);
    expect(bundle.anchors[0].procedureId).toBe("AI-INF.1");
    expect(bundle.anchors[1].procedureId).toBe("AI-GRD.1");
  });

  it("sorts anchors by timestamp", () => {
    const entries = [
      { seq: 1, fingerprint: "aaa", payload: { procedure_id: "P2", fingerprint_timestamp_ms: 5000 } },
      { seq: 2, fingerprint: "bbb", payload: { procedure_id: "P1", fingerprint_timestamp_ms: 1000 } },
    ];
    writeWalEntries(walDir, "T1", entries);

    const exporter = new EvidenceExporter({ walDir, tenantId: "T1" });
    const bundle = exporter.buildBundle();
    expect(bundle.anchors[0].procedureId).toBe("P1");
    expect(bundle.anchors[1].procedureId).toBe("P2");
  });

  it("skips corrupted WAL lines", () => {
    const safe = "T1";
    const walPath = join(walDir, `${safe}.wal`);
    writeFileSync(walPath, '{"seq":1,"fingerprint":"ok","payload":{"procedure_id":"X"}}\nNOT JSON\n{"seq":2,"fingerprint":"ok2","payload":{"procedure_id":"Y"}}\n', "utf-8");

    const exporter = new EvidenceExporter({ walDir, tenantId: "T1" });
    const bundle = exporter.buildBundle();
    expect(bundle.anchors).toHaveLength(2);
  });

  // -- Merkle roots --

  it("includes merkle roots in bundle", () => {
    const roots = [
      { root: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", count: 5, timestamp: "2026-05-20T00:00:00Z" },
    ];
    const exporter = new EvidenceExporter({ walDir, tenantId: "T1", merkleRoots: roots });
    const bundle = exporter.buildBundle();
    expect(bundle.merkleRoots).toHaveLength(1);
    expect(bundle.merkleRoots[0].count).toBe(5);
  });

  // -- Metadata --

  it("populates metadata fields", () => {
    const exporter = new EvidenceExporter({
      walDir, tenantId: "MY_TENANT", agentId: "agent-1", clearingLevel: 2,
    });
    const bundle = exporter.buildBundle();
    expect(bundle.metadata.tenantId).toBe("MY_TENANT");
    expect(bundle.metadata.agentId).toBe("agent-1");
    expect(bundle.metadata.clearingLevel).toBe(2);
    expect(bundle.metadata.sdkVersion).toBe("0.5.3");
    expect(bundle.metadata.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(bundle.metadata.exportTimestamp).toBeGreaterThan(0);
  });

  // -- JSON export --

  it("exportJson returns valid JSON with camelCase keys", () => {
    const entries = [
      { seq: 1, fingerprint: "fp1", payload: { procedure_id: "AI-INF.1", factor_a: 1, factor_b: 2, factor_c: 3, anchor_epoch: 1, fingerprint_timestamp_ms: 1000 } },
    ];
    writeWalEntries(walDir, "T1", entries);

    const exporter = new EvidenceExporter({ walDir, tenantId: "T1" });
    const json = exporter.exportJson();
    const parsed = JSON.parse(json);
    expect(parsed.metadata.tenantId).toBe("T1");
    expect(parsed.anchors[0].procedureId).toBe("AI-INF.1");
    expect(parsed.anchors[0].factorA).toBe(1);
  });

  // -- HTML export --

  it("exportHtml returns valid HTML with watermark", () => {
    const exporter = new EvidenceExporter({ walDir, tenantId: "T1" });
    const html = exporter.exportHtml();
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("DEMO / UNVERIFIED");
    expect(html).toContain("SWT3 Evidence Bundle");
  });

  it("exportHtml includes anchor rows", () => {
    const entries = [
      { seq: 1, fingerprint: "fp_test", payload: { procedure_id: "AI-INF.1", factor_a: 1, factor_b: 0, factor_c: 0, anchor_epoch: 1, fingerprint_timestamp_ms: 1000 } },
    ];
    writeWalEntries(walDir, "T1", entries);

    const exporter = new EvidenceExporter({ walDir, tenantId: "T1" });
    const html = exporter.exportHtml();
    expect(html).toContain("AI-INF.1");
    expect(html).toContain("fp_test");
  });

  it("exportHtml shows connected watermark", () => {
    const exporter = new EvidenceExporter({ walDir, tenantId: "T1", apiKey: "axm_test" });
    const html = exporter.exportHtml();
    expect(html).toContain("CONNECTED");
  });

  it("exportHtml escapes HTML entities", () => {
    const exporter = new EvidenceExporter({ walDir, tenantId: "<script>alert(1)</script>" });
    const html = exporter.exportHtml();
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });

  // -- Default values --

  it("defaults to UNKNOWN for missing tenant and agent", () => {
    const exporter = new EvidenceExporter({ walDir });
    const bundle = exporter.buildBundle();
    expect(bundle.metadata.tenantId).toBe("UNKNOWN");
    expect(bundle.metadata.agentId).toBe("UNKNOWN");
  });
});
