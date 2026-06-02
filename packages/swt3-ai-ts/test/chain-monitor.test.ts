/**
 * Chain Monitor exporter tests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ChainMonitorExporter } from "../src/exporters/chain-monitor.js";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function createMockWal(dir: string, tenantId: string, entries: object[]): void {
  const safe = tenantId.replace(/[^a-zA-Z0-9_-]/g, "_");
  const walPath = join(dir, `${safe}.wal`);
  const content = entries.map((e) => JSON.stringify(e)).join("\n") + "\n";
  writeFileSync(walPath, content, "utf-8");
}

describe("ChainMonitorExporter", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "swt3-test-wal-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("builds empty report when no WAL exists", () => {
    const exporter = new ChainMonitorExporter({ walDir: tmpDir, tenantId: "TEST" });
    const report = exporter.buildReport();
    expect(report.timeline).toHaveLength(0);
    expect(report.metadata.entryCount).toBe(0);
  });

  it("reads WAL entries into timeline", () => {
    createMockWal(tmpDir, "TEST", [
      { seq: 1, fingerprint: "abc123def456", payload: { procedure_id: "AI-INF.1", fingerprint_timestamp_ms: 1700000000000 } },
      { seq: 2, fingerprint: "def456abc789", payload: { procedure_id: "AI-TOOL.1", fingerprint_timestamp_ms: 1700000001000, ai_model_id: "search_db" } },
    ]);
    const exporter = new ChainMonitorExporter({ walDir: tmpDir, tenantId: "TEST" });
    const report = exporter.buildReport();
    expect(report.timeline).toHaveLength(2);
    expect(report.timeline[0].procedureId).toBe("AI-INF.1");
    expect(report.timeline[1].toolName).toBe("search_db");
    expect(report.metadata.entryCount).toBe(2);
  });

  it("flags chain-enforcer entries as violations", () => {
    createMockWal(tmpDir, "TEST", [
      { seq: 1, fingerprint: "abc123", payload: { procedure_id: "AI-CHAIN.1", provider: "chain-enforcer", fingerprint_timestamp_ms: 1700000000000 } },
    ]);
    const exporter = new ChainMonitorExporter({ walDir: tmpDir, tenantId: "TEST" });
    const report = exporter.buildReport();
    expect(report.timeline[0].isViolation).toBe(true);
    expect(report.metadata.violationCount).toBe(1);
  });

  it("includes passed violations in report", () => {
    const exporter = new ChainMonitorExporter({
      walDir: tmpDir,
      tenantId: "TEST",
      violations: [
        { rule: "blocklist", toolName: "shell_exec", action: "blocked", reason: "Blocked", timestamp: Date.now() },
      ],
    });
    const report = exporter.buildReport();
    expect(report.violations).toHaveLength(1);
    expect(report.metadata.violationCount).toBe(1);
  });

  it("exportJson produces valid JSON", () => {
    const exporter = new ChainMonitorExporter({ walDir: tmpDir, tenantId: "TEST" });
    const json = exporter.exportJson();
    const parsed = JSON.parse(json);
    expect(parsed.metadata).toBeDefined();
    expect(parsed.timeline).toBeDefined();
    expect(parsed.violations).toBeDefined();
  });

  it("exportHtml produces HTML with required sections", () => {
    createMockWal(tmpDir, "TEST", [
      { seq: 1, fingerprint: "abc123def456", payload: { procedure_id: "AI-INF.1", fingerprint_timestamp_ms: 1700000000000 } },
    ]);
    const exporter = new ChainMonitorExporter({ walDir: tmpDir, tenantId: "TEST", agentId: "agent-1" });
    const html = exporter.exportHtml();
    expect(html).toContain("SWT3 Exploit Chain Monitor");
    expect(html).toContain("Timeline");
    expect(html).toContain("Self-Signed / Unnotarized");
    expect(html).toContain("agent-1");
    expect(html).toContain("AI-INF.1");
  });

  it("exportHtml includes merkle root when provided", () => {
    const exporter = new ChainMonitorExporter({
      walDir: tmpDir,
      tenantId: "TEST",
      merkleRoot: "9f8e7d6c5b4a3f2e",
    });
    const html = exporter.exportHtml();
    expect(html).toContain("Cryptographic Seal");
    expect(html).toContain("9f8e7d6c5b4a3f2e");
  });

  it("sorts timeline by timestamp", () => {
    createMockWal(tmpDir, "TEST", [
      { seq: 2, fingerprint: "late", payload: { procedure_id: "AI-TOOL.1", fingerprint_timestamp_ms: 1700000002000 } },
      { seq: 1, fingerprint: "early", payload: { procedure_id: "AI-INF.1", fingerprint_timestamp_ms: 1700000001000 } },
    ]);
    const exporter = new ChainMonitorExporter({ walDir: tmpDir, tenantId: "TEST" });
    const report = exporter.buildReport();
    expect(report.timeline[0].fingerprint).toBe("early");
    expect(report.timeline[1].fingerprint).toBe("late");
  });
});
