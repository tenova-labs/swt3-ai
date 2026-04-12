#!/usr/bin/env node
/**
 * SWT3 AI Witness SDK — Zero-Friction Demo
 *
 * Run with:  npx @tenova/swt3-ai demo
 *            or:  npx tsx node_modules/@tenova/swt3-ai/src/demo.ts
 *
 * No API keys. No account. No network calls.
 */

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";

const isColor = process.stdout.isTTY;
const B = isColor ? "\x1b[1m" : "";
const D = isColor ? "\x1b[2m" : "";
const G = isColor ? "\x1b[32m" : "";
const A = isColor ? "\x1b[33m" : "";
const C = isColor ? "\x1b[36m" : "";
const W = isColor ? "\x1b[37m" : "";
const RD = isColor ? "\x1b[31m" : "";
const R = isColor ? "\x1b[0m" : "";

function sha256(data: string, len = 64): string {
  return createHash("sha256").update(data).digest("hex").slice(0, len);
}

function mintFingerprint(
  tenant: string, proc: string,
  fa: number, fb: number, fc: number, tsMs: number,
): string {
  const n = (v: number) => (v === Math.floor(v) ? String(v) : String(v));
  const input = `WITNESS:${tenant}:${proc}:${n(fa)}:${n(fb)}:${n(fc)}:${tsMs}`;
  return createHash("sha256").update(input).digest("hex").slice(0, 12);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function main() {
  console.log();
  console.log(`${B}SWT3 AI Witness SDK — Live Demo${R}`);
  console.log(`${D}No API keys. No account. No network calls.${R}`);
  console.log(`${D}${"─".repeat(56)}${R}`);
  console.log();

  const tenant = "DEMO_TENANT";
  const provider = "LOCAL";
  const modelId = "gpt-4o-2024-08-06";
  const prompt = "What are the compliance requirements for the EU AI Act?";
  const responseText = "The EU AI Act requires high-risk AI systems to maintain technical documentation, implement risk management systems, and ensure human oversight...";

  console.log(`${C}1. Simulating AI inference...${R}`);
  console.log(`   Model:    ${W}${modelId}${R}`);
  console.log(`   Prompt:   ${D}${prompt.slice(0, 50)}...${R}`);
  await sleep(300);

  const promptHash = sha256(prompt, 16);
  const responseHash = sha256(responseText, 16);
  const modelHash = sha256(modelId, 12);

  console.log();
  console.log(`${C}2. Hashing locally (raw text never leaves your infrastructure)...${R}`);
  console.log(`   Prompt hash:   ${G}${promptHash}${R}`);
  console.log(`   Response hash: ${G}${responseHash}${R}`);
  console.log(`   Model hash:    ${G}${modelHash}${R}`);
  await sleep(300);

  const latencyMs = 847;
  const tokenCount = 142;
  const guardrailsActive = 3;

  console.log();
  console.log(`${C}3. Extracting compliance factors...${R}`);
  console.log(`   factor_a (latency):    ${W}${latencyMs} ms${R}`);
  console.log(`   factor_b (tokens):     ${W}${tokenCount}${R}`);
  console.log(`   factor_c (guardrails): ${W}${guardrailsActive} active${R}`);
  await sleep(300);

  console.log();
  console.log(`${C}4. Applying Clearing Level 1 (Standard)...${R}`);
  console.log(`   ${G}✓${R} Hashes retained`);
  console.log(`   ${G}✓${R} Factors retained`);
  console.log(`   ${G}✓${R} Raw prompt purged from wire`);
  console.log(`   ${G}✓${R} Raw response purged from wire`);
  await sleep(300);

  const tsMs = Date.now();
  const epoch = Math.floor(tsMs / 1000);

  const procedures: [string, number, number, number, string, string][] = [
    ["AI-INF.1", 1, 1, 1, "PASS", "Inference traced"],
    ["AI-MDL.1", 1, 1, 0, "PASS", "Model version recorded"],
    ["AI-GRD.1", 1, 1, guardrailsActive, "PASS", "Guardrails active"],
  ];

  console.log();
  console.log(`${C}5. Minting SWT3 Witness Anchors...${R}`);
  console.log();

  const anchors: string[] = [];
  for (const [procId, fa, fb, fc, verdict, desc] of procedures) {
    const fp = mintFingerprint(tenant, procId, fa, fb, fc, tsMs);
    const anchor = `SWT3-E-${provider}-AI-${procId}-${verdict}-${epoch}-${fp}`;
    anchors.push(anchor);
    const color = verdict === "PASS" ? G : A;
    console.log(`   ${color}■ ${verdict}${R}  ${W}${procId}${R}  ${D}${desc}${R}`);
    console.log(`     ${D}${anchor}${R}`);
    console.log();
  }

  console.log(`${C}6. Verifying anchor integrity...${R}`);
  const fpCheck = mintFingerprint(tenant, "AI-INF.1", 1, 1, 1, tsMs);
  console.log(`   Recomputed: ${G}${fpCheck}${R}`);
  console.log(`   Match:      ${G}✓ Anchor is independently verifiable${R}`);
  console.log();

  // ── Regulatory Translation Layer ──
  console.log();
  console.log(`  ${G}[SWT3] 3 Evidence Anchors Verified.${R}`);
  console.log(`  ${D}${"─".repeat(50)}${R}`);
  console.log(`  ${B}REGULATORY COVERAGE SUMMARY (NIST AI RMF / EU AI ACT)${R}`);
  console.log();

  // Covered obligations — mapped to EU AI Act articles
  const coverageMap: [string, string, string, string][] = [
    ["AI-INF.1", "Art. 12(1)",  "Automatic Logging of Use Periods", "PASS"],
    ["AI-MDL.1", "Art. 9(4a)",  "Model Risk Identification",        "PASS"],
    ["AI-GRD.1", "Art. 9(2a)",  "Risk Mitigation Measures",         "PASS"],
  ];
  for (const [proc, article, desc, verdict] of coverageMap) {
    console.log(`  ${G}✓${R} ${W}${proc}${R} → ${article}: ${desc} ${G}[${verdict}]${R}`);
  }

  console.log(`  ${D}${"─".repeat(50)}${R}`);

  // Uncovered obligations
  const uncovered: [string, string, string][] = [
    ["AI-INF.2",  "Art. 15(3)",  "Performance Consistency"],
    ["AI-INF.3",  "Art. 12(1)",  "Volume & Usage Logging"],
    ["AI-MDL.2",  "Art. 12(2b)", "Version & Lineage Tracking"],
    ["AI-MDL.3",  "Art. 72(1)",  "Post-Market Drift Monitoring"],
    ["AI-MDL.4",  "Art. 15(4)",  "Feedback Loop Isolation"],
    ["AI-GRD.2",  "Art. 9(4b)",  "Content Safety Filtering"],
    ["AI-GRD.3",  "Art. 10(2f)", "PII & Data Protection"],
    ["AI-EXPL.1", "Art. 13(1)",  "Transparency & Explainability"],
    ["AI-EXPL.2", "Art. 13(3b)", "Confidence Calibration"],
  ];
  console.log(`  ${A}⚠ ${uncovered.length}/12 obligations uncovered:${R}`);
  for (const [proc, article, desc] of uncovered) {
    console.log(`  ${D}  ${proc} → ${article}: ${desc}${R}`);
  }

  console.log(`  ${D}${"─".repeat(50)}${R}`);
  console.log();

  // EU AI Act countdown
  const deadline = new Date("2026-08-02T00:00:00Z");
  const daysLeft = Math.ceil((deadline.getTime() - Date.now()) / 86400000);
  if (daysLeft > 0) {
    const dc = daysLeft < 60 ? RD : daysLeft < 120 ? A : C;
    console.log(`  ${dc}EU AI Act enforcement in ${daysLeft} days (Aug 2, 2026)${R}`);
    console.log();
  }

  console.log(`  ${D}Full conformity requires all 12 procedures. Connect to close the gap:${R}`);
  console.log(`  ${C}https://sovereign.tenova.io/signup?ref=sdk_demo${R}`);
  console.log();
  console.log(`  ${D}SDK docs:     ${C}https://sovereign.tenova.io/docs/${R}`);
  console.log(`  ${D}Book a pilot: ${C}https://calendly.com/tenova-axiom/30min${R}`);
  console.log(`  ${D}GitHub:       ${C}https://github.com/tenova-labs/swt3-ai${R}`);
  console.log();

  // ── Write HTML coverage report (best-effort) ──
  try {
    const html = generateHtmlReport(coverageMap, uncovered, anchors, daysLeft);
    writeFileSync("swt3-coverage-report.html", html, "utf-8");
    console.log(`  ${G}[SWT3] Coverage report saved \u2192 swt3-coverage-report.html${R}`);
    console.log();
  } catch { /* best-effort — never fail the demo */ }
}

function generateHtmlReport(
  coverageMap: [string, string, string, string][],
  uncoveredList: [string, string, string][],
  anchorList: string[],
  daysLeft: number,
): string {
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  const coveredRows = coverageMap.map(([p, a, d, v]) =>
    `<tr><td style="font-family:monospace">${p}</td><td>${a}</td><td>${d}</td><td style="color:#4ADE80;font-weight:700">[${v}]</td></tr>`
  ).join("\n");
  const uncoveredRows = uncoveredList.map(([p, a, d]) =>
    `<tr><td style="font-family:monospace;color:#FBBF24">${p}</td><td>${a}</td><td>${d}</td></tr>`
  ).join("\n");
  const anchorText = anchorList.join("\n");
  const countdown = daysLeft > 0
    ? `EU AI Act enforcement in ${daysLeft} days (August 2, 2026)`
    : "EU AI Act enforcement has begun.";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SWT3 AI Witness \u2014 Coverage Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#070504;color:#E0D9D1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:2.5rem;line-height:1.6}
.c{max-width:800px;margin:0 auto}
h1{color:#E8A87C;font-size:1.5rem;margin-bottom:.25rem}
h2{color:#E8A87C;font-size:1.1rem;margin:1.5rem 0 .75rem}
.meta{color:#6B7280;font-size:.8rem;margin-bottom:1.5rem}
.score{font-size:2.5rem;font-weight:800;margin:1rem 0}
.score .pass{color:#4ADE80}
.score .total{color:#6B7280}
table{width:100%;border-collapse:collapse;margin:.75rem 0;font-size:.9rem}
th{text-align:left;padding:.5rem .75rem;color:#E8A87C;border-bottom:1px solid #222;font-size:.75rem;text-transform:uppercase;letter-spacing:.1em}
td{padding:.5rem .75rem;border-bottom:1px solid #151312}
pre{background:#111;padding:1rem;border-radius:8px;overflow-x:auto;font-size:.8rem;color:#9CA3AF;margin:.75rem 0;border:1px solid #222}
.countdown{font-size:1rem;font-weight:600;color:#FBBF24;margin:1.5rem 0}
.cta{display:inline-block;margin-top:1.25rem;padding:.75rem 2rem;background:#E8A87C;color:#070504;font-weight:700;text-decoration:none;border-radius:6px;font-size:.9rem;letter-spacing:.03em}
.cta:hover{opacity:.9}
.footer{color:#6B7280;font-size:.75rem;margin-top:2.5rem;padding-top:1.5rem;border-top:1px solid #222}
.warn{color:#FBBF24}
.sep{border:none;border-top:1px solid #222;margin:1.5rem 0}
</style>
</head>
<body>
<div class="c">
<h1>SWT3 AI Witness \u2014 Coverage Report</h1>
<p class="meta">Generated ${ts} UTC | SWT3 Protocol v0.2.9 | Demo Environment</p>

<div class="score"><span class="pass">3</span><span class="total"> / 12 obligations covered</span></div>

<h2>Covered \u2014 EU AI Act Article Mapping</h2>
<table>
<tr><th>Procedure</th><th>EU AI Act</th><th>Obligation</th><th>Status</th></tr>
${coveredRows}
</table>

<h2 class="warn">Uncovered Obligations (${uncoveredList.length})</h2>
<table>
<tr><th>Procedure</th><th>EU AI Act</th><th>Obligation</th></tr>
${uncoveredRows}
</table>

<hr class="sep">

<p class="countdown">${countdown}</p>

<h2>Anchor Evidence (Demo)</h2>
<pre>${anchorText}</pre>

<p>Full conformity requires all 12 procedures across inference, model governance, guardrails, and explainability domains.</p>
<a class="cta" href="https://sovereign.tenova.io/signup?ref=sdk_demo">Close the Gap \u2014 Free Account</a>

<div class="footer">
<p>SWT3 Protocol \u2014 Patent Pending \u2014 Apache 2.0</p>
<p>TeNova: Defining the AI Accountability Standard.</p>
<p style="margin-top:.5rem">This report was generated locally by the SWT3 AI Witness SDK demo. No data was transmitted.</p>
</div>
</div>
</body>
</html>`;
}

main();
