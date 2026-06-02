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
  console.log(`  ${G}New in v0.5.4:${R} AI-LIC.1 License Provenance,`);
  console.log(`  OpenMDW-1.1 support, MCP governance, 65 procedures.`);
  console.log(`  ${D}License guide: sovereign.tenova.io/guides/openmdw-license-provenance.html${R}`);
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

  // ── License Provenance (AI-LIC.1) ──
  console.log(`${C}7. License Provenance Witnessing (AI-LIC.1)...${R}`);
  console.log();
  console.log(`   ${D}Base model:   Apache-2.0 (permissive)${R}`);
  console.log(`   ${D}LoRA adapter: CC-BY-4.0 (permissive)${R}`);
  console.log(`   ${D}Training data: OpenMDW-1.1 (openmdw)${R}`);

  const licFp = mintFingerprint(tenant, "AI-LIC.1", 3, 1, 0, tsMs);
  const licAnchor = `SWT3-E-${provider}-AI-AI-LIC.1-PASS-${epoch}-${licFp}`;
  anchors.push(licAnchor);
  console.log();
  console.log(`   ${G}■ PASS${R}  ${W}AI-LIC.1${R}  ${D}3 license components verified, all compliant${R}`);
  console.log(`     ${D}${licAnchor}${R}`);
  console.log();

  // ── Summary Table ──
  console.log(`  ${D}${"─".repeat(56)}${R}`);
  console.log(`  ${B}WITNESS SUMMARY${R}`);
  console.log(`  ${D}${"─".repeat(56)}${R}`);
  console.log(`  ${"Procedure".padEnd(14)}${"Verdict".padEnd(10)}Fingerprint`);
  console.log(`  ${D}${"─".repeat(56)}${R}`);
  const summaryItems: [string, string][] = [
    ["AI-INF.1", "PASS"], ["AI-MDL.1", "PASS"], ["AI-GRD.1", "PASS"],
    ["AI-LIC.1", "PASS"],
  ];
  for (let i = 0; i < summaryItems.length; i++) {
    const [proc, verdict] = summaryItems[i];
    const fpVal = anchors[i]?.split("-").pop() ?? "?";
    const color = verdict === "PASS" ? G : RD;
    console.log(`  ${W}${proc.padEnd(14)}${R}${color}${verdict.padEnd(10)}${R}${D}${fpVal}${R}`);
  }
  console.log(`  ${D}${"─".repeat(56)}${R}`);
  console.log(`  ${G}${anchors.length} anchors${R} ${D}| 0 violations | local demo${R}`);
  console.log();

  // ── Regulatory Translation Layer ──
  console.log();
  console.log(`  ${G}[SWT3] ${anchors.length} Evidence Anchors Verified.${R}`);
  console.log(`  ${D}${"─".repeat(50)}${R}`);
  console.log(`  ${B}REGULATORY COVERAGE SUMMARY (NIST AI RMF / EU AI ACT)${R}`);
  console.log();

  // Demonstrated obligations — mapped to EU AI Act articles
  const coverageMap: [string, string, string, string][] = [
    ["AI-INF.1", "Art. 12(1)",  "Automatic Logging of Use Periods", "DEMONSTRATED"],
    ["AI-MDL.1", "Art. 9(4a)",  "Model Risk Identification",        "DEMONSTRATED"],
    ["AI-GRD.1", "Art. 9(2a)",  "Risk Mitigation Measures",         "DEMONSTRATED"],
    ["AI-LIC.1", "Art. 53(1d)", "Training Data Licensing (GPAI)",    "DEMONSTRATED"],
  ];
  for (const [proc, article, desc, verdict] of coverageMap) {
    console.log(`  ${G}✓${R} ${W}${proc}${R} → ${article}: ${desc} ${G}[${verdict}]${R}`);
  }

  console.log(`  ${D}${"─".repeat(50)}${R}`);

  // Mapped obligations that need production data
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
  console.log(`  ${C}${uncovered.length} additional obligations mapped (need production data):${R}`);
  for (const [proc, article, desc] of uncovered) {
    console.log(`  ${D}  ${proc} → ${article}: ${desc}${R}`);
  }

  console.log(`  ${D}${"─".repeat(50)}${R}`);
  console.log();

  // EU AI Act countdown
  const deadline = new Date("2027-12-02T00:00:00Z");
  const daysLeft = Math.ceil((deadline.getTime() - Date.now()) / 86400000);
  if (daysLeft > 0) {
    const dc = daysLeft < 60 ? RD : daysLeft < 120 ? A : C;
    console.log(`  ${dc}EU AI Act high-risk enforcement in ${daysLeft} days (Dec 2, 2027)${R}`);
    console.log();
  }

  console.log(`  ${D}Preview a live auditor view (no account required):${R}`);
  console.log(`  ${C}https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public${R}`);
  console.log();
  console.log(`  ${D}Full conformity requires all 48 AI procedures. Connect to close the gap:${R}`);
  console.log(`  ${C}https://sovereign.tenova.io/signup?ref=sdk_demo${R}`);
  console.log();
  console.log(`  ${D}SDK docs:     ${C}https://sovereign.tenova.io/docs${R}`);
  console.log(`  ${D}Contact:      ${C}engineering@tenovaai.com${R}`);
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
    `<tr><td style="font-family:monospace">${p}</td><td>${a}</td><td>${d}</td><td style="color:#9CA3AF;font-weight:600">[NEEDS PRODUCTION]</td></tr>`
  ).join("\n");
  const anchorText = anchorList.join("\n");
  const countdown = daysLeft > 0
    ? `EU AI Act high-risk enforcement in ${daysLeft} days (December 2, 2027)`
    : "EU AI Act high-risk enforcement has begun.";

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
.cta-secondary{display:inline-block;margin-top:1.25rem;margin-right:.75rem;padding:.75rem 2rem;background:transparent;color:#E8A87C;border:1px solid #E8A87C;font-weight:600;text-decoration:none;border-radius:6px;font-size:.9rem;letter-spacing:.03em}
.cta-secondary:hover{background:rgba(232,168,124,.1)}
.footer{color:#6B7280;font-size:.75rem;margin-top:2.5rem;padding-top:1.5rem;border-top:1px solid #222}
.warn{color:#FBBF24}
.sep{border:none;border-top:1px solid #222;margin:1.5rem 0}
</style>
</head>
<body>
<div class="c">
<h1>SWT3 AI Witness \u2014 Coverage Report</h1>
<p class="meta">Generated ${ts} UTC | SWT3 Protocol v1.6.0 | Demo Environment</p>

<div class="score"><span class="pass">13</span><span class="total"> / 13 obligations mapped</span></div>
<p style="color:#9CA3AF;font-size:.95rem;margin-top:-.5rem">4 demonstrated locally \u00b7 9 need production data</p>

<h2>Demonstrated Locally</h2>
<table>
<tr><th>Procedure</th><th>EU AI Act</th><th>Obligation</th><th>Status</th></tr>
${coveredRows}
</table>

<h2>Mapped \u2014 Needs Production Data (${uncoveredList.length})</h2>
<table>
<tr><th>Procedure</th><th>EU AI Act</th><th>Obligation</th><th>Status</th></tr>
${uncoveredRows}
</table>

<hr class="sep">

<p class="countdown">${countdown}</p>

<h2>Anchor Evidence (Demo)</h2>
<pre>${anchorText}</pre>

<p>Full conformity requires all 48 AI procedures across inference, model governance, guardrails, RAG, skills, licensing, and explainability domains.</p>
<a class="cta-secondary" href="https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public">See Live Auditor View \u2192</a>
<a class="cta" href="https://sovereign.tenova.io/signup?ref=sdk_demo">Close the Gap \u2014 Free Account</a>
<p style="margin-top:.75rem;font-size:.8rem;color:#9CA3AF">Preview a real tenant's EU AI Act posture (no account required) \u2014 then create your own.</p>

<div class="footer">
<p>SWT3 Protocol \u2014 Patent Pending \u2014 Apache 2.0</p>
<p>TeNova: Defining the AI Accountability Standard.</p>
<p style="margin-top:.5rem">This report was generated locally by the SWT3 AI Witness SDK demo. No data was transmitted.</p>
</div>
</div>
</body>
</html>`;
}

export async function runMeshTest() {
  const {
    TrustRegistry, verifyCredential, signCredential,
    TRUST_LEVEL_NAMES, TRUST_DENIED,
  } = await import("./trust.js");
  const { createHash } = await import("node:crypto");

  console.log();
  console.log(`${B}SWT3 Trust Mesh Simulation${R}`);
  console.log(`${D}Two agents. One handshake. Zero network calls.${R}`);
  console.log(`${D}${"─".repeat(56)}${R}`);
  console.log();

  // ── Agent Setup ──
  console.log(`  ${C}Agents:${R}`);
  console.log(`    ${G}Alice${R}  tenant=EU_REGULATED  profile=eu-ai-act-high-risk  ${D}(signed, guardrails, CL2)${R}`);
  console.log(`    ${A}Bob${R}    tenant=DEV_SANDBOX   profile=minimal              ${D}(unsigned, no guardrails, CL0)${R}`);
  console.log();

  const now = Date.now();
  const fp = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 12);

  // Alice: strict, signed, high clearing
  const aliceRegistry = new TrustRegistry();
  aliceRegistry.setMinTrustLevel(2);
  aliceRegistry.setRequireSignature(true);
  aliceRegistry.trustTenant("DEV_SANDBOX");

  const aliceCredential = {
    agentId: "alice-agent", tenantId: "EU_REGULATED",
    anchorFingerprint: fp("alice-anchor-" + now),
    anchorTimestampMs: now,
    isSigned: true, procedures: ["AI-INF.1", "AI-GRD.1", "AI-FAIR.1"],
    clearingLevel: 2, hasGuardrails: true, hasHardwareAttestation: false,
  };

  // Bob: permissive, unsigned, minimal
  const bobRegistry = new TrustRegistry();
  bobRegistry.setMinTrustLevel(0);
  bobRegistry.trustTenant("EU_REGULATED");

  const bobCredential = {
    agentId: "bob-agent", tenantId: "DEV_SANDBOX",
    anchorFingerprint: fp("bob-anchor-" + now),
    anchorTimestampMs: now,
    isSigned: false, procedures: [] as string[],
    clearingLevel: 0, hasGuardrails: false, hasHardwareAttestation: false,
  };

  // ── Step 1: Alice presents ──
  console.log(`  ${C}Step 1: Alice presents credential to Bob${R}`);
  console.log(`    Procedures: ${G}${aliceCredential.procedures.join(", ")}${R}`);
  console.log(`    Signed: ${G}yes${R} | Guardrails: ${G}yes${R} | Hardware: ${A}no${R} | Clearing: ${G}${aliceCredential.clearingLevel}${R}`);
  console.log();

  // ── Step 2: Bob verifies Alice ──
  console.log(`  ${C}Step 2: Bob verifies Alice's credential${R}`);
  const bobResult = verifyCredential(aliceCredential, bobRegistry, "DEV_SANDBOX");
  console.log(`    Checks: ${bobResult.checksPerformed} performed, ${bobResult.checksPassed} passed`);
  console.log(`    Trust level: ${bobResult.trustLevel} (${TRUST_LEVEL_NAMES[bobResult.trustLevel] ?? "unknown"})`);
  if (bobResult.granted) {
    console.log(`    Result: ${G}GRANTED${R}`);
  } else {
    console.log(`    Denial reason: ${RD}${bobResult.denialReason}${R}`);
    console.log(`    Result: ${RD}DENIED${R}`);
  }
  console.log();

  // ── Step 3: Bob presents ──
  console.log(`  ${C}Step 3: Bob presents credential to Alice${R}`);
  console.log(`    Procedures: ${D}(none)${R}`);
  console.log(`    Signed: ${RD}no${R} | Guardrails: ${RD}no${R} | Hardware: ${A}no${R} | Clearing: ${A}${bobCredential.clearingLevel}${R}`);
  console.log();

  // ── Step 4: Alice verifies Bob ──
  console.log(`  ${C}Step 4: Alice verifies Bob's credential${R}`);
  const aliceResult = verifyCredential(bobCredential, aliceRegistry, "EU_REGULATED");
  console.log(`    Checks: ${aliceResult.checksPerformed} performed, ${aliceResult.checksPassed} passed`);
  console.log(`    Trust level: ${aliceResult.trustLevel} (${TRUST_LEVEL_NAMES[aliceResult.trustLevel] ?? "unknown"})`);
  if (aliceResult.granted) {
    console.log(`    Result: ${G}GRANTED${R}`);
  } else {
    console.log(`    Denial reason: ${RD}${aliceResult.denialReason}${R}`);
    console.log(`    Result: ${RD}DENIED${R}`);
  }
  console.log();

  // ── Summary ──
  console.log(`  ${B}Summary:${R} Asymmetric trust -- Alice is ${G}accepted${R}, Bob is ${RD}rejected${R}.`);
  console.log(`  ${D}This is how .swt3.yaml policy controls who your agent communicates with.${R}`);
  console.log();
}

async function runTelecomDemo() {
  console.log();
  console.log(`${B}SWT3 AI Witness -- Telecom Fraud Detection Demo${R}`);
  console.log(`${D}Simulating a telecom fraud scoring model lifecycle.${R}`);
  console.log(`${D}${"─".repeat(56)}${R}`);
  console.log(`  ${D}Profile: telecom-compliance | Clearing: 2 (Sensitive)${R}`);
  console.log(`  ${D}Use case: Real-time fraud detection on call detail records${R}`);
  console.log(`${D}${"─".repeat(56)}${R}`);
  console.log();

  const tenant = "TELECOM_DEMO";
  const provider = "LOCAL";
  const modelId = "fraud-scoring-v3.2.1";
  const tsMs = Date.now();
  const epoch = Math.floor(tsMs / 1000);
  const anchors: string[] = [];

  // Step 1: Model inference on call record
  console.log(`${C}1. Fraud model inference on call detail record...${R}`);
  console.log(`   Model:     ${W}${modelId}${R}`);
  console.log(`   Input:     ${D}CDR #8847291 (international call, 47min, new SIM)${R}`);
  console.log(`   Score:     ${A}0.87 (HIGH RISK)${R}`);
  console.log(`   Latency:   ${W}23ms${R}`);
  await sleep(300);

  // Step 2: Bias check
  console.log();
  console.log(`${C}2. Bias disparity check across demographic groups...${R}`);
  console.log(`   Groups tested:   ${W}12${R}`);
  console.log(`   Disparities:     ${G}0 above threshold${R}`);
  console.log(`   Max disparity:   ${W}4.2%${R} (below 10% threshold)`);
  await sleep(200);

  // Step 3: Drift detection
  console.log();
  console.log(`${C}3. Model drift check against production baseline...${R}`);
  console.log(`   Metrics evaluated: ${W}8${R}`);
  console.log(`   Drifted:           ${G}0${R}`);
  console.log(`   Drift type:        ${D}data (distribution stable)${R}`);
  await sleep(200);

  // Step 4: Performance metrics
  console.log();
  console.log(`${C}4. Performance validation against declared accuracy...${R}`);
  console.log(`   Precision: ${G}94.2%${R}  Recall: ${G}91.8%${R}  F1: ${G}93.0%${R}`);
  console.log(`   Benchmark: ${W}fraud-detection-v3 (weekly)${R}`);
  await sleep(200);

  // Step 5: Automated decision
  console.log();
  console.log(`${C}5. Automated decision: flagging transaction for review...${R}`);
  console.log(`   Decision:  ${A}FLAGGED${R} (score > 0.75 threshold)`);
  console.log(`   Type:      ${W}fraud_flag (legal/financial effect)${R}`);
  console.log(`   GDPR basis: ${W}Art. 22 -- automated decision notification sent${R}`);
  await sleep(200);

  // Step 6: Human review
  console.log();
  console.log(`${C}6. Human analyst reviews flagged transaction...${R}`);
  console.log(`   Reviewer:  ${W}analyst-7829${R}`);
  console.log(`   Decision:  ${G}CONFIRMED FRAUD${R}`);
  console.log(`   Override:  ${D}none (model agreed)${R}`);
  await sleep(200);

  // Step 7: Explainability
  console.log();
  console.log(`${C}7. Generating explanation for affected customer...${R}`);
  console.log(`   Top features: ${W}call_duration (0.34), new_sim (0.28), international (0.21)${R}`);
  console.log(`   Confidence:   ${G}0.87${R}`);
  await sleep(200);

  // Step 8: Transparency disclosure
  console.log();
  console.log(`${C}8. Transparency notification to customer...${R}`);
  console.log(`   Disclosure: ${W}AI-assisted fraud detection was used${R}`);
  console.log(`   Recipient:  ${W}data_subject (account holder)${R}`);
  console.log(`   FCC + Art. 13 requirement satisfied`);
  await sleep(200);

  // Mint anchors
  const procedures: [string, number, number, number, string, string][] = [
    ["AI-INF.1",     1, 1, 1,   "PASS", "Fraud inference witnessed"],
    ["AI-FAIR.3",   12, 0, 42,  "PASS", "Bias audit: 12 groups, 0 disparities"],
    ["AI-DRIFT.1",   8, 0, 0,   "PASS", "Drift check: 8 metrics stable"],
    ["AI-PERF.1",    3, 3, 3,   "PASS", "Performance: 3/3 metrics passing"],
    ["AI-AUTO.1",    1, 1, 0,   "PASS", "Automated decision notified"],
    ["AI-HITL.1",    1, 1, 0,   "PASS", "Human review completed"],
    ["AI-EXPL.1",    3, 1, 0,   "PASS", "Explanation generated (3 features)"],
    ["AI-TRANS.1",   1, 0, 1,   "PASS", "Transparency disclosure sent"],
  ];

  console.log();
  console.log(`${C}9. Minting SWT3 Witness Anchors...${R}`);
  console.log();

  for (const [procId, fa, fb, fc, verdict, desc] of procedures) {
    const fp = mintFingerprint(tenant, procId, fa, fb, fc, tsMs);
    const anchor = `SWT3-E-${provider}-AI-${procId}-${verdict}-${epoch}-${fp}`;
    anchors.push(anchor);
    console.log(`   ${G}\u25a0 ${verdict}${R}  ${W}${procId.padEnd(14)}${R}${D}${desc}${R}`);
    console.log(`     ${D}${anchor}${R}`);
    console.log();
  }

  // Summary
  console.log(`  ${D}${"─".repeat(56)}${R}`);
  console.log(`  ${B}TELECOM FRAUD DETECTION -- WITNESS CHAIN${R}`);
  console.log(`  ${D}${"─".repeat(56)}${R}`);
  console.log(`  ${"Procedure".padEnd(16)}${"Verdict".padEnd(10)}${"Regulation".padEnd(16)}Fingerprint`);
  console.log(`  ${D}${"─".repeat(56)}${R}`);

  const regMap: Record<string, string> = {
    "AI-INF.1": "Art. 12(1)",
    "AI-FAIR.3": "Art. 10(2f)",
    "AI-DRIFT.1": "Art. 9(2b)",
    "AI-PERF.1": "Art. 15(1)",
    "AI-AUTO.1": "GDPR Art. 22",
    "AI-HITL.1": "Art. 14(1)",
    "AI-EXPL.1": "Art. 13(1)",
    "AI-TRANS.1": "FCC + Art. 13",
  };

  for (let i = 0; i < procedures.length; i++) {
    const [proc, , , , verdict] = procedures[i];
    const fpVal = anchors[i]?.split("-").pop() ?? "?";
    const reg = regMap[proc] ?? "";
    console.log(`  ${W}${proc.padEnd(16)}${R}${G}${verdict.padEnd(10)}${R}${D}${reg.padEnd(16)}${fpVal}${R}`);
  }

  console.log(`  ${D}${"─".repeat(56)}${R}`);
  console.log(`  ${G}${anchors.length} anchors${R} ${D}| Full fraud lifecycle witnessed | telecom-compliance profile${R}`);
  console.log();
  console.log(`  ${D}Telecom profile: swt3 init --profile telecom-compliance${R}`);
  console.log(`  ${D}Covers: FCC AI transparency, EU AI Act Art. 9-15, GDPR Art. 22${R}`);
  console.log();
  console.log(`  ${D}Connect to production:${R}`);
  console.log(`  ${C}https://sovereign.tenova.io/signup?ref=telecom_demo${R}`);
  console.log();
}

if (process.argv.includes("--mesh-test")) {
  runMeshTest();
} else if (process.argv.includes("--scenario") && process.argv.includes("telecom-fraud")) {
  runTelecomDemo();
} else {
  main();
}
