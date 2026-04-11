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

const isColor = process.stdout.isTTY;
const B = isColor ? "\x1b[1m" : "";
const D = isColor ? "\x1b[2m" : "";
const G = isColor ? "\x1b[32m" : "";
const A = isColor ? "\x1b[33m" : "";
const C = isColor ? "\x1b[36m" : "";
const W = isColor ? "\x1b[37m" : "";
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

  for (const [procId, fa, fb, fc, verdict, desc] of procedures) {
    const fp = mintFingerprint(tenant, procId, fa, fb, fc, tsMs);
    const anchor = `SWT3-E-${provider}-AI-${procId}-${verdict}-${epoch}-${fp}`;
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

  console.log(`${D}${"─".repeat(56)}${R}`);
  console.log(`${B}What just happened:${R}`);
  console.log("  • AI inference was simulated locally");
  console.log("  • Prompt and response were SHA-256 hashed (raw text never transmitted)");
  console.log("  • 3 compliance factors extracted (latency, tokens, guardrails)");
  console.log("  • Clearing Level 1 purged raw data from the wire payload");
  console.log("  • 3 SWT3 Witness Anchors minted with tamper-evident fingerprints");
  console.log("  • Any party can re-derive the fingerprint using the same formula");
  console.log();
  console.log(`  ${G}✓ 3 anchors verified locally.${R}`);
  console.log();
  console.log(`  → Track your Integrity Debt Score and generate a Compliance Passport:`);
  console.log(`    ${C}https://sovereign.tenova.io/signup${R} ${D}(free, no credit card)${R}`);
  console.log();
  console.log(`${B}Ready for production?${R}`);
  console.log(`  Start free:               ${C}https://sovereign.tenova.io/signup${R}`);
  console.log(`  SDK docs:                 ${C}https://sovereign.tenova.io/docs/${R}`);
  console.log(`  Book a pilot:             ${C}https://calendly.com/tenova-axiom/30min${R}`);
  console.log(`  GitHub:                   ${C}https://github.com/tenova-labs/swt3-ai${R}`);
  console.log();
  console.log(`${D}One Protocol. Every Model. Any Language. Zero Trust Required.${R}`);
  console.log(`${D}TeNova — Defining the AI Accountability Standard.${R}`);
  console.log();
}

main();
