#!/usr/bin/env node
// ── swt3-verify — The Auditor's Verification Tool ─────────────────
//
// Standalone CLI for C3PAO assessors to independently verify SWT3
// Witness Anchors without access to the Axiom platform.
//
// Usage:
//   swt3-verify --anchor <SWT3 token> --evidence <factors.json>
//   swt3-verify --file <evidence-factor.json>
//   cat factors.json | swt3-verify --anchor <SWT3 token> --stdin
//
// Copyright (c) 2026 Tenable Nova LLC — Apache 2.0 — Patent pending

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { verifyAnchor, verifyEnclave, parseAnchor } from "../index.js";
import type { EvidenceFactor, Factors } from "../types.js";

// ── ANSI colors (no dependencies) ────────────────────────────────
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const CYAN = "\x1b[36m";
const DIM = "\x1b[2m";
const YELLOW = "\x1b[33m";

function green(s: string): string { return `${GREEN}${s}${RESET}`; }
function red(s: string): string { return `${RED}${s}${RESET}`; }
function bold(s: string): string { return `${BOLD}${s}${RESET}`; }
function dim(s: string): string { return `${DIM}${s}${RESET}`; }
function cyan(s: string): string { return `${CYAN}${s}${RESET}`; }
function yellow(s: string): string { return `${YELLOW}${s}${RESET}`; }

// ── CLI argument parsing ─────────────────────────────────────────
const { values } = parseArgs({
  options: {
    anchor: { type: "string", short: "a" },
    evidence: { type: "string", short: "e" },
    file: { type: "string", short: "f" },
    stdin: { type: "boolean" },
    json: { type: "boolean", short: "j" },
    batch: { type: "boolean", short: "b" },
    help: { type: "boolean", short: "h" },
    version: { type: "boolean", short: "v" },
  },
  strict: true,
  allowPositionals: false,
});

if (values.version) {
  console.log("swt3-verify 1.0.0 (libswt3 reference implementation)");
  process.exit(0);
}

if (values.help) {
  console.log(`
${bold("swt3-verify")} — SWT3 Witness Anchor Verification Tool
${dim("Independent verification for C3PAO assessors and GRC platforms")}

${bold("USAGE")}

  ${cyan("Single anchor verification:")}
  swt3-verify --anchor SWT3-E-VULTR-NET-SC76-PASS-1773316622-96b7d56c0245 \\
              --evidence factors.json

  ${cyan("Full evidence factor file (anchor + factors in one JSON):")}
  swt3-verify --file evidence-factor.json

  ${cyan("Batch verification (array of evidence factors):")}
  swt3-verify --file batch-evidence.json --batch

  ${cyan("Pipe from stdin:")}
  cat factors.json | swt3-verify --anchor SWT3-... --stdin

${bold("OPTIONS")}
  -a, --anchor <token>    SWT3 anchor token to verify
  -e, --evidence <path>   Path to JSON file with factors
  -f, --file <path>       Path to SWT3 Evidence Factor JSON (includes anchor)
  -b, --batch             Batch mode: input is array of evidence factors
      --stdin             Read factors from stdin
  -j, --json              Output as JSON
  -h, --help              Show this help
  -v, --version           Show version

${bold("EVIDENCE FACTOR FORMAT")} (--file)
  {
    "swt3_version": "1.0",
    "anchor": "SWT3-E-VULTR-NET-SC76-PASS-1773316622-96b7d56c0245",
    "factors": {
      "procedure_id": "SC-7.6",
      "tenant_id": "DEMO_ENCLAVE",
      "factor_a": 4, "factor_b": 3, "factor_c": -1,
      "timestamp_ms": 1773316622000
    }
  }

${bold("FACTORS-ONLY FORMAT")} (--evidence, with separate --anchor)
  {
    "procedure_id": "SC-7.6",
    "tenant_id": "DEMO_ENCLAVE",
    "factor_a": 4, "factor_b": 3, "factor_c": -1,
    "timestamp_ms": 1773316622000
  }

${bold("EXIT CODES")}
  0  All anchors verified (CERTIFIED TRUTH)
  1  One or more anchors failed verification (TAMPERED)
  2  Invalid input or usage error

${dim("SWT3 Protocol Specification: https://github.com/tenova-ai/libswt3")}
  `);
  process.exit(0);
}

// ── Input loading ────────────────────────────────────────────────
function loadJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    console.error(red(`Error reading ${path}: ${(err as Error).message}`));
    process.exit(2);
  }
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    process.stdin.on("data", (chunk: Uint8Array) => chunks.push(chunk));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", reject);
  });
}

function validateFactors(obj: unknown): Factors {
  const f = obj as Record<string, unknown>;
  const required = ["procedure_id", "tenant_id", "factor_a", "factor_b", "factor_c", "timestamp_ms"];
  for (const key of required) {
    if (f[key] === undefined) {
      console.error(red(`Missing required factor: ${key}`));
      process.exit(2);
    }
  }
  return {
    procedure_id: String(f.procedure_id),
    tenant_id: String(f.tenant_id),
    factor_a: Number(f.factor_a),
    factor_b: Number(f.factor_b),
    factor_c: Number(f.factor_c),
    timestamp_ms: Number(f.timestamp_ms),
  };
}

// ── Output formatting ────────────────────────────────────────────
function printResult(anchor: string, result: ReturnType<typeof verifyAnchor>): void {
  const parsed = parseAnchor(anchor);
  const label = parsed ? `${parsed.procedure} (${parsed.verdict})` : anchor;

  if (result.verified) {
    console.log(`\n  ${green("[VERIFIED]")} ${bold(label)}`);
    console.log(`  ${dim("Status:")}      ${green("CERTIFIED TRUTH")}`);
  } else {
    console.log(`\n  ${red("[TAMPERED]")} ${bold(label)}`);
    console.log(`  ${dim("Status:")}      ${red(result.status)}`);
  }

  console.log(`  ${dim("Claimed:")}     ${result.claimed_fingerprint}`);
  console.log(`  ${dim("Recomputed:")}  ${result.recomputed_fingerprint}`);

  if (result.factors) {
    console.log(`  ${dim("Procedure:")}   ${result.factors.procedure_id}`);
    console.log(`  ${dim("Tenant:")}      ${result.factors.tenant_id}`);
    console.log(`  ${dim("Factors:")}     A=${result.factors.factor_a} B=${result.factors.factor_b} C=${result.factors.factor_c}`);
    console.log(`  ${dim("Timestamp:")}   ${result.factors.timestamp_ms} (${new Date(result.factors.timestamp_ms).toISOString()})`);
  }

  if (!result.verified) {
    console.log(`  ${yellow("WARNING:")}     Evidence integrity check FAILED`);
  }
}

// ── Main ─────────────────────────────────────────────────────────
async function main(): Promise<void> {
  // Mode 1: Full evidence factor file (--file)
  if (values.file) {
    const data = loadJson(values.file);

    // Batch mode
    if (values.batch) {
      const items = (data as { anchors?: EvidenceFactor[] }).anchors ?? (data as EvidenceFactor[]);
      if (!Array.isArray(items)) {
        console.error(red("Batch mode expects an array of evidence factors"));
        process.exit(2);
      }

      const entries = items.map((item: EvidenceFactor) => ({
        anchor: item.anchor,
        factors: validateFactors(item.factors),
      }));

      const { results, integrity } = verifyEnclave(entries);

      if (values.json) {
        console.log(JSON.stringify({ results, integrity }, null, 2));
      } else {
        console.log(bold("\n  SWT3 Enclave Verification Report"));
        console.log(dim("  ─".repeat(24)));

        for (let i = 0; i < results.length; i++) {
          printResult(entries[i].anchor, results[i]);
        }

        console.log(dim("\n  ─".repeat(24)));
        console.log(`  ${bold("Total:")}     ${integrity.total}`);
        console.log(`  ${green("Verified:")}  ${integrity.verified}`);
        if (integrity.tampered > 0) {
          console.log(`  ${red("Tampered:")}  ${integrity.tampered}`);
        }
        console.log(`  ${dim("Enclave Signature:")} ${cyan(integrity.enclave_signature.slice(0, 16))}...`);
      }

      process.exit(integrity.tampered > 0 ? 1 : 0);
    }

    // Single evidence factor file
    const ef = data as EvidenceFactor;
    if (!ef.anchor || !ef.factors) {
      console.error(red("Evidence factor file must contain 'anchor' and 'factors' fields"));
      process.exit(2);
    }

    const factors = validateFactors(ef.factors);
    const result = verifyAnchor(ef.anchor, factors);

    if (values.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printResult(ef.anchor, result);
      console.log();
    }

    process.exit(result.verified ? 0 : 1);
  }

  // Mode 2: Separate anchor + evidence (--anchor + --evidence/--stdin)
  if (!values.anchor) {
    console.error(red("Provide either --file or --anchor. Use --help for usage."));
    process.exit(2);
  }

  let factorsData: unknown;

  if (values.stdin) {
    const raw = await readStdin();
    try {
      factorsData = JSON.parse(raw);
    } catch {
      console.error(red("Invalid JSON on stdin"));
      process.exit(2);
    }
  } else if (values.evidence) {
    factorsData = loadJson(values.evidence);
  } else {
    console.error(red("Provide --evidence <path> or --stdin with --anchor"));
    process.exit(2);
  }

  const factors = validateFactors(factorsData);
  const result = verifyAnchor(values.anchor, factors);

  if (values.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printResult(values.anchor, result);
    console.log();
  }

  process.exit(result.verified ? 0 : 1);
}

main().catch((err) => {
  console.error(red(`Fatal: ${(err as Error).message}`));
  process.exit(2);
});
