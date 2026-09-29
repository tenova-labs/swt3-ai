/**
 * SWT3 AI Witness SDK -- NVIDIA OpenShell OCSF Event Consumer.
 *
 * Consumes OCSF v1.7.0 structured events emitted by OpenShell sandboxes
 * and mints SWT3 witness anchors for each compliance-relevant event.
 *
 * OpenShell is NVIDIA's open-source (Apache 2.0) sandboxed agent runtime.
 * It emits events for network connections, process lifecycle, filesystem
 * policy decisions, and configuration changes. This adapter reads those
 * events and produces cryptographic attestation anchors.
 *
 * Architecture:
 *   - Zero external dependencies (reads JSON, uses stdlib only)
 *   - Event consumer pattern (not a proxy -- OpenShell emits, we consume)
 *   - Stays out of the critical path (reads logs after events occur)
 *   - Graceful degradation (unknown events skipped, no witness = no-op)
 *
 * Usage:
 *   import { OpenShellWitness } from "@tenova/swt3-ai/adapters/openshell";
 *
 *   // Programmatic: process events from any source
 *   const osw = new OpenShellWitness(witness);
 *   osw.processEvent(ocsfEventObject);
 *
 *   // Stream: pipe from async iterator (stdin, socket, queue)
 *   await osw.watchStream(asyncEventIterator);
 *
 *   // Node.js log tailing: watch a sandbox log file
 *   await osw.watchLog("/var/log/openshell/sandbox-001.jsonl");
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

// -- OCSF Event Class to SWT3 Procedure Mapping ----------------------------

// OpenShell OCSF v1.7.0 event classes mapped to SWT3 procedures.
// Keys are class_name values, sub-keys are disposition strings.
// Disposition values:
//   "allow" = policy permitted the action
//   "deny"  = policy blocked the action
//   "route" = credential injection / proxy forward

const OCSF_TO_PROCEDURE: Record<string, Record<string, string>> = {
  network_activity: {
    allow: "AI-INF.1",    // inference call permitted
    deny: "AI-SEC.1",     // blocked by sandbox policy
    route: "AI-ACC.1",    // credential injection / proxy
  },
  process_activity: {
    launch: "AI-ID.1",    // agent identity established
    terminate: "AI-ID.1", // agent lifecycle end
    tool_call: "AI-TOOL.1", // tool invocation
  },
  file_activity: {
    allow: "AI-DATA.1",   // data access permitted
    deny: "AI-SEC.1",     // data access blocked
  },
  configuration_change: {
    update: "AI-MDL.2",   // policy mutation
  },
  security_finding: {
    guardrail_allow: "AI-GRD.1", // guardrail passed
    guardrail_deny: "AI-GRD.1",  // guardrail blocked
  },
};

// Procedures that map to security events
const SECURITY_PROCEDURES = new Set(["AI-SEC.1", "AI-GRD.1"]);

// OCSF integer disposition IDs to string
const DISPOSITION_MAP: Record<number, string> = {
  1: "allow",
  2: "deny",
  6: "route",
};

/** OCSF v1.7.0 event shape (minimal fields consumed by this adapter). */
export interface OcsfEvent {
  class_name?: string;
  disposition?: string | number;
  activity_name?: string;
  activity_id?: number;
  time?: number;
  duration?: number;
  request_uid?: string;
  response_uid?: string;
  dst_endpoint?: { hostname?: string; url?: string; ip?: string };
  process?: { name?: string };
  file?: { path?: string };
  metadata?: Record<string, unknown>;
}

/** Processing statistics. */
export interface OpenShellStats {
  processed: number;
  skipped: number;
}

// -- Procedure Resolution ---------------------------------------------------

function getProcedure(event: OcsfEvent): string | null {
  const className = event.class_name ?? "";
  let disposition = event.disposition ?? "allow";

  // OCSF uses integer disposition IDs
  if (typeof disposition === "number") {
    disposition = DISPOSITION_MAP[disposition] ?? "allow";
  }

  const mapping = OCSF_TO_PROCEDURE[className];
  if (!mapping) return null;

  return mapping[disposition as string] ?? null;
}

// -- OpenShellWitness Class -------------------------------------------------

/**
 * Consumes NVIDIA OpenShell OCSF events and mints SWT3 witness anchors.
 *
 * Stays out of the critical path -- reads events after they occur.
 * Zero external dependencies beyond the SWT3 SDK.
 */
export class OpenShellWitness {
  private readonly witness: Witness;
  private eventsProcessed = 0;
  private eventsSkipped = 0;

  constructor(witness: Witness) {
    this.witness = witness;
  }

  /** Processing statistics. */
  get stats(): OpenShellStats {
    return {
      processed: this.eventsProcessed,
      skipped: this.eventsSkipped,
    };
  }

  /**
   * Process a single OCSF event and mint the appropriate anchor.
   *
   * @param event - OCSF v1.7.0 event from OpenShell sandbox log.
   * @returns The SWT3 procedure ID that was witnessed, or null if skipped.
   */
  processEvent(event: OcsfEvent): string | null {
    const procedure = getProcedure(event);
    if (!procedure) {
      this.eventsSkipped++;
      return null;
    }

    this.eventsProcessed++;

    // Extract common fields
    const timestampMs = event.time ?? Date.now();
    const activityName = event.activity_name ?? "unknown";
    const disposition = event.disposition ?? "allow";
    const denied =
      disposition === "deny" ||
      disposition === 2 ||
      (typeof disposition === "string" && disposition.includes("deny"));

    // Model ID: try dst_endpoint for network events, else use activity
    const dst = event.dst_endpoint;
    const modelId = dst?.hostname ?? activityName;

    // Content hashes from event metadata
    const promptHash = sha256Truncated(
      event.request_uid || String(event.activity_id ?? ""),
      12,
    );
    const responseHash = sha256Truncated(
      event.response_uid || String(timestampMs),
      12,
    );

    // Duration (OCSF duration field is in milliseconds)
    const durationMs = event.duration ?? 0;

    // For security events: guardrail_passed reflects allow/deny
    const guardrailPassed = !denied;

    // Tool name for process_activity/tool_call events
    let toolName: string | undefined;
    if (procedure === "AI-TOOL.1") {
      toolName = event.process?.name ?? activityName;
    }

    // Access target for network/file events
    let accessTarget: string | undefined;
    const accessGranted = !denied;
    if (
      procedure === "AI-ACC.1" ||
      procedure === "AI-DATA.1" ||
      procedure === "AI-SEC.1"
    ) {
      if (dst) {
        accessTarget = dst.url ?? dst.hostname ?? dst.ip;
      }
      if (event.file?.path) {
        accessTarget = event.file.path;
      }
    }

    const isSecurity = SECURITY_PROCEDURES.has(procedure);

    const record: InferenceRecord = {
      modelId,
      modelHash: sha256Truncated(modelId, 16),
      promptHash,
      responseHash,
      latencyMs: durationMs,
      provider: "nvidia-openshell",
      hasRefusal: denied,
      guardrailsActive: isSecurity ? 1 : 0,
      guardrailsRequired: isSecurity ? 1 : 0,
      guardrailPassed,
      toolName,
      accessTarget,
      accessGranted,
      guardrailNames: [],
    };

    this.witness.record(record);
    return procedure;
  }

  /**
   * Process events from an async iterator.
   *
   * Use this for programmatic integration (stdin, socket, queue).
   *
   * @param stream - Async iterator yielding OCSF event objects.
   */
  async watchStream(stream: AsyncIterable<OcsfEvent>): Promise<void> {
    for await (const event of stream) {
      this.processEvent(event);
    }
  }

  /**
   * Tail an OpenShell sandbox log file and process events (Node.js only).
   *
   * Reads JSONL (one JSON event per line). Tails indefinitely until
   * the AbortSignal fires. New lines are processed as they appear.
   *
   * @param logPath - Path to the sandbox .jsonl log file.
   * @param options - pollIntervalMs (default 500), signal (AbortSignal).
   */
  async watchLog(
    logPath: string,
    options?: { pollIntervalMs?: number; signal?: AbortSignal },
  ): Promise<void> {
    const pollMs = options?.pollIntervalMs ?? 500;
    const signal = options?.signal;

    // Dynamic import -- Node.js only, keeps browser bundle clean
    const fs = await import("node:fs");
    const readline = await import("node:readline");

    // Wait for file to exist
    while (!fs.existsSync(logPath)) {
      if (signal?.aborted) return;
      await sleep(pollMs);
    }

    const stream = fs.createReadStream(logPath, {
      encoding: "utf-8",
      start: fs.statSync(logPath).size, // seek to end (new events only)
    });

    const rl = readline.createInterface({ input: stream });

    if (signal) {
      signal.addEventListener("abort", () => {
        rl.close();
        stream.destroy();
      }, { once: true });
    }

    for await (const line of rl) {
      if (signal?.aborted) break;
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        const event: OcsfEvent = JSON.parse(trimmed);
        this.processEvent(event);
      } catch {
        // Skip non-JSON lines silently
      }
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
