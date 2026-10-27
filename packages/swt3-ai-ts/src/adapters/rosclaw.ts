/**
 * SWT3 AI Witness SDK -- ROSClaw Structured Audit Log Consumer.
 *
 * Consumes structured audit log entries emitted by ROSClaw (the OpenClaw
 * ROS 2 executive layer for agentic robot control) and mints SWT3 witness
 * anchors for each governance-relevant event.
 *
 * ROSClaw formalizes the boundary between cognition and actuation as a
 * contract C = (A, O, V, L) where L is a structured audit logger. Every
 * robot action gets an append-only log entry recording the proposal,
 * validation decision, and execution outcome.
 *
 * SWT3 is an independent witness protocol. It records evidence of what
 * ROSClaw's validator reported. It does not define safety envelopes,
 * keep-out zones, or velocity bounds.
 *
 * Architecture:
 *   - Zero external dependencies (reads JSON, uses stdlib only)
 *   - Zero ROS dependencies (reads structured log output, does NOT import rcljs)
 *   - Event consumer pattern (ROSClaw validates, we witness)
 *   - Stays out of the robot's control loop
 *
 * Usage:
 *   import { ROSClawWitness } from "@tenova/swt3-ai/adapters/rosclaw";
 *
 *   const rcw = new ROSClawWitness(witness);
 *   rcw.processEntry(auditLogEntryObject);
 *
 *   await rcw.watchStream(asyncEntryIterator);
 *   await rcw.watchLog("/var/log/rosclaw/audit.jsonl");
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

// -- ROSClaw Audit Entry to SWT3 Procedure Mapping ----------------------------

const ROSCLAW_TO_PROCEDURE: Record<string, Record<string, string>> = {
  action_proposal: {
    executed: "AI-TOOL.1",    // actuator command executed
    blocked: "AI-SAFE.1",     // validator blocked the action
    modified: "AI-TOOL.1",    // action was modified before execution
  },
  safety_violation: {
    velocity_bound: "AI-SAFE.1",   // exceeded velocity limits
    keepout_zone: "AI-SAFE.1",     // entered restricted zone
    rate_limit: "AI-SAFE.1",       // action rate exceeded
    precondition: "AI-SAFE.1",     // precondition check failed
    force_limit: "AI-SAFE.1",      // force/torque exceeded
    collision: "AI-SAFE.1",        // collision detected
  },
  capability_discovery: {
    registered: "AI-TOOL.2",       // new tool/actuator registered
    deregistered: "AI-TOOL.2",     // tool/actuator removed
  },
  observation: {
    processed: "AI-INF.1",         // sensor observation processed
  },
  lifecycle: {
    spawn: "AI-LCM.1",            // agent spawned
    terminate: "AI-LCM.1",        // agent terminated
    checkpoint: "AI-LCM.1",       // state checkpointed
  },
};

const BLOCKED_DECISIONS = new Set(["blocked", "denied", "rejected"]);

const TOOL_PROCEDURES = new Set(["AI-TOOL.1", "AI-TOOL.2"]);

/** ROSClaw audit log entry shape (minimal fields consumed). */
export interface ROSClawEntry {
  entry_type?: string;
  decision?: string;
  reason?: string;
  status?: string;
  action_name?: string;
  agent_id?: string;
  outcome?: string;
  timestamp?: number;
  execution_ms?: number;
  observation_hash?: string;
}

/** Processing statistics. */
export interface ROSClawStats {
  processed: number;
  skipped: number;
}

function getProcedure(entry: ROSClawEntry): string | null {
  const entryType = entry.entry_type ?? "";
  // Decision field varies: decision for action_proposal, reason for safety_violation
  const decision = entry.decision ?? entry.reason ?? entry.status;
  if (decision == null) return null;

  const mapping = ROSCLAW_TO_PROCEDURE[entryType];
  if (!mapping) return null;

  return mapping[decision.toLowerCase()] ?? null;
}

// -- ROSClawWitness Class -----------------------------------------------------

/**
 * Consumes ROSClaw structured audit log entries and mints SWT3 anchors.
 *
 * Stays out of the robot's control loop -- reads audit logs after events
 * occur. Zero external dependencies. Zero ROS dependencies.
 */
export class ROSClawWitness {
  private readonly witness: Witness;
  private entriesProcessed = 0;
  private entriesSkipped = 0;

  constructor(witness: Witness) {
    this.witness = witness;
  }

  /** Processing statistics. */
  get stats(): ROSClawStats {
    return {
      processed: this.entriesProcessed,
      skipped: this.entriesSkipped,
    };
  }

  /**
   * Process a single ROSClaw audit log entry and mint the appropriate anchor.
   *
   * @param entry - ROSClaw audit log entry dict.
   * @returns The SWT3 procedure ID that was witnessed, or null if skipped.
   */
  processEntry(entry: ROSClawEntry): string | null {
    const procedure = getProcedure(entry);
    if (!procedure) {
      this.entriesSkipped++;
      return null;
    }

    this.entriesProcessed++;

    const timestampMs = entry.timestamp ?? Date.now();
    const decision = (entry.decision ?? entry.reason ?? entry.status ?? "unknown").toLowerCase();
    const blocked = BLOCKED_DECISIONS.has(decision);
    const actionName = entry.action_name ?? entry.entry_type ?? "unknown";
    const agentId = entry.agent_id ?? "unknown";
    const outcome = entry.outcome;

    const modelId = `rosclaw-${actionName}`;

    const record: InferenceRecord = {
      modelId,
      modelHash: sha256Truncated(modelId, 16),
      promptHash: sha256Truncated(`${agentId}:${actionName}:${timestampMs}`, 16),
      responseHash: sha256Truncated(`${decision}:${outcome ?? "none"}:${timestampMs}`, 16),
      latencyMs: entry.execution_ms ?? 0,
      provider: "rosclaw",
      hasRefusal: blocked,
      guardrailsActive: procedure === "AI-SAFE.1" ? 1 : 0,
      guardrailsRequired: procedure === "AI-SAFE.1" ? 1 : 0,
      guardrailPassed: !blocked,
      guardrailNames: [],
      toolName: TOOL_PROCEDURES.has(procedure) ? actionName : undefined,
      accessTarget: undefined,
      accessGranted: !blocked,
    };

    this.witness.record(record, procedure);
    return procedure;
  }

  /**
   * Process entries from an async iterator.
   */
  async watchStream(stream: AsyncIterable<ROSClawEntry>): Promise<void> {
    for await (const entry of stream) {
      this.processEntry(entry);
    }
  }

  /**
   * Tail a ROSClaw audit log file and process entries.
   *
   * Reads JSONL (one JSON entry per line). Tails indefinitely until
   * the AbortSignal fires.
   */
  async watchLog(
    logPath: string,
    options?: { pollIntervalMs?: number; signal?: AbortSignal },
  ): Promise<void> {
    const pollMs = options?.pollIntervalMs ?? 500;
    const signal = options?.signal;

    // Dynamic import for Node.js-only modules
    const fs = await import("node:fs");
    const path = await import("node:path");
    const readline = await import("node:readline");

    // Path validation
    const resolved = path.resolve(logPath);
    if (!resolved.endsWith(".jsonl") && !resolved.endsWith(".log")) {
      throw new Error(`Refusing to tail non-log file: ${resolved}`);
    }

    // Wait for file to exist
    while (!fs.existsSync(resolved)) {
      if (signal?.aborted) return;
      await new Promise((r) => setTimeout(r, pollMs));
    }

    if (!fs.statSync(resolved).isFile()) {
      throw new Error(`Path is not a regular file: ${resolved}`);
    }

    const stream = fs.createReadStream(resolved, {
      encoding: "utf-8",
      start: fs.statSync(resolved).size, // seek to end
    });

    const rl = readline.createInterface({ input: stream });

    for await (const line of rl) {
      if (signal?.aborted) break;
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const entry: ROSClawEntry = JSON.parse(trimmed);
        this.processEntry(entry);
      } catch {
        // skip non-JSON lines
      }
    }
  }
}
