/**
 * SWT3 AI Witness SDK -- NVIDIA NemoClaw Policy Engine Event Consumer.
 *
 * Consumes structured policy decision events emitted by NemoClaw and mints
 * SWT3 witness anchors for each compliance-relevant decision.
 *
 * NemoClaw is NVIDIA's open-source agent governance stack that sits above
 * OpenShell. While OpenShell sandboxes the runtime, NemoClaw evaluates
 * policy rules before actions reach the sandbox. This adapter witnesses
 * NemoClaw's policy decisions -- what was allowed, denied, and which rule
 * governed the decision.
 *
 * SWT3 is an independent witness protocol. It records evidence of what
 * NemoClaw's policy engine reported. It does not enforce policy, define
 * rules, or intercept agent behavior.
 *
 * Architecture:
 *   - Zero external dependencies (reads JSON, uses stdlib only)
 *   - Event consumer pattern (NemoClaw decides, we witness)
 *   - Stays out of the critical path (reads logs after decisions occur)
 *   - Complements OpenShell adapter (gate vs sandbox -- two independent attestations)
 *
 * Usage:
 *   import { NemoClawWitness } from "@tenova/swt3-ai/adapters/nemoclaw";
 *
 *   const ncw = new NemoClawWitness(witness);
 *   ncw.processEvent(policyDecisionObject);
 *
 *   await ncw.watchStream(asyncEventIterator);
 *   await ncw.watchLog("/var/log/nemoclaw/decisions.jsonl");
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

// -- NemoClaw Event to SWT3 Procedure Mapping --------------------------------

const NEMOCLAW_TO_PROCEDURE: Record<string, Record<string, string>> = {
  tool_request: {
    allow: "AI-TOOL.1",     // tool invocation permitted by policy
    deny: "AI-SAND.1",      // tool blocked by policy
  },
  network_request: {
    allow: "AI-ACC.1",      // network access permitted
    deny: "AI-ACC.1",       // network access denied
  },
  filesystem_request: {
    allow: "AI-DATA.1",     // file access permitted
    deny: "AI-ACC.1",       // file access denied
  },
  policy_evaluation: {
    pass: "AI-TOOL.2",      // tool permission set matches charter
    fail: "AI-TOOL.2",      // tool permission drift detected
  },
  credential_access: {
    allow: "AI-ACC.1",      // credential access permitted
    deny: "AI-ACC.1",       // credential access denied
  },
};

const DENIED_DECISIONS = new Set(["deny", "fail", "blocked"]);

const TOOL_PROCEDURES = new Set(["AI-TOOL.1", "AI-SAND.1", "AI-TOOL.2"]);
const ACCESS_PROCEDURES = new Set(["AI-ACC.1", "AI-DATA.1"]);

/** NemoClaw policy decision event shape (minimal fields consumed). */
export interface NemoClawEvent {
  request_type?: string;
  decision?: string;
  policy_rule?: string;
  policy_version?: string;
  resource?: string;
  agent_id?: string;
  timestamp?: number;
  evaluation_ms?: number;
}

/** Processing statistics. */
export interface NemoClawStats {
  processed: number;
  skipped: number;
}

function getProcedure(event: NemoClawEvent): string | null {
  const requestType = event.request_type ?? "";
  if (event.decision == null) return null;
  const decision = event.decision.toLowerCase();

  const mapping = NEMOCLAW_TO_PROCEDURE[requestType];
  if (!mapping) return null;

  return mapping[decision] ?? null;
}

// -- NemoClawWitness Class ---------------------------------------------------

/**
 * Consumes NVIDIA NemoClaw policy decision events and mints SWT3 anchors.
 *
 * Stays out of the critical path -- reads decisions after they occur.
 * Zero external dependencies beyond the SWT3 SDK.
 */
export class NemoClawWitness {
  private readonly witness: Witness;
  private eventsProcessed = 0;
  private eventsSkipped = 0;

  constructor(witness: Witness) {
    this.witness = witness;
  }

  /** Processing statistics. */
  get stats(): NemoClawStats {
    return {
      processed: this.eventsProcessed,
      skipped: this.eventsSkipped,
    };
  }

  /**
   * Process a single NemoClaw policy decision and mint the appropriate anchor.
   *
   * @param event - NemoClaw policy decision dict.
   * @returns The SWT3 procedure ID that was witnessed, or null if skipped.
   */
  processEvent(event: NemoClawEvent): string | null {
    const procedure = getProcedure(event);
    if (!procedure) {
      this.eventsSkipped++;
      return null;
    }

    this.eventsProcessed++;

    const timestampMs = event.timestamp ?? Date.now();
    const decision = (event.decision ?? "unknown").toLowerCase();
    const denied = DENIED_DECISIONS.has(decision);
    const resource = event.resource ?? event.request_type ?? "unknown";
    const policyRule = event.policy_rule ?? "default";
    const agentId = event.agent_id ?? "unknown";

    const modelId = `nemoclaw-${policyRule}`;

    const record: InferenceRecord = {
      model_id: modelId,
      model_hash: sha256Truncated(modelId, 16),
      prompt_hash: sha256Truncated(`${agentId}:${resource}:${timestampMs}`, 16),
      response_hash: sha256Truncated(`${decision}:${timestampMs}`, 16),
      latency_ms: event.evaluation_ms ?? 0,
      provider: "nvidia-nemoclaw",
      has_refusal: denied,
      guardrails_active: 1,
      guardrails_required: 1,
      guardrail_passed: !denied,
      tool_name: TOOL_PROCEDURES.has(procedure) ? resource : undefined,
      access_target: ACCESS_PROCEDURES.has(procedure) ? resource : undefined,
      access_granted: !denied,
    };

    this.witness.record(record, { procedures: [procedure] });
    return procedure;
  }

  /**
   * Process events from an async iterator.
   */
  async watchStream(stream: AsyncIterable<NemoClawEvent>): Promise<void> {
    for await (const event of stream) {
      this.processEvent(event);
    }
  }

  /**
   * Tail a NemoClaw decision log file and process events.
   *
   * Reads JSONL (one JSON decision per line). Tails indefinitely until
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
        const event: NemoClawEvent = JSON.parse(trimmed);
        this.processEvent(event);
      } catch {
        // skip non-JSON lines
      }
    }
  }
}
