/**
 * AI-TASK.1: Task Outcome Attestation (v8.3).
 *
 * Witnesses composite AI tasks -- bounded units of work comprising one or
 * more inferences -- and cryptographically binds the declared outcome to
 * the evidence chain of constituent steps via a Merkle rollup.
 */

import { mintFingerprint, sha256Truncated, timestampMs } from "./fingerprint";
import { getMerkleRoot } from "./merkle";
import type { WitnessPayload, TaskReceipt } from "./types";
import { COST_SOURCE_CODES, TASK_OUTCOME_CODES } from "./types";
import type { LifecycleChain } from "./witness";

type WitnessRef = {
  config: {
    tenantId: string;
    clearingLevel: number;
    policyVersion?: string;
    agentId?: string;
  };
  buffer: { enqueueMany(payloads: WitnessPayload[]): void };
  _applyOperationalMetadata(payload: WitnessPayload, policyHash?: string): void;
  _activeTask: TaskBuilder | null;
};

export function generateTaskId(tenantId: string, chainId: string, tsMs: number): string {
  const h = sha256Truncated(`TASK:${tenantId}:${chainId}:${tsMs}`, 16);
  return `TASK-${h}`;
}

/**
 * Estimate inference cost from token counts and model ID.
 * Stub for v8.3 -- returns 0. Provider billing API adapters in v8.4+.
 */
function estimateCost(_inputTokens: number, _outputTokens: number, _modelId: string): number {
  return 0;
}

/**
 * Accumulates step anchors and mints AI-TASK.1 on completion.
 *
 * Reuses existing LifecycleChain infrastructure for anchor linking.
 */
export class TaskBuilder {
  private _witness: WitnessRef;
  private _name: string;
  private _taskType: string;
  private _chain: LifecycleChain;
  private _steps: string[] = [];
  private _stepProcedures: Set<string> = new Set();
  private _startMs: number;
  private _costDeclared: number | null = null;
  private _costWitnessed: number = 0;
  private _costSource: number = 0;
  private _outcomeDesc: string | null = null;
  private _outcomeStatus: number = TASK_OUTCOME_CODES.completed;
  private _stepsComplete: boolean = false;
  private _explicitlyFailed: boolean = false;
  private _toolCallCount: number = 0;
  private _agentIds: Set<string> = new Set();
  private _lastReceipt: TaskReceipt | null = null;

  constructor(
    witness: unknown,
    name: string,
    taskType: string,
    chain: LifecycleChain,
  ) {
    this._witness = witness as WitnessRef;
    this._name = name;
    this._taskType = taskType;
    this._chain = chain;
    this._startMs = timestampMs()[0];
  }

  get chainId(): string { return this._chain.chainId; }
  get stepCount(): number { return this._steps.length; }
  get stepsComplete(): boolean { return this._stepsComplete; }
  get explicitlyFailed(): boolean { return this._explicitlyFailed; }

  /**
   * Register a sub-inference anchor as a task step.
   */
  addStep(options: { fingerprint?: string; payload?: WitnessPayload }): void {
    let fp = options.fingerprint;
    const p = options.payload;
    if (p) {
      fp = p.anchor_fingerprint;
      if (p.procedure_id) this._stepProcedures.add(p.procedure_id);
      if (p.ai_input_tokens && p.ai_output_tokens) {
        this._costWitnessed += estimateCost(
          p.ai_input_tokens, p.ai_output_tokens, p.ai_model_id ?? "unknown",
        );
      }
      if (p.procedure_id === "AI-TOOL.1") this._toolCallCount++;
      if (p.agent_id) this._agentIds.add(p.agent_id);
    }
    if (!fp) throw new Error("Either fingerprint or payload is required");
    this._steps.push(fp);
  }

  /**
   * Declare the provider's stated cost for the task (USD).
   */
  declareCost(options: { declared: number; source?: string }): void {
    this._costDeclared = options.declared;
    this._costSource = COST_SOURCE_CODES[options.source ?? "manual"] ?? 0;
  }

  /**
   * Declare the task outcome (hashed at clearing level 1+).
   */
  declareOutcome(description: string): void {
    this._outcomeDesc = description;
  }

  /**
   * Mark all inference steps as successfully completed.
   */
  markStepsComplete(): void {
    this._stepsComplete = true;
  }

  /**
   * Set outcome status (used by context manager on exception).
   */
  setOutcomeStatus(status: number): void {
    this._outcomeStatus = status;
  }

  /**
   * Mark the task as failed and mint the terminal anchor.
   */
  fail(reason: string = ""): TaskReceipt {
    this._explicitlyFailed = true;
    this._outcomeStatus = TASK_OUTCOME_CODES.failed;
    if (reason) this._outcomeDesc = reason;
    return this._finalize();
  }

  /**
   * Finalize the task and mint the AI-TASK.1 anchor.
   */
  complete(): TaskReceipt {
    return this._finalize();
  }

  _finalize(): TaskReceipt {
    const endMs = timestampMs()[0];
    const duration = Math.floor(endMs - this._startMs);

    const merkleRoot = this._steps.length > 0 ? getMerkleRoot(this._steps) : "";

    let costRatio = 0;
    if (this._costDeclared && this._costDeclared > 0 && this._costWitnessed > 0) {
      costRatio = Math.floor((this._costWitnessed / this._costDeclared) * 1000);
    }

    const fa = this._steps.length;
    const fb = costRatio;
    const fc = this._outcomeStatus;

    const taskId = generateTaskId(
      this._witness.config.tenantId, this._chain.chainId, this._startMs,
    );

    // Mint terminal anchor (bypass chain._mint for clearing-level control)
    const w = this._witness;
    const [ts, ep] = timestampMs();
    const fp = mintFingerprint(w.config.tenantId, "AI-TASK.1", fa, fb, fc, ts);
    const policyHash = w.config.policyVersion
      ? sha256Truncated(w.config.policyVersion, 12)
      : undefined;

    const payload: WitnessPayload = {
      procedure_id: "AI-TASK.1",
      factor_a: fa,
      factor_b: fb,
      factor_c: fc,
      clearing_level: w.config.clearingLevel as 0 | 1 | 2 | 3,
      anchor_fingerprint: fp,
      anchor_epoch: ep,
      fingerprint_timestamp_ms: ts,
      lifecycle_chain_id: this._chain.chainId,
      lifecycle_parent: this._chain.lastFingerprint,
      lifecycle_stage: "resolved",
    };

    const clearing = w.config.clearingLevel;
    const envelope = this._buildEnvelope(taskId, merkleRoot, duration, costRatio, clearing);

    if (clearing < 3 && Object.keys(envelope).length > 0) {
      payload.ai_context = { provider: "task", ...envelope };
    }

    w._applyOperationalMetadata(payload, policyHash);
    w.buffer.enqueueMany([payload]);

    // Update chain state
    const chain = this._chain as any;
    chain._lastFingerprint = fp;
    chain._anchorCount++;
    chain._closed = true;

    // Clear active task on witness (manual builder cleanup)
    if (w._activeTask === this) {
      w._activeTask = null;
    }

    this._lastReceipt = {
      taskId,
      merkleRoot,
      stepCount: this._steps.length,
      chainId: this._chain.chainId,
      durationMs: duration,
      costRatio: costRatio || null,
      anchor: payload,
    };
    return this._lastReceipt;
  }

  private _buildEnvelope(
    taskId: string,
    merkleRoot: string,
    duration: number,
    costRatio: number,
    clearing: number,
  ): Record<string, unknown> {
    if (clearing >= 3) return {};

    const envelope: Record<string, unknown> = {
      task_id: taskId,
      outcome_status: this._outcomeStatus,
      outcome_hash: sha256Truncated(this._outcomeDesc ?? "", 16),
      step_count: this._steps.length,
      merkle_root: merkleRoot,
      step_procedures: [...this._stepProcedures].sort(),
      duration_ms: duration,
      start_epoch: Math.floor(this._startMs / 1000),
      end_epoch: Math.floor((this._startMs + duration) / 1000),
      tool_call_count: this._toolCallCount,
    };

    if (clearing === 0 && this._outcomeDesc) {
      envelope.declared_outcome = this._outcomeDesc;
    }

    if (clearing <= 1) {
      envelope.task_type = this._taskType;
      envelope.lifecycle_chain_id = this._chain.chainId;
      if (this._costDeclared !== null) {
        envelope.cost_declared = Math.floor(this._costDeclared * 1_000_000);
        envelope.cost_source = this._costSource;
      }
      if (this._costWitnessed > 0) {
        envelope.cost_witnessed = Math.floor(this._costWitnessed * 1_000_000);
      }
      envelope.cost_ratio = costRatio;
      const sortedAgents = [...this._agentIds].sort();
      envelope.agent_ids = clearing >= 1
        ? sortedAgents.map((a) => sha256Truncated(a, 8))
        : sortedAgents;
    }

    return envelope;
  }
}
