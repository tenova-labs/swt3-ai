/**
 * SWT3 AI Witness SDK — Core Witness class.
 *
 * Usage:
 *   import { Witness } from "@tenova/swt3-ai";
 *   import OpenAI from "openai";
 *
 *   const witness = new Witness({
 *     endpoint: "https://sovereign.tenova.io",
 *     apiKey: "axm_live_...",
 *     tenantId: "YOUR_TENANT_ID",
 *   });
 *
 *   const client = witness.wrap(new OpenAI()) as OpenAI;
 *   const response = await client.chat.completions.create({ ... });
 *
 *   // Graceful shutdown
 *   await witness.flush();
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { randomUUID } from "node:crypto";
import { sha256Truncated, mintFingerprint, timestampMs } from "./fingerprint.js";
import { extractPayloads, extractGatekeeperPayload, extractRevocationPayload, extractChainTrustDegradationPayload, REVOCATION_REASONS } from "./clearing.js";
import { signPayload } from "./signing.js";
import { WitnessBuffer } from "./buffer.js";
import { WriteAheadLog } from "./wal.js";
import { writeHandoffFiles } from "./handoff.js";
import { wrapOpenAI } from "./adapters/openai.js";
import { wrapAnthropic } from "./adapters/anthropic.js";
import { wrapBedrock } from "./adapters/bedrock.js";
import { wrapOllama, isOllamaClient } from "./adapters/ollama.js";
import { wrapVllm } from "./adapters/vllm.js";
import { queryHardware as queryHw, topologyCode as topoCode, queryTPM as queryTpm, ZERO_PCR_HASH } from "./hardware.js";
import type { TPMSnapshot } from "./hardware.js";
import { queryEnvironment as queryEnv, NODE_TYPE_CODES } from "./environment.js";
import type { EnvironmentSnapshot } from "./environment.js";
import {
  TrustRegistry, verifyCredential, signCredential, TRUST_LEVEL_NAMES,
  type TrustCredential, type TrustResult,
} from "./trust.js";
import { createVercelOnFinish, type VercelOnFinishOptions } from "./adapters/vercel-ai.js";
import type {
  WitnessConfig, WitnessPayload, WitnessReceipt, InferenceRecord,
  RagChunk, RagContextOptions, ModelWeightInfo, AdapterInfo, SkillInfo, MemorySource,
} from "./types.js";
import { QUANTIZATION_CODES, POLICY_CATEGORIES, BINDING_METHODS, APPROVAL_STATUS, PII_EVENT_TYPES, CONTENT_TYPE_CODES, BASELINE_MODE_CODES, LICENSE_TYPE_CODES, SBOM_FORMAT_CODES, REDTEAM_CATEGORY_CODES, CONSENT_BASIS_CODES, DRIFT_TYPE_CODES, LOG_FORMAT_CODES, INCIDENT_SEVERITY_CODES, INCIDENT_TYPE_CODES, BENCHMARK_TYPE_CODES, PERTURBATION_TYPE_CODES, CYBER_FRAMEWORK_CODES, DISCLOSURE_TYPE_CODES, RECIPIENT_TYPE_CODES, DETECTION_METHOD_CODES, PROCESSING_TYPE_CODES, DECISION_TYPE_CODES, CLASSIFICATION_CODES, REPORTING_STATUS_CODES, SUPPLY_RISK_CODES, PMM_TYPE_CODES } from "./types.js";
import { loadConfig as loadConfigFromFile, loadFullConfig, validatePolicy } from "./config.js";
import type { TrustMeshConfig, HardwareConfig, DensityPolicyConfig, McpPolicyConfig, MerkleConfig, ChainRule, ChainPolicyViolation, RuntimeProfileConfig } from "./types.js";
import { MerkleAccumulator } from "./merkle.js";

// ── Chain Density Enforcement ──────────────────────────────────────────

function globToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp("^" + escaped + "$");
}

function parseVelocity(spec: string): { limit: number; windowMs: number } {
  const parts = spec.split("/");
  const limit = parseInt(parts[0], 10);
  const windowS = parseInt(parts[1].replace("s", ""), 10);
  return { limit, windowMs: windowS * 1000 };
}

export class PolicyViolationError extends Error {
  violation: ChainPolicyViolation;
  constructor(violation: ChainPolicyViolation) {
    super(`Chain policy violation: ${violation.reason}`);
    this.name = "PolicyViolationError";
    this.violation = violation;
  }
}

/**
 * Chain density enforcement engine.
 *
 * Evaluates tool calls against rate limits, depth limits, allow/blocklists,
 * and custom rules. All checks are in-memory, zero network calls.
 * Instantiated from McpPolicyConfig by Witness.fromConfig().
 */
export class ChainEnforcer {
  private velocityWindow: number[] = [];
  private velocityLimit = 0;
  private velocityWindowMs = 0;
  private chainDepth = 0;
  private maxChainDepth: number;
  private allowPatterns: RegExp[] | null;
  private blockPatterns: RegExp[];
  private failSecure: boolean;
  private customRules: Array<ChainRule & { regex: RegExp }>;
  private lastToolName: string | null = null;
  private tokenCount = 0;
  private maxTokensPerSession: number;
  private _violations: ChainPolicyViolation[] = [];

  constructor(policy: McpPolicyConfig) {
    if (policy.maxVelocity) {
      const parsed = parseVelocity(policy.maxVelocity);
      this.velocityLimit = parsed.limit;
      this.velocityWindowMs = parsed.windowMs;
    }
    this.maxChainDepth = policy.maxChainDepth ?? Infinity;
    this.maxTokensPerSession = policy.maxTokensPerSession ?? Infinity;
    this.allowPatterns = (policy.toolAllowlist?.length)
      ? policy.toolAllowlist.map(globToRegex)
      : null;
    this.blockPatterns = (policy.toolBlocklist ?? []).map(globToRegex);
    this.failSecure = policy.failSecure ?? true;
    this.customRules = (policy.rules ?? []).map((r) => ({
      ...r,
      regex: globToRegex(r.match),
    }));
  }

  check(toolName: string): ChainPolicyViolation | null {
    const now = Date.now();

    // 1. Blocklist
    for (const pattern of this.blockPatterns) {
      if (pattern.test(toolName)) {
        return this.violation("blocklist", toolName, "blocked",
          `Tool "${toolName}" is on the blocklist`, now);
      }
    }

    // 2. Allowlist (skip if null = all allowed)
    if (this.allowPatterns) {
      const allowed = this.allowPatterns.some((p) => p.test(toolName));
      if (!allowed) {
        return this.violation("allowlist", toolName, "blocked",
          `Tool "${toolName}" is not on the allowlist`, now);
      }
    }

    // 3. Velocity (sliding window)
    if (this.velocityLimit > 0) {
      const cutoff = now - this.velocityWindowMs;
      while (this.velocityWindow.length > 0 && this.velocityWindow[0] <= cutoff) {
        this.velocityWindow.shift();
      }
      if (this.velocityWindow.length >= this.velocityLimit) {
        const action = this.failSecure ? "blocked" : "logged";
        return this.violation("velocity", toolName, action,
          `Rate limit exceeded: ${this.velocityLimit} calls per ${this.velocityWindowMs / 1000}s`, now,
          { currentCount: this.velocityWindow.length, limit: this.velocityLimit });
      }
      this.velocityWindow.push(now);
    }

    // 4. Depth tracking
    if (this.maxChainDepth < Infinity) {
      if (toolName !== this.lastToolName && this.lastToolName !== null) {
        this.chainDepth = 0;
      }
      this.chainDepth++;
      this.lastToolName = toolName;

      if (this.chainDepth > this.maxChainDepth) {
        const action = this.failSecure ? "blocked" : "logged";
        return this.violation("depth", toolName, action,
          `Chain depth ${this.chainDepth} exceeds max ${this.maxChainDepth}`, now,
          { currentDepth: this.chainDepth, maxDepth: this.maxChainDepth });
      }
    }

    // 5. Token budget
    if (this.maxTokensPerSession < Infinity && this.tokenCount >= this.maxTokensPerSession) {
      const action = this.failSecure ? "blocked" : "logged";
      const v = this.violation("token_budget", toolName, action,
        `Token budget exceeded: ${this.tokenCount} tokens consumed, limit is ${this.maxTokensPerSession}`, now,
        { currentTokens: this.tokenCount, limit: this.maxTokensPerSession });
      this._violations.push(v);
      return v;
    }

    // 6. Custom rules
    for (const rule of this.customRules) {
      if (rule.regex.test(toolName)) {
        return this.violation(`custom:${rule.reason}`, toolName,
          rule.action === "block" ? "blocked" : "logged",
          rule.reason, now, rule.params);
      }
    }

    return null;
  }

  resetDepth(): void {
    this.chainDepth = 0;
    this.lastToolName = null;
  }

  recordTokens(count: number): void {
    this.tokenCount += count;
  }

  resetTokens(): void {
    this.tokenCount = 0;
  }

  get currentTokenCount(): number {
    return this.tokenCount;
  }

  get violations(): readonly ChainPolicyViolation[] {
    return this._violations;
  }

  clearViolations(): void {
    this._violations = [];
  }

  private violation(
    rule: string, toolName: string, action: "blocked" | "logged",
    reason: string, timestamp: number, context?: Record<string, unknown>,
  ): ChainPolicyViolation {
    const v: ChainPolicyViolation = { rule, toolName, action, reason, timestamp, ...(context ? { context } : {}) };
    this._violations.push(v);
    return v;
  }
}

export interface WitnessOptions {
  endpoint: string;
  apiKey: string;
  tenantId: string;
  clearingLevel?: 0 | 1 | 2 | 3;
  bufferSize?: number;
  flushInterval?: number;
  timeout?: number;
  maxRetries?: number;
  latencyThresholdMs?: number;
  guardrailsRequired?: number;
  guardrailNames?: string[];
  procedures?: string[];
  factorHandoff?: "file";
  factorHandoffPath?: string;
  agentId?: string;
  signingKey?: string;
  signingAlgorithm?: "hmac-sha256" | "ml-dsa-65";
  cycleId?: string;
  strict?: boolean;
  policyVersion?: string;
  jurisdiction?: string;
  legalBasis?: string;
  purposeClass?: string;
  onFlush?: (payloads: WitnessPayload[], receipts: WitnessReceipt[]) => void;
  tokenBudget?: number;
  chainMinTrustLevel?: number;
  onViolation?: (violation: ChainPolicyViolation) => void;
  gatewayMode?: boolean;
  walPath?: string;
  replayWindow?: number;
  digestAlgorithm?: string;
}

/**
 * Raised when strict (gatekeeper) mode blocks an inference due to
 * insufficient guardrails. The inference never reaches the AI model.
 */
export class GatekeeperError extends Error {
  readonly required: number;
  readonly active: number;
  readonly missingNames: string[];

  constructor(required: number, active: number, missingNames: string[] = []) {
    const msg = `Gatekeeper blocked: ${active} guardrails active, ${required} required` +
      (missingNames.length ? `. Missing: ${missingNames.join(", ")}` : "");
    super(msg);
    this.name = "GatekeeperError";
    this.required = required;
    this.active = active;
    this.missingNames = missingNames;
  }
}

export class ChainTrustError extends Error {
  readonly effectiveTrustLevel: number;
  readonly minimumRequired: number;

  constructor(effective: number, minimum: number) {
    super(`Chain trust blocked: effective level ${effective} below minimum ${minimum}`);
    this.name = "ChainTrustError";
    this.effectiveTrustLevel = effective;
    this.minimumRequired = minimum;
  }
}

export class Witness {
  private config: WitnessConfig;
  private buffer: WitnessBuffer;
  private handoffWarned = false;
  private _strict: boolean;
  private _gatewayMode: boolean;
  private _chainTrustLevels: number[] = [];
  private _onViolation?: (violation: ChainPolicyViolation) => void;
  private _walPath?: string;

  /** True if the SDK is deferring witnessing to an SWT3 Gateway. */
  get gatewayMode(): boolean {
    return this._gatewayMode;
  }

  /**
   * Create a Witness from a .swt3.yaml config file.
   *
   * @param path - Explicit path to YAML file. If omitted, searches for
   *               swt3.yaml or .swt3.yaml in the current directory.
   * @param overrides - Override any field from the YAML file.
   *                    Code takes precedence over config file.
   * @returns Configured Witness instance.
   *
   * Requires: `npm install yaml`
   */
  static fromConfig(path?: string, overrides?: Partial<WitnessOptions>): Witness {
    const loaded = loadFullConfig(path);
    const mergedOptions = { ...loaded.witnessOptions, ...overrides };

    // Re-validate policy AFTER overrides to prevent silent downgrades
    if (loaded.policy && overrides) {
      validatePolicy(mergedOptions as Record<string, unknown>, {
        require_signing: loaded.policy.requireSigning,
        min_clearing_level: loaded.policy.minClearingLevel,
        required_procedures: loaded.policy.requiredProcedures,
        require_agent_id: loaded.policy.requireAgentId,
        max_flush_interval: loaded.policy.maxFlushInterval,
        require_jurisdiction: loaded.policy.requireJurisdiction,
      });
    }

    const witness = new Witness(mergedOptions as WitnessOptions);

    witness._configHash = loaded.configHash;

    if (loaded.trustMesh) {
      witness._configureTrustMesh(loaded.trustMesh);
    }

    if (loaded.hardware) {
      witness._hardwareConfig = loaded.hardware;
      if (loaded.hardware.requireAttestation) {
        witness.witnessHardware();
      }
      if (loaded.hardware.runtimeProfile && witness._lastHwSnapshot) {
        witness._validateRuntimeProfile(loaded.hardware.runtimeProfile, witness._lastHwSnapshot);
      }
    }

    if (loaded.skillCard && loaded.skillCard.skills.length > 0) {
      witness.witnessSkillManifest(loaded.skillCard.skills, {
        expectedManifestHash: loaded.skillCard.expectedManifestHash,
      });
    }

    if (loaded.densityPolicy) {
      witness._densityPolicy = loaded.densityPolicy;
    }

    if (loaded.mcpPolicy) {
      witness._mcpPolicy = loaded.mcpPolicy;
      const p = loaded.mcpPolicy;
      if (p.maxVelocity || p.maxChainDepth !== undefined || p.maxTokensPerSession !== undefined ||
          p.toolAllowlist?.length || p.toolBlocklist?.length || p.rules?.length) {
        witness._chainEnforcer = new ChainEnforcer(p);
      }
    }

    if (loaded.merkle) {
      witness._merkleConfig = loaded.merkle;
      if (loaded.merkle.enabled) {
        witness._merkleAccumulator = new MerkleAccumulator({
          tenantId: (loaded.witnessOptions as Record<string, unknown>).tenantId as string
            ?? (loaded.witnessOptions as Record<string, unknown>).tenant_id as string,
        });
      }
    }

    // Fire-and-forget sentinel auto-detection (patent pending).
    // Non-blocking: <10ms probe. If daemon is running, wrapTool/record
    // will delegate to it. If not, SDK operates standalone as before.
    witness._detectSentinelAsync();

    return witness;
  }

  private _configHash?: string;
  private _hardwareConfig?: HardwareConfig;
  private _lastHwSnapshot?: import("./hardware.js").HardwareSnapshot;
  private _densityPolicy?: DensityPolicyConfig;
  private _mcpPolicy?: McpPolicyConfig;
  private _merkleConfig?: MerkleConfig;
  private _merkleAccumulator?: MerkleAccumulator;
  private _chainEnforcer?: ChainEnforcer;
  private _sentinel?: import("./sentinel-client.js").SentinelClient;
  private _sentinelDetecting = false;

  get configHash(): string | undefined {
    return this._configHash;
  }

  /** Density policy from YAML config (null if not configured). */
  get densityPolicy(): DensityPolicyConfig | undefined {
    return this._densityPolicy;
  }

  /** MCP tool witnessing policy from YAML config (null if not configured). */
  get mcpPolicy(): McpPolicyConfig | undefined {
    return this._mcpPolicy;
  }

  /** Merkle accumulator config from YAML config (null if not configured). */
  get merkleConfig(): MerkleConfig | undefined {
    return this._merkleConfig;
  }

  /** SDK-side Merkle accumulator (created when merkle.enabled is true). */
  get merkleAccumulator(): MerkleAccumulator | undefined {
    return this._merkleAccumulator;
  }

  /** Chain density enforcer (created when chain density fields are configured). */
  get chainEnforcer(): ChainEnforcer | undefined {
    return this._chainEnforcer;
  }

  /** Connected sentinel daemon client (null if no daemon detected). */
  get sentinel(): import("./sentinel-client.js").SentinelClient | undefined {
    return this._sentinel;
  }

  /**
   * Connect to a running swt3-sentinel daemon.
   *
   * When connected, chain enforcement, signing, and WAL operations are
   * delegated to the isolated daemon process. If the daemon is not running,
   * returns false and the SDK continues with local enforcement.
   *
   * This method is called automatically by fromConfig() in fire-and-forget
   * mode. You only need to call it explicitly if you want to await the
   * connection or use a custom socket path.
   */
  async connectSentinel(socketPath?: string): Promise<boolean> {
    try {
      const { SentinelClient } = await import("./sentinel-client.js");
      const client = await SentinelClient.detect(socketPath);
      if (client) {
        this._sentinel = client;
        return true;
      }
    } catch {
      // Sentinel not available -- silent fallback
    }
    return false;
  }

  /**
   * Fire-and-forget sentinel detection. Called from fromConfig().
   * Non-blocking: takes <10ms, resolves in background.
   */
  private _detectSentinelAsync(): void {
    if (this._sentinelDetecting) return;
    this._sentinelDetecting = true;
    this.connectSentinel().finally(() => {
      this._sentinelDetecting = false;
    });
  }

  /** Record token usage against the chain enforcer's session budget. */
  recordSessionTokens(count: number): void {
    if (this._chainEnforcer) {
      this._chainEnforcer.recordTokens(count);
    }
    // Mirror to sentinel for cross-process shared budget
    if (this._sentinel?.connected) {
      this._sentinel.recordTokens(count).catch(() => {});
    }
  }

  /** Set or replace the violation callback at runtime. */
  set onViolation(cb: ((violation: ChainPolicyViolation) => void) | undefined) {
    this._onViolation = cb;
  }

  private _fireViolation(violation: ChainPolicyViolation): void {
    if (this._onViolation) {
      try { this._onViolation(violation); } catch (e) {
        if (typeof process !== "undefined" && process.env.SWT3_DEBUG) {
          console.error("SWT3: onViolation callback threw:", e);
        }
      }
    }
  }

  private _recordChainViolation(violation: ChainPolicyViolation): void {
    const record: InferenceRecord = {
      modelId: violation.toolName,
      modelHash: sha256Truncated(violation.toolName),
      promptHash: sha256Truncated(violation.rule),
      responseHash: sha256Truncated(violation.reason),
      latencyMs: 0,
      guardrailsActive: 0,
      guardrailsRequired: 0,
      guardrailPassed: false,
      hasRefusal: true,
      provider: "chain-enforcer",
      guardrailNames: [],
      toolName: violation.toolName,
      toolCallId: `chain-${violation.timestamp}`,
    };
    this.record(record);
    this._fireViolation(violation);
  }

  private _configureTrustMesh(mesh: TrustMeshConfig): void {
    const registry = this.trustRegistry;
    for (const t of mesh.trustedTenants) registry.trustTenant(t);
    for (const ta of mesh.trustedAgents) registry.trustAgent(ta.tenant, ta.agent);
    for (const a of mesh.denyAgents) registry.denyAgent(a);
    for (const t of mesh.denyTenants) registry.denyTenant(t);
    registry.setRequireSignature(mesh.requireSignature);
    registry.setMinTrustLevel(mesh.minTrustLevel);
    registry.setFreshnessWindow(mesh.freshnessWindow);
    if (mesh.requiredProcedures.length > 0) {
      registry.setRequiredProcedures(mesh.requiredProcedures);
    }
    for (const sk of mesh.signingKeys) {
      registry.registerSigningKey(sk.agent, sk.key);
    }
    if (mesh.mode === "strict" && !mesh.requireSignature) {
      registry.setRequireSignature(true);
    }
  }

  constructor(options: WitnessOptions) {
    this._gatewayMode = options.gatewayMode ?? false;

    // Gateway mode: SDK defers all witnessing to the SWT3 Gateway.
    if (!this._gatewayMode) {
      if (!options.endpoint) throw new Error("endpoint is required (or set gatewayMode: true)");
      if (!options.apiKey) throw new Error("apiKey is required (or set gatewayMode: true)");
      if (!options.apiKey.startsWith("axm_")) throw new Error("apiKey must start with 'axm_'");
    }
    if (!options.tenantId && !this._gatewayMode) throw new Error("tenantId is required");
    if (options.factorHandoff && options.factorHandoff !== "file") {
      throw new Error("factorHandoff must be 'file'");
    }
    if (options.factorHandoff === "file" && !options.factorHandoffPath) {
      throw new Error("factorHandoffPath is required when factorHandoff is 'file'");
    }

    this.config = {
      endpoint: (options.endpoint || "unused").replace(/\/+$/, ""),
      apiKey: options.apiKey || "axm_gateway",
      tenantId: options.tenantId || "GATEWAY",
      clearingLevel: options.clearingLevel ?? 1,
      bufferSize: options.bufferSize ?? 10,
      flushInterval: options.flushInterval ?? 5.0,
      timeout: options.timeout ?? 10000,
      maxRetries: options.maxRetries ?? 3,
      latencyThresholdMs: options.latencyThresholdMs ?? 30000,
      guardrailsRequired: options.guardrailsRequired ?? 0,
      guardrailNames: options.guardrailNames ?? [],
      procedures: options.procedures,
      factorHandoff: options.factorHandoff,
      factorHandoffPath: options.factorHandoffPath,
      agentId: options.agentId,
      signingKey: options.signingKey,
      cycleId: options.cycleId,
      policyVersion: options.policyVersion,
      jurisdiction: options.jurisdiction,
      legalBasis: options.legalBasis,
      purposeClass: options.purposeClass,
      tokenBudget: options.tokenBudget,
      chainMinTrustLevel: options.chainMinTrustLevel,
      onFlush: options.onFlush,
    };

    this._strict = options.strict ?? false;
    this._onViolation = options.onViolation;
    this._walPath = options.walPath;

    // WAL: crash-resilient buffer persistence + replay protection (patent pending)
    let wal: WriteAheadLog | undefined;
    if (options.walPath) {
      wal = new WriteAheadLog(this.config.tenantId, {
        walDir: options.walPath,
        replayWindow: options.replayWindow,
      });
    }

    this.buffer = new WitnessBuffer(this.config, undefined, wal);

    // Recover any unflushed payloads from a previous crash
    if (wal) {
      const recovered = wal.recover();
      if (recovered.length > 0) {
        this.buffer.enqueueMany(recovered);
      }
    }
  }

  /**
   * Wrap an AI client with transparent witnessing.
   *
   * Supported: OpenAI, Ollama (auto-detected), Anthropic, Bedrock.
   * For vLLM, use wrapVllm() from adapters/vllm.
   *
   * Usage:
   *   const client = witness.wrap(new OpenAI()) as OpenAI;
   *   const client = witness.wrap(new Anthropic()) as Anthropic;
   */
  wrap(client: unknown): unknown {
    const proto = Object.getPrototypeOf(client);
    const name = proto?.constructor?.name ?? "";
    const obj = client as Record<string, unknown>;

    // OpenAI: has client.chat.completions
    if (name === "OpenAI" || obj?.chat) {
      // Check for Ollama before defaulting to OpenAI
      if (isOllamaClient(client)) {
        return wrapOllama(client, this);
      }
      return wrapOpenAI(client, this);
    }

    // Anthropic: has client.messages
    if (name === "Anthropic" || (obj?.messages && !obj?.chat)) {
      return wrapAnthropic(client, this);
    }

    // AWS Bedrock: has client.send and client.config
    if (name === "BedrockRuntimeClient" || (obj?.send && (obj as Record<string, unknown>)?.config)) {
      return wrapBedrock(client, this);
    }

    throw new TypeError(
      `Unsupported client: ${name || "unknown"}. Supported: OpenAI, Ollama, Anthropic, BedrockRuntimeClient, vLLM (via wrapVllm).`,
    );
  }

  /** Whether strict (gatekeeper) mode is enabled. Used by adapters. */
  get strict(): boolean {
    return this._strict;
  }

  /**
   * Pre-call guardrail gate (strict mode only).
   *
   * Evaluates whether configured guardrail requirements are met BEFORE
   * the inference call reaches the AI model. If requirements are not met,
   * throws `GatekeeperError` and mints an AI-GRD.3 anchor recording
   * the rejection. The rejection is evidence — it is enqueued for flush.
   *
   * This method is SYNCHRONOUS — evaluates local config only, no network.
   *
   * @throws {GatekeeperError} if guardrail requirements are not met
   */
  gateCheck(_messages?: unknown, _model?: string): string {
    const required = this.config.guardrailsRequired;
    const active = this.config.guardrailNames.length;
    const gatePassed = active >= required;

    // Mint AI-GRD.3 anchor regardless of outcome — rejection is evidence
    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;
    const payload = extractGatekeeperPayload(
      this.config.tenantId,
      required,
      active,
      gatePassed,
      this.config.clearingLevel,
      this.config.agentId,
      this.config.signingKey,
      this.config.signingKeyId,
      this.config.signingKeyVersion,
      this.config.cycleId,
      policyHash,
      this.config.jurisdiction,
      this.config.legalBasis,
      this.config.purposeClass,
      this.config.signingAlgorithm,
    );
    this.buffer.enqueueMany([payload]);

    if (!gatePassed) {
      throw new GatekeeperError(required, active);
    }

    return payload.anchor_fingerprint;
  }

  /**
   * Wrap a function as a witnessed tool call (AI-TOOL.1).
   *
   * Usage:
   *   const search = witness.wrapTool(searchDatabase, "search_db");
   *   const result = await search("SELECT ...");
   *
   * Each call mints an AI-TOOL.1 anchor with:
   *   factor_a = 1 (tool was called)
   *   factor_b = latency_ms
   *   factor_c = 1 if succeeded, 0 if exception raised
   */
  wrapTool<T extends (...args: any[]) => any>(fn: T, toolName?: string): T {
    const name = toolName ?? fn.name ?? "anonymous";
    const self = this;

    const wrapper = function (this: any, ...args: any[]): any {
      // Chain density enforcement -- BEFORE execution.
      // Local enforcer runs synchronously (fast path).
      // Sentinel (if connected) mirrors the check for cross-process shared state.
      if (self._chainEnforcer) {
        const violation = self._chainEnforcer.check(name);
        if (violation) {
          if (violation.action === "blocked") {
            self._fireViolation(violation);
            throw new PolicyViolationError(violation);
          }
          self._recordChainViolation(violation);
        }
      }
      // Mirror to sentinel for cross-process state (fire-and-forget).
      if (self._sentinel?.connected) {
        self._sentinel.check(name).catch(() => {});
      }

      const callId = randomUUID().replace(/-/g, "").slice(0, 12);
      const start = performance.now();
      let succeeded = true;
      let result: any;

      const finish = () => {
        const elapsedMs = Math.round(performance.now() - start);
        const inputHash = sha256Truncated(JSON.stringify(args));
        const outputHash = sha256Truncated(succeeded ? JSON.stringify(result) : "ERROR");

        const record: InferenceRecord = {
          modelId: name,
          modelHash: sha256Truncated(name),
          promptHash: inputHash,
          responseHash: outputHash,
          latencyMs: elapsedMs,
          guardrailsActive: 0,
          guardrailsRequired: 0,
          guardrailPassed: true,
          hasRefusal: !succeeded,
          provider: "tool",
          guardrailNames: [],
          toolName: name,
          toolCallId: callId,
        };

        self.record(record);
      };

      try {
        result = fn.apply(this, args);
      } catch (err) {
        succeeded = false;
        finish();
        throw err;
      }

      // Handle async functions (Promise detection)
      if (result && typeof result.then === "function") {
        return result.then(
          (v: any) => {
            result = v;
            finish();
            return v;
          },
          (err: any) => {
            succeeded = false;
            finish();
            throw err;
          },
        );
      }

      finish();
      return result;
    };

    return wrapper as unknown as T;
  }

  /**
   * Wrap a function as a witnessed access attempt (AI-ACC.1).
   *
   * Usage:
   *   const queryDb = witness.wrapAccess(dbQuery, "prod-database", "read-only analytics");
   *   const result = await queryDb("SELECT ...");
   *
   * Each call mints an AI-ACC.1 anchor with:
   *   factor_a = 1 (access attempt occurred)
   *   factor_b = 1 if within declared scope (or no scope set), 0 if out of scope
   *   factor_c = 1 if access granted, 0 if denied/failed
   */
  wrapAccess<T extends (...args: any[]) => any>(
    fn: T,
    resourceName?: string,
    scope?: string,
  ): T {
    const name = resourceName ?? fn.name ?? "unknown-resource";
    const self = this;

    const wrapper = function (this: any, ...args: any[]): any {
      const start = performance.now();
      let granted = true;
      let result: any;

      const finish = () => {
        const elapsedMs = Math.round(performance.now() - start);
        const inputHash = sha256Truncated(JSON.stringify(args));
        const outputHash = sha256Truncated(granted ? JSON.stringify(result) : "ACCESS_DENIED");

        const record: InferenceRecord = {
          modelId: name,
          modelHash: sha256Truncated(name),
          promptHash: inputHash,
          responseHash: outputHash,
          latencyMs: elapsedMs,
          guardrailsActive: 0,
          guardrailsRequired: 0,
          guardrailPassed: true,
          hasRefusal: !granted,
          provider: "access",
          guardrailNames: [],
          accessTarget: name,
          accessGranted: granted,
          accessScope: scope,
        };

        self.record(record);
      };

      try {
        result = fn.apply(this, args);
      } catch (err) {
        granted = false;
        finish();
        throw err;
      }

      // Handle async functions (Promise detection)
      if (result && typeof result.then === "function") {
        return result.then(
          (v: any) => {
            result = v;
            finish();
            return v;
          },
          (err: any) => {
            granted = false;
            finish();
            throw err;
          },
        );
      }

      finish();
      return result;
    };

    return wrapper as unknown as T;
  }

  /**
   * Witness a security/adversarial detection result (AI-SEC.1).
   *
   * Call after running your own detection system (Prompt Guard, LlamaGuard,
   * NeMo Guardrails, etc.) to record the result as a tamper-evident anchor.
   *
   * @param threatScore - Detection score from your system (0-1000 scale).
   * @param options.threshold - Score above which input is a threat. Default 500.
   * @param options.threatType - One of: none, prompt_injection, data_poisoning,
   *   model_extraction, jailbreak, adversarial_input.
   *
   * @example
   *   const score = await promptGuard.scan(userInput);
   *   witness.witnessSecurityScan(score, { threatType: "prompt_injection" });
   */
  witnessSecurityScan(
    threatScore: number,
    options?: { threshold?: number; threatType?: string },
  ): void {
    const threshold = options?.threshold ?? 500;
    const threatType = options?.threatType ?? "none";
    const threatCodes: Record<string, number> = {
      none: 0, prompt_injection: 1, data_poisoning: 2,
      model_extraction: 3, jailbreak: 4, adversarial_input: 5,
    };

    const [ts, epoch] = timestampMs();
    const fa = threshold;
    const fb = threatScore;
    const fc = threatCodes[threatType] ?? 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-SEC.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-SEC.1",
      factor_a: fa,
      factor_b: fb,
      factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp,
      anchor_epoch: epoch,
      fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "security-scan";
      payload.ai_context = { provider: "security" };
    }

    if (this.config.agentId) payload.agent_id = this.config.agentId;
    if (this.config.cycleId) payload.cycle_id = this.config.cycleId;
    if (this.config.jurisdiction) payload.jurisdiction = this.config.jurisdiction;
    if (this.config.legalBasis) payload.legal_basis = this.config.legalBasis;
    if (this.config.purposeClass) payload.purpose_class = this.config.purposeClass;
    if (this.config.policyVersion) {
      payload.policy_version_hash = sha256Truncated(this.config.policyVersion, 12);
    }
    if (this.config.signingKey) {
      const algo = this.config.signingAlgorithm ?? "hmac-sha256";
      payload.payload_signature = signPayload(this.config.signingKey, fp, this.config.agentId, algo);
      payload.signing_algorithm = algo;
      if (this.config.signingKeyId) payload.signing_key_id = this.config.signingKeyId;
      if (this.config.signingKeyVersion !== undefined) payload.signing_key_version = this.config.signingKeyVersion;
    }

    this.buffer.enqueueMany([payload]);
  }

  /**
   * Witness an input validation/sanitization result (AI-SEC.2).
   *
   * Call after validating or sanitizing user input before inference.
   *
   * @param passed - True if input accepted (clean or sanitized). False if blocked.
   * @param options.sanitized - True if input was modified during validation.
   *
   * @example
   *   const { clean, modified } = mySanitizer.validate(userInput);
   *   witness.witnessInputValidation(clean, { sanitized: modified });
   */
  witnessInputValidation(
    passed: boolean,
    options?: { sanitized?: boolean },
  ): void {
    const sanitized = options?.sanitized ?? false;

    const [ts, epoch] = timestampMs();
    const fa = 1;
    const fb = passed ? 1 : 0;
    const fc = (passed && !sanitized) ? 0 : (passed && sanitized) ? 1 : 2;
    const fp = mintFingerprint(this.config.tenantId, "AI-SEC.2", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-SEC.2",
      factor_a: fa,
      factor_b: fb,
      factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp,
      anchor_epoch: epoch,
      fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "input-validation";
      payload.ai_context = { provider: "security" };
    }

    if (this.config.agentId) payload.agent_id = this.config.agentId;
    if (this.config.cycleId) payload.cycle_id = this.config.cycleId;
    if (this.config.jurisdiction) payload.jurisdiction = this.config.jurisdiction;
    if (this.config.legalBasis) payload.legal_basis = this.config.legalBasis;
    if (this.config.purposeClass) payload.purpose_class = this.config.purposeClass;
    if (this.config.policyVersion) {
      payload.policy_version_hash = sha256Truncated(this.config.policyVersion, 12);
    }
    if (this.config.signingKey) {
      const algo = this.config.signingAlgorithm ?? "hmac-sha256";
      payload.payload_signature = signPayload(this.config.signingKey, fp, this.config.agentId, algo);
      payload.signing_algorithm = algo;
      if (this.config.signingKeyId) payload.signing_key_id = this.config.signingKeyId;
      if (this.config.signingKeyVersion !== undefined) payload.signing_key_version = this.config.signingKeyVersion;
    }

    this.buffer.enqueueMany([payload]);
  }

  /**
   * Witness a RAG retrieval step (AI-RAG.1 + optional AI-RAG.2).
   *
   * Records what context chunks were retrieved and from which corpus.
   * Chunk text is NEVER transmitted -- only SHA-256 hashes.
   *
   * Automatically emits AI-RAG.2 (Context Relevance) when
   * similarityThreshold is set and chunks have similarityScore.
   *
   * @param options.chunks - Raw strings (auto-hashed) or RagChunk objects.
   * @param options.corpusId - Identifier for the retrieval corpus/index.
   * @param options.similarityThreshold - When set and chunks have scores,
   *   AI-RAG.2 is emitted alongside AI-RAG.1.
   * @returns Array of WitnessPayload objects (1-2 payloads).
   *
   * @example
   *   witness.witnessRagContext({
   *     chunks: ["chunk text 1", "chunk text 2"],
   *     corpusId: "legal-docs-v3",
   *   });
   */
  witnessRagContext(options: RagContextOptions): WitnessPayload[] {
    const normalized: RagChunk[] = options.chunks.map((chunk) => {
      if (typeof chunk === "string") {
        return { contentHash: sha256Truncated(chunk) };
      }
      return chunk;
    });

    const payloads: WitnessPayload[] = [];
    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;

    // --- AI-RAG.1: Context Retrieval Provenance ---
    const [ts1, ep1] = timestampMs();
    const fa1 = normalized.length;
    const fb1 = options.corpusId ? 1 : 0;
    const fc1 = 0;
    const fp1 = mintFingerprint(this.config.tenantId, "AI-RAG.1", fa1, fb1, fc1, ts1);

    const p1: WitnessPayload = {
      procedure_id: "AI-RAG.1",
      factor_a: fa1,
      factor_b: fb1,
      factor_c: fc1,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp1,
      anchor_epoch: ep1,
      fingerprint_timestamp_ms: ts1,
    };

    if (this.config.clearingLevel <= 1) {
      p1.ai_model_id = options.embeddingModel ?? "rag-retrieval";
      const ctx: Record<string, unknown> = {
        provider: "rag",
        chunk_count: normalized.length,
        chunk_hashes: normalized.map((c) => c.contentHash),
      };
      if (options.corpusId) ctx.corpus_id = options.corpusId;
      if (options.corpusHash) ctx.corpus_hash = options.corpusHash;
      if (options.embeddingModel) ctx.embedding_model = options.embeddingModel;
      if (options.retrievalLatencyMs != null) ctx.retrieval_latency_ms = options.retrievalLatencyMs;
      if (options.topK != null) ctx.top_k = options.topK;
      p1.ai_context = ctx;
    }
    if (this.config.clearingLevel <= 2 && options.retrievalLatencyMs != null) {
      p1.ai_latency_ms = options.retrievalLatencyMs;
    }

    this._applyOperationalMetadata(p1, policyHash);
    payloads.push(p1);

    // --- AI-RAG.2: Context Relevance (conditional) ---
    const scoredChunks = normalized.filter((c) => c.similarityScore != null);
    if (options.similarityThreshold != null && scoredChunks.length > 0) {
      const scores = scoredChunks.map((c) => c.similarityScore!);
      const avgSim = scores.reduce((a, b) => a + b, 0) / scores.length;
      const belowCount = scores.filter((s) => s < options.similarityThreshold!).length;

      const [ts2, ep2] = timestampMs();
      const fa2 = Math.round(options.similarityThreshold * 1000);
      const fb2 = Math.round(avgSim * 1000);
      const fc2 = belowCount;
      const fp2 = mintFingerprint(this.config.tenantId, "AI-RAG.2", fa2, fb2, fc2, ts2);

      const p2: WitnessPayload = {
        procedure_id: "AI-RAG.2",
        factor_a: fa2,
        factor_b: fb2,
        factor_c: fc2,
        clearing_level: this.config.clearingLevel,
        anchor_fingerprint: fp2,
        anchor_epoch: ep2,
        fingerprint_timestamp_ms: ts2,
      };

      if (this.config.clearingLevel <= 1) {
        p2.ai_model_id = options.embeddingModel ?? "rag-retrieval";
        p2.ai_context = {
          provider: "rag",
          similarity_threshold: options.similarityThreshold,
          avg_similarity: Math.round(avgSim * 10000) / 10000,
          min_similarity: Math.round(Math.min(...scores) * 10000) / 10000,
          chunks_below_threshold: belowCount,
          chunk_scores: scores.map((s) => Math.round(s * 10000) / 10000),
        };
      }

      this._applyOperationalMetadata(p2, policyHash);
      payloads.push(p2);
    }

    this.buffer.enqueueMany(payloads);
    return payloads;
  }

  // -- Model Weight & Adapter Methods (AI-MDL.5/6/7) --

  /**
   * Hash a model weight file and return a ModelWeightInfo.
   *
   * Call ONCE at startup, not per-inference. File I/O is synchronous.
   *
   * @example
   *   const info = Witness.hashModelFile("/models/llama-3.1-70b.safetensors");
   *   witness.witnessModelWeights(info);
   */
  static hashModelFile(filePath: string, format?: string): ModelWeightInfo {
    const { createHash } = require("node:crypto") as typeof import("node:crypto");
    const fs = require("node:fs") as typeof import("node:fs");
    const path = require("node:path") as typeof import("node:path");
    const hash = createHash("sha256");
    const buf = fs.readFileSync(filePath);
    hash.update(buf);
    const ext = path.extname(filePath).replace(".", "");
    return {
      fileHash: hash.digest("hex"),
      filePath,
      fileSizeBytes: buf.length,
      format: format ?? (ext || undefined),
    };
  }

  /**
   * Witness model weight file integrity (AI-MDL.5).
   *
   * @param weights - ModelWeightInfo (from hashModelFile() or manual),
   *   or file path string (blocks for large files -- prefer hashModelFile()).
   * @param options.expectedHash - If provided and matches, PASS. If mismatches, FAIL.
   */
  witnessModelWeights(
    weights: ModelWeightInfo | string,
    options?: { expectedHash?: string },
  ): WitnessPayload {
    const info: ModelWeightInfo = typeof weights === "string"
      ? Witness.hashModelFile(weights)
      : weights;

    const match = options?.expectedHash ? info.fileHash === options.expectedHash : true;
    const [ts, epoch] = timestampMs();
    const fa = 1, fb = match ? 1 : 0, fc = 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-MDL.5", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-MDL.5", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = info.format ?? "model-weights";
      const ctx: Record<string, unknown> = { provider: "model-weights", file_hash: info.fileHash };
      if (info.filePath) ctx.file_path = info.filePath;
      if (info.fileSizeBytes != null) ctx.file_size_bytes = info.fileSizeBytes;
      if (info.format) ctx.format = info.format;
      if (options?.expectedHash) ctx.expected_hash = options.expectedHash;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness active LoRA/QLoRA/PEFT adapter stack (AI-MDL.6).
   */
  witnessAdapterStack(adapters: AdapterInfo[], baseModelId?: string): WitnessPayload {
    const allVerified = adapters.length === 0 || adapters.every((a) => a.adapterHash);
    const [ts, epoch] = timestampMs();
    const fa = adapters.length, fb = allVerified ? 1 : 0, fc = 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-MDL.6", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-MDL.6", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = baseModelId ?? "unknown-base";
      const adapterList = adapters.map((a) => {
        const obj: Record<string, string> = { name: a.name, hash: a.adapterHash };
        if (a.baseModel) obj.base_model = a.baseModel;
        return obj;
      });
      payload.ai_context = { provider: "adapter", adapters: adapterList };
      if (baseModelId) (payload.ai_context as Record<string, unknown>).base_model_id = baseModelId;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness model quantization method (AI-MDL.7).
   *
   * @param method - fp32, fp16, bf16, int8, int4, gptq, awq, gguf.
   */
  witnessQuantization(method: string, options?: { bits?: number; groupSize?: number }): WitnessPayload {
    const code = QUANTIZATION_CODES[method.toLowerCase()] ?? 0;
    const [ts, epoch] = timestampMs();
    const fa = 1, fb = 1, fc = code;
    const fp = mintFingerprint(this.config.tenantId, "AI-MDL.7", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-MDL.7", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `quantization-${method.toLowerCase()}`;
      const ctx: Record<string, unknown> = { provider: "quantization", method: method.toLowerCase() };
      if (options?.bits != null) ctx.bits = options.bits;
      if (options?.groupSize != null) ctx.group_size = options.groupSize;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // -- Procedural Knowledge / Skills Methods (AI-SKILL.1/2/3) --

  /**
   * Witness active skill/tool/plugin manifest (AI-SKILL.1).
   *
   * @param skills - Skill name strings (auto-hashed) or SkillInfo objects.
   * @param options.expectedManifestHash - Expected hash of the full manifest.
   *
   * @example
   *   witness.witnessSkillManifest(["code_exec", "web_search", "file_read"]);
   */
  witnessSkillManifest(
    skills: (string | SkillInfo)[],
    options?: { expectedManifestHash?: string },
  ): WitnessPayload {
    const normalized: SkillInfo[] = skills.map((s) =>
      typeof s === "string" ? { name: s, skillHash: sha256Truncated(s) } : s,
    );

    const manifestParts = normalized
      .map((si) => si.skillHash ?? sha256Truncated(si.name))
      .sort();
    const computedManifest = sha256Truncated(manifestParts.join(":"));
    const match = options?.expectedManifestHash ? computedManifest === options.expectedManifestHash : true;

    const [ts, epoch] = timestampMs();
    const fa = normalized.length, fb = match ? 1 : 0, fc = 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-SKILL.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-SKILL.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "skill-manifest";
      payload.ai_context = {
        provider: "skill-manifest",
        skills: normalized.map((si) => {
          const obj: Record<string, string> = { name: si.name };
          if (si.version) obj.version = si.version;
          if (si.skillHash) obj.hash = si.skillHash;
          return obj;
        }),
        manifest_hash: computedManifest,
      };
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness persistent memory sources influencing a decision (AI-SKILL.2).
   */
  witnessMemoryContext(sources: MemorySource[]): WitnessPayload {
    const allIdentified = sources.length > 0 && sources.every((s) => s.sourceId || s.contentHash);
    const [ts, epoch] = timestampMs();
    const fa = sources.length, fb = allIdentified ? 1 : 0, fc = 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-SKILL.2", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-SKILL.2", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "memory-context";
      payload.ai_context = {
        provider: "memory",
        sources: sources.map((s) => {
          const obj: Record<string, string> = { type: s.sourceType };
          if (s.sourceId) obj.id = s.sourceId;
          if (s.contentHash) obj.hash = s.contentHash;
          return obj;
        }),
        total_sources: sources.length,
      };
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness RLHF/DPO reward model binding (AI-SKILL.3).
   */
  witnessRewardModel(
    modelId: string,
    options?: { modelHash?: string; method?: string },
  ): WitnessPayload {
    const identified = Boolean(modelId?.trim());
    const [ts, epoch] = timestampMs();
    const fa = 1, fb = identified ? 1 : 0, fc = 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-SKILL.3", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-SKILL.3", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = modelId;
      const ctx: Record<string, unknown> = { provider: "reward-model", model_id: modelId };
      if (options?.modelHash) ctx.model_hash = options.modelHash;
      if (options?.method) ctx.method = options.method;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /** Apply operational metadata (agent_id, signing, CJT fields) to a payload. */
  private _applyOperationalMetadata(payload: WitnessPayload, policyHash?: string): void {
    if (payload.procedure_id) this._witnessedProcedures.add(payload.procedure_id);
    if (this.config.agentId) payload.agent_id = this.config.agentId;
    if (this.config.cycleId) payload.cycle_id = this.config.cycleId;
    if (this.config.jurisdiction) payload.jurisdiction = this.config.jurisdiction;
    if (this.config.legalBasis) payload.legal_basis = this.config.legalBasis;
    if (this.config.purposeClass) payload.purpose_class = this.config.purposeClass;
    if (policyHash) payload.policy_version_hash = policyHash;
    if (this.config.signingKey) {
      const alg = this.config.signingAlgorithm ?? "hmac-sha256";
      payload.payload_signature = signPayload(this.config.signingKey, payload.anchor_fingerprint, this.config.agentId, alg);
      payload.signing_algorithm = alg;
      if (this.config.signingKeyId) payload.signing_key_id = this.config.signingKeyId;
      if (this.config.signingKeyVersion !== undefined) payload.signing_key_version = this.config.signingKeyVersion;
    }
  }

  /**
   * Validate hardware snapshot against a runtime profile. Logs warnings
   * on mismatch but never blocks -- we are a witness, not enforcement.
   */
  private _validateRuntimeProfile(
    profile: RuntimeProfileConfig,
    snapshot: import("./hardware.js").HardwareSnapshot,
  ): void {
    const warn = (msg: string) => console.warn(`[swt3] runtime profile: ${msg}`);
    if (profile.expectedTopology && snapshot.topology !== profile.expectedTopology) {
      warn(`expected topology "${profile.expectedTopology}", got "${snapshot.topology}"`);
    }
    if (profile.minGpuCount != null && snapshot.gpus.length < profile.minGpuCount) {
      warn(`expected min_gpu_count=${profile.minGpuCount}, got ${snapshot.gpus.length}`);
    }
    if (profile.minMemoryMb != null && snapshot.totalMemoryMb < profile.minMemoryMb) {
      warn(`expected min_memory_mb=${profile.minMemoryMb}, got ${snapshot.totalMemoryMb}`);
    }
    if (profile.expectedAccelerator) {
      const match = snapshot.gpus.some((g) =>
        g.name.toUpperCase().includes(profile.expectedAccelerator!.toUpperCase()),
      );
      if (!match) {
        warn(`expected accelerator containing "${profile.expectedAccelerator}", none found`);
      }
    }
  }

  /**
   * Revoke a previously-issued witness anchor (AI-REV.1).
   *
   * Mints an AI-REV.1 anchor that references the target anchor's
   * fingerprint, creating an immutable revocation receipt.
   *
   * @param fingerprint - The 12-character anchor fingerprint to revoke.
   * @param reason - Revocation reason: model_recall, policy_violation,
   *   data_contamination, consent_withdrawal, regulatory_order,
   *   error_correction, or unspecified.
   * @returns The fingerprint of the revocation anchor itself.
   */
  /**
   * Witness accelerator hardware inventory (AI-HW.1).
   *
   * Records what GPU/accelerator hardware is present. Call ONCE at
   * service startup, not per-inference. If no GPUs are detectable,
   * returns a payload with factor_a=0, factor_b=0 (graceful no-op).
   *
   * @param options.snapshot - Pre-computed HardwareSnapshot (from queryHardware()).
   *   If omitted, auto-detects via nvidia-smi.
   * @param options.expectedTopology - Expected topology (e.g., "NVL72").
   *   If provided and doesn't match detected topology, factor_b=0.
   */
  witnessHardware(options?: {
    snapshot?: import("./hardware.js").HardwareSnapshot;
    expectedTopology?: string;
  }): WitnessPayload {
    const snapshot = options?.snapshot ?? queryHw();
    this._lastHwSnapshot = snapshot;
    const gpuCount = snapshot.gpus.length;
    let allHealthy = gpuCount > 0;
    if (options?.expectedTopology && snapshot.topology !== options.expectedTopology) {
      allHealthy = false;
    }

    const fa = gpuCount;
    const fb = allHealthy ? 1 : 0;
    const fc = topoCode(snapshot.topology);
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-HW.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-HW.1",
      factor_a: fa,
      factor_b: fb,
      factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp,
      anchor_epoch: epoch,
      fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `hw-${snapshot.topology}`;
      const ctx: Record<string, unknown> = {
        provider: "nvidia-hw",
        topology: snapshot.topology,
        interconnect: snapshot.interconnect,
        total_memory_mb: snapshot.totalMemoryMb,
        gpu_count: gpuCount,
        hostname_hash: snapshot.hostnameHash,
      };
      if (snapshot.driverVersion) ctx.driver_version = snapshot.driverVersion;
      if (snapshot.cudaVersion) ctx.cuda_version = snapshot.cudaVersion;
      if (snapshot.gpus.length > 0) {
        ctx.gpus = snapshot.gpus.map((g) => ({
          name: g.name,
          memory_mb: g.memoryMb,
          bus_id_hash: g.busIdHash,
          uuid_hash: g.uuidHash,
        }));
      }
      if (options?.expectedTopology) ctx.expected_topology = options.expectedTopology;
      payload.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness TPM 2.0 platform attestation (AI-HW.3).
   *
   * Reads PCR registers 0-7 via tpm2-tools and mints an anchor proving
   * host firmware integrity. All raw PCR digests are SHA-256 hashed
   * before leaving the module.
   *
   * @param options.snapshot - Pre-computed TPMSnapshot (from queryTPM()).
   */
  witnessTPMAttestation(options?: {
    snapshot?: TPMSnapshot;
  }): WitnessPayload {
    const snapshot = options?.snapshot ?? queryTpm();
    const pcrCount = snapshot.pcrs.length;
    const allNonZero = pcrCount > 0 && snapshot.pcrs.every(
      (pcr) => pcr.digestHash !== ZERO_PCR_HASH,
    );

    const fa = pcrCount;
    const fb = allNonZero ? 1 : 0;
    const fc = 0; // reserved
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-HW.3", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-HW.3",
      factor_a: fa,
      factor_b: fb,
      factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp,
      anchor_epoch: epoch,
      fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "tpm-attestation";
      const ctx: Record<string, unknown> = {
        provider: "tpm-2.0",
        pcr_count: pcrCount,
        all_non_zero: allNonZero,
        manufacturer_hash: snapshot.manufacturer,
        firmware_hash: snapshot.firmwareVersion,
        endorsement_key_hash: snapshot.endorsementKeyHash,
        hostname_hash: snapshot.hostnameHash,
      };
      if (snapshot.pcrs.length > 0) {
        ctx.pcrs = snapshot.pcrs.map((pcr) => ({
          index: pcr.index,
          bank: pcr.bank,
          digest_hash: pcr.digestHash,
        }));
      }
      payload.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Environment (AI-ENV.1 / AI-ENV.2) ────────────────────────────

  /**
   * Witness thermal integrity of the compute environment (AI-ENV.1).
   *
   * Call at service startup or on a periodic schedule, not per-inference.
   * Auto-detects Linux thermal zones. Pass manual values for XFRA/Span nodes.
   *
   * @param options.temperatureCelsius - Measured temperature (auto-detected if omitted)
   * @param options.thresholdCelsius - Safe maximum (default 85)
   * @param options.snapshot - Pre-computed EnvironmentSnapshot
   * @param options.nodeType - Node type: datacenter, edge, residential, mobile
   */
  witnessEnvironment(options?: {
    temperatureCelsius?: number;
    thresholdCelsius?: number;
    snapshot?: EnvironmentSnapshot;
    nodeType?: string;
  }): WitnessPayload {
    const snapshot = options?.snapshot ?? queryEnv();
    const temp = options?.temperatureCelsius ?? snapshot.temperatureCelsius;
    const threshold = options?.thresholdCelsius ?? 85;
    const nodeType = options?.nodeType ?? snapshot.nodeType ?? "unknown";

    const fa = Math.round(Number(temp) || 0);
    const fb = Math.round(Number(threshold) || 85);
    const fc = fa <= fb ? 1 : 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-ENV.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-ENV.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `env-thermal-${nodeType}`;
      payload.ai_context = {
        provider: "env-telemetry",
        node_type: nodeType,
        temperature_celsius: temp,
        threshold_celsius: threshold,
        thermal_zones: snapshot.thermalZones,
        hostname_hash: snapshot.hostnameHash,
      };
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness power integrity of the compute environment (AI-ENV.2).
   *
   * Call at service startup or on a periodic schedule, not per-inference.
   * Pass manual values from Span panel API, IPMI, or other power monitoring.
   *
   * @param options.powerWatts - Current power draw in watts
   * @param options.capacityWatts - Total available capacity in watts
   * @param options.throttled - Whether power throttling is active
   * @param options.snapshot - Pre-computed EnvironmentSnapshot
   * @param options.nodeType - Node type: datacenter, edge, residential, mobile
   */
  witnessEnergyDraw(options?: {
    powerWatts?: number;
    capacityWatts?: number;
    throttled?: boolean;
    snapshot?: EnvironmentSnapshot;
    nodeType?: string;
  }): WitnessPayload {
    const snapshot = options?.snapshot ?? queryEnv();
    const power = Number(options?.powerWatts ?? snapshot.powerWatts) || 0;
    const capacity = Number(options?.capacityWatts ?? 0) || 0;
    const headroom = Math.max(0, capacity - power);
    const throttled = options?.throttled ?? false;
    const nodeType = options?.nodeType ?? snapshot.nodeType ?? "unknown";

    const fa = Math.round(power);
    const fb = Math.round(headroom);
    const fc = throttled ? 1 : 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-ENV.2", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-ENV.2",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `env-power-${nodeType}`;
      payload.ai_context = {
        provider: "env-telemetry",
        node_type: nodeType,
        power_watts: power,
        capacity_watts: capacity,
        headroom_watts: headroom,
        throttled,
        power_domains: snapshot.powerDomains,
        hostname_hash: snapshot.hostnameHash,
      };
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Content Provenance (AI-MARK.1) ────────────────────────────

  /**
   * Witness content provenance marking (AI-MARK.1).
   *
   * Records when AI-generated content is labelled for machine
   * detectability per EU AI Act Art. 50(2) and GPAI Code of Practice.
   *
   * @param options.contentCount - Number of content items marked.
   * @param options.contentType - Content type key (text, image, audio, video, multimodal, code, structured_data).
   * @param options.markingMethod - Marking method (c2pa, watermark, metadata_tag, steganographic, manifest).
   * @param options.hasMetadata - True if C2PA/watermark metadata was attached.
   * @param options.content - Raw content string (auto-hashed to contentHash).
   * @param options.contentHash - Pre-computed SHA-256 of content.
   * @param options.manifestHash - SHA-256 of C2PA manifest.
   * @param options.standard - Standard identifier (e.g., "C2PA-1.4", "IPTC", "XMP").
   */
  witnessContentMark(options: {
    contentCount: number;
    contentType: string;
    markingMethod: string;
    hasMetadata: boolean;
    content?: string;
    contentHash?: string;
    manifestHash?: string;
    standard?: string;
  }): WitnessPayload {
    const fa = options.contentCount;
    const fb = options.hasMetadata ? 1 : 0;
    const fc = CONTENT_TYPE_CODES[options.contentType] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-MARK.1", fa, fb, fc, ts);

    const contentHash = options.contentHash
      ?? (options.content ? sha256Truncated(options.content) : undefined);

    const payload: WitnessPayload = {
      procedure_id: "AI-MARK.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `mark-${options.contentType}`;
      const ctx: Record<string, unknown> = {
        provider: "content-provenance",
        content_type: options.contentType,
        marking_method: options.markingMethod,
      };
      if (contentHash) ctx.content_hash = contentHash;
      if (options.manifestHash) ctx.manifest_hash = options.manifestHash;
      if (options.standard) ctx.standard = options.standard;
      payload.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Agent Behavioral Baseline (AI-BASE.1) ───────────────────

  /**
   * Witness an agent behavioral baseline (AI-BASE.1).
   *
   * Records the establishment or monitoring of an agent's behavior
   * envelope and detects drift from baseline.
   *
   * @param options.dimensions - Number of behavioral dimensions measured.
   * @param options.withinEnvelope - True if behavior is within baseline.
   * @param options.mode - Baseline mode (establishing, monitoring, drift_detected, baseline_reset).
   * @param options.driftScore - Normalized distance from baseline center (0.0-1.0).
   * @param options.baselineHash - SHA-256 of the baseline vector.
   * @param options.currentHash - SHA-256 of current observation vector.
   * @param options.driftThreshold - Threshold above which drift is flagged (default 0.5).
   * @param options.baselineWindowHours - Hours of data the baseline covers.
   */
  witnessAgentBaseline(options: {
    dimensions: number;
    withinEnvelope: boolean;
    mode: string;
    driftScore: number;
    baselineHash: string;
    currentHash: string;
    driftThreshold?: number;
    baselineWindowHours?: number;
  }): WitnessPayload {
    const fa = options.dimensions;
    const fb = options.withinEnvelope ? 1 : 0;
    const fc = BASELINE_MODE_CODES[options.mode] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-BASE.1", fa, fb, fc, ts);

    const agentIdHash = this.config.agentId
      ? sha256Truncated(this.config.agentId)
      : undefined;

    const payload: WitnessPayload = {
      procedure_id: "AI-BASE.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `baseline-${options.mode}`;
      const ctx: Record<string, unknown> = {
        provider: "agent-baseline",
        dimensions: options.dimensions,
        drift_score: options.driftScore,
        baseline_hash: options.baselineHash,
        current_hash: options.currentHash,
        drift_threshold: options.driftThreshold ?? 0.5,
      };
      if (options.baselineWindowHours != null) ctx.baseline_window_hours = options.baselineWindowHours;
      if (agentIdHash) ctx.agent_id_hash = agentIdHash;
      payload.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── License Provenance (AI-LIC.1) ──────────────────────────────

  /**
   * Witness license provenance of a model stack (AI-LIC.1).
   *
   * Records the license composition of base models, adapters, and
   * training data. Detects license drift when components from
   * different license families are combined.
   *
   * @param options.componentsChecked - Number of license components verified.
   * @param options.allCompliant - True if all components are license-compatible.
   * @param options.licenseType - Primary license type (permissive, copyleft, proprietary, dual, openmdw, unknown).
   * @param options.baseModelLicense - SPDX identifier of the base model license.
   * @param options.adapterLicenses - List of adapter/LoRA license identifiers.
   * @param options.spdxIds - SPDX identifiers for all components.
   * @param options.licenseHash - SHA-256 of the full license manifest.
   */
  witnessLicenseProvenance(options: {
    componentsChecked: number;
    allCompliant: boolean;
    licenseType: string;
    baseModelLicense?: string;
    adapterLicenses?: string[];
    spdxIds?: string[];
    licenseHash?: string;
  }): WitnessPayload {
    const fa = options.componentsChecked;
    const fb = options.allCompliant ? 1 : 0;
    const fc = LICENSE_TYPE_CODES[options.licenseType] ?? 5;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-LIC.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-LIC.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `license-${options.licenseType}`;
      const ctx: Record<string, unknown> = {
        provider: "license-provenance",
        license_type: options.licenseType,
      };
      if (options.baseModelLicense) ctx.base_model_license = options.baseModelLicense;
      if (options.adapterLicenses) ctx.adapter_licenses = options.adapterLicenses;
      if (options.spdxIds) ctx.spdx_ids = options.spdxIds;
      if (options.licenseHash) ctx.license_hash = options.licenseHash;
      payload.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── AI Bill of Materials (AI-SBOM.1) ────────────────────────────

  /**
   * Witness an AI bill of materials snapshot (AI-SBOM.1).
   *
   * Records the component inventory of an AI system at build or deploy
   * time, covering models, datasets, infrastructure, and security
   * posture per G7/CISA "SBOM for AI Minimum Elements" (May 2026).
   *
   * @param options.totalComponents - Number of components in the BOM.
   * @param options.clustersDocumented - G7 clusters documented (0-7).
   * @param options.format - BOM format (cyclonedx, spdx, custom, unknown).
   * @param options.bomHash - SHA-256 of the full BOM document.
   * @param options.version - BOM version string.
   * @param options.modelCount - Number of AI models in BOM.
   * @param options.datasetCount - Number of datasets in BOM.
   * @param options.infrastructureComponents - Number of infra components.
   */
  witnessSbom(options: {
    totalComponents: number;
    clustersDocumented: number;
    format: string;
    bomHash: string;
    version?: string;
    modelCount?: number;
    datasetCount?: number;
    infrastructureComponents?: number;
  }): WitnessPayload {
    const fa = options.totalComponents;
    const fb = options.clustersDocumented;
    const fc = SBOM_FORMAT_CODES[options.format] ?? 3;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-SBOM.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-SBOM.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `sbom-${options.format}`;
      const ctx: Record<string, unknown> = {
        provider: "ai-sbom",
        bom_hash: options.bomHash,
        format: options.format,
      };
      if (options.version) ctx.version = options.version;
      if (options.modelCount != null) ctx.model_count = options.modelCount;
      if (options.datasetCount != null) ctx.dataset_count = options.datasetCount;
      if (options.infrastructureComponents != null) ctx.infrastructure_components = options.infrastructureComponents;
      payload.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Adversarial Test Campaign (AI-REDTEAM.1) ──────────────────

  /**
   * Witness an adversarial test campaign (AI-REDTEAM.1).
   *
   * Records red team or adversarial testing results, transforming
   * point-in-time reports into continuous verifiable evidence per
   * EO 14110, EU AI Act Art. 9(7), and NIST AI 100-2.
   *
   * @param options.testsExecuted - Number of attack scenarios run.
   * @param options.testsPassed - Number of attacks successfully mitigated.
   * @param options.coverageCategory - Coverage category key (prompt_injection, jailbreak, etc.).
   * @param options.framework - Testing framework (e.g. "OWASP-LLM-Top10", "NIST-AI-100-2").
   * @param options.campaignId - Unique identifier for this test campaign.
   * @param options.modelUnderTest - Model identifier being tested.
   * @param options.attackTaxonomy - Attack taxonomy version or reference.
   * @param options.passRate - Computed pass rate (0-1).
   * @param options.durationSeconds - Campaign duration in seconds.
   */
  witnessRedTeam(options: {
    testsExecuted: number;
    testsPassed: number;
    coverageCategory: string;
    framework?: string;
    campaignId?: string;
    modelUnderTest?: string;
    attackTaxonomy?: string;
    passRate?: number;
    durationSeconds?: number;
  }): WitnessPayload {
    const fa = options.testsExecuted;
    const fb = options.testsPassed;
    const fc = REDTEAM_CATEGORY_CODES[options.coverageCategory] ?? 10;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-REDTEAM.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-REDTEAM.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `redteam-${options.coverageCategory}`;
      const ctx: Record<string, unknown> = {
        provider: "red-team",
        coverage_category: options.coverageCategory,
      };
      if (options.framework) ctx.framework = options.framework;
      if (options.campaignId) ctx.campaign_id = options.campaignId;
      if (options.modelUnderTest) ctx.model_under_test = options.modelUnderTest;
      if (options.attackTaxonomy) ctx.attack_taxonomy = options.attackTaxonomy;
      if (options.passRate != null) ctx.pass_rate = options.passRate;
      if (options.durationSeconds != null) ctx.duration_seconds = options.durationSeconds;
      payload.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Data Subject Consent (AI-CONSENT.1) ───────────────────────

  /**
   * Witness data subject consent documentation (AI-CONSENT.1).
   *
   * Records that consent or lawful basis was documented before
   * processing. Complements CJT fields (which declare legal basis)
   * by proving consent was actually obtained per GDPR Art. 6/7
   * and EU AI Act Art. 10.
   *
   * @param options.subjectsCovered - Number of data subjects in scope.
   * @param options.legalBasisType - GDPR lawful basis (consent, contract, legal_obligation, vital_interest, public_task, legitimate_interest).
   * @param options.withdrawalAvailable - True if withdrawal mechanism exists.
   * @param options.purpose - Processing purpose description.
   * @param options.retentionDays - Data retention period in days.
   * @param options.consentMechanism - Mechanism used (e.g. "opt-in-form", "api-consent-endpoint").
   * @param options.consentHash - SHA-256 of the consent record.
   * @param options.dataCategories - Categories of personal data processed.
   */
  witnessConsent(options: {
    subjectsCovered: number;
    legalBasisType: string;
    withdrawalAvailable: boolean;
    purpose?: string;
    retentionDays?: number;
    consentMechanism?: string;
    consentHash?: string;
    dataCategories?: string[];
  }): WitnessPayload {
    const fa = options.subjectsCovered;
    const fb = CONSENT_BASIS_CODES[options.legalBasisType] ?? 0;
    const fc = options.withdrawalAvailable ? 1 : 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-CONSENT.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-CONSENT.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `consent-${options.legalBasisType}`;
      const ctx: Record<string, unknown> = {
        provider: "consent-management",
        legal_basis_type: options.legalBasisType,
      };
      if (options.purpose) ctx.purpose = options.purpose;
      if (options.retentionDays != null) ctx.retention_days = options.retentionDays;
      if (options.consentMechanism) ctx.consent_mechanism = options.consentMechanism;
      if (options.consentHash) ctx.consent_hash = options.consentHash;
      if (options.dataCategories) ctx.data_categories = options.dataCategories;
      payload.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Multi-Agent Delegation (AI-MULTI.1) ───────────────────────

  /**
   * Witness inter-agent permission delegation (AI-MULTI.1).
   *
   * Records the permission envelope when one agent delegates tasks
   * to another. Complements AI-CHAIN.1/2 (which witness handoffs and
   * trust degradation) by witnessing WHAT was delegated per
   * EU AI Act Art. 9 and NIST AI RMF GOVERN 1.3.
   *
   * @param options.delegationDepth - Hops from original human authorization.
   * @param options.permissionsGranted - Count of distinct permissions delegated.
   * @param options.timeBoundMinutes - Minutes until delegation expires (0 = unbounded).
   * @param options.parentAgentId - Delegating agent identifier (hashed in context).
   * @param options.childAgentId - Receiving agent identifier (hashed in context).
   * @param options.delegatedTools - List of tool names being delegated.
   * @param options.scopeHash - SHA-256 of the permission manifest.
   * @param options.authorizationChain - Ordered agent IDs from human to child (each hashed).
   */
  witnessMultiAgentDelegation(options: {
    delegationDepth: number;
    permissionsGranted: number;
    timeBoundMinutes: number;
    parentAgentId: string;
    childAgentId: string;
    delegatedTools?: string[];
    scopeHash?: string;
    authorizationChain?: string[];
  }): WitnessPayload {
    const fa = options.delegationDepth;
    const fb = options.permissionsGranted;
    const fc = options.timeBoundMinutes;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-MULTI.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-MULTI.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `delegation-depth-${options.delegationDepth}`;
      const ctx: Record<string, unknown> = {
        provider: "multi-agent",
        parent_agent_hash: sha256Truncated(options.parentAgentId),
        child_agent_hash: sha256Truncated(options.childAgentId),
      };
      if (options.delegatedTools) ctx.delegated_tools = options.delegatedTools;
      if (options.scopeHash) ctx.scope_hash = options.scopeHash;
      if (options.authorizationChain) {
        ctx.authorization_chain = options.authorizationChain.map(
          (id) => sha256Truncated(id),
        );
      }
      payload.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Model Drift Detection (AI-DRIFT.1) ─────────────────────────

  /**
   * Witness model drift detection (AI-DRIFT.1).
   *
   * Records statistical drift events including data drift, concept drift,
   * and prediction drift per EU AI Act Art. 9(2)(b) continuous risk
   * estimation and NIST AI RMF MEASURE 2.6.
   */
  witnessDrift(options: {
    metricsEvaluated: number;
    driftedCount: number;
    driftType: string;
    baselineHash?: string;
    driftScore?: number;
    detectionMethod?: string;
    windowSize?: number;
    threshold?: number;
  }): WitnessPayload {
    const fa = options.metricsEvaluated;
    const fb = options.driftedCount;
    const fc = DRIFT_TYPE_CODES[options.driftType] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-DRIFT.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-DRIFT.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `drift-${options.driftType}`;
      const ctx: Record<string, unknown> = { provider: "drift-detection", drift_type: options.driftType };
      if (options.baselineHash) ctx.baseline_hash = options.baselineHash;
      if (options.driftScore != null) ctx.drift_score = options.driftScore;
      if (options.detectionMethod) ctx.detection_method = options.detectionMethod;
      if (options.windowSize != null) ctx.window_size = options.windowSize;
      if (options.threshold != null) ctx.threshold = options.threshold;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Audit Log Integrity (AI-AUDIT.1) ──────────────────────────

  /**
   * Witness audit log integrity verification (AI-AUDIT.1).
   *
   * Records verification of audit trail integrity per EU AI Act
   * Art. 12 (record-keeping) and GDPR Art. 30 (ROPA).
   */
  witnessAuditIntegrity(options: {
    entriesChecked: number;
    integrityVerified: boolean;
    logFormat: string;
    logHash?: string;
    periodStart?: string;
    periodEnd?: string;
    gapsDetected?: number;
  }): WitnessPayload {
    const fa = options.entriesChecked;
    const fb = options.integrityVerified ? 1 : 0;
    const fc = LOG_FORMAT_CODES[options.logFormat] ?? 3;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-AUDIT.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-AUDIT.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `audit-${options.logFormat}`;
      const ctx: Record<string, unknown> = { provider: "audit-integrity", log_format: options.logFormat };
      if (options.logHash) ctx.log_hash = options.logHash;
      if (options.periodStart) ctx.period_start = options.periodStart;
      if (options.periodEnd) ctx.period_end = options.periodEnd;
      if (options.gapsDetected != null) ctx.gaps_detected = options.gapsDetected;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Incident Reporting (AI-INCIDENT.1) ────────────────────────

  /**
   * Witness incident reporting (AI-INCIDENT.1).
   *
   * Records that a serious incident was reported per EU AI Act
   * Art. 62 and NIST AI RMF MANAGE 3.2.
   */
  witnessIncident(options: {
    severityCode: number;
    authorityNotified: boolean;
    incidentType: string;
    incidentId?: string;
    authority?: string;
    affectedSubjects?: number;
    remediationStatus?: string;
  }): WitnessPayload {
    const fa = options.severityCode;
    const fb = options.authorityNotified ? 1 : 0;
    const fc = INCIDENT_TYPE_CODES[options.incidentType] ?? 5;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-INCIDENT.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-INCIDENT.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `incident-${options.incidentType}`;
      const ctx: Record<string, unknown> = { provider: "incident-reporting", incident_type: options.incidentType };
      if (options.incidentId) ctx.incident_id = options.incidentId;
      if (options.authority) ctx.authority = options.authority;
      if (options.affectedSubjects != null) ctx.affected_subjects = options.affectedSubjects;
      if (options.remediationStatus) ctx.remediation_status = options.remediationStatus;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Performance Metrics (AI-PERF.1) ───────────────────────────

  /**
   * Witness performance/accuracy metrics (AI-PERF.1).
   *
   * Records model performance benchmarks per EU AI Act Art. 15(1)
   * accuracy requirements and NIST AI RMF MEASURE 2.5.
   */
  witnessPerformance(options: {
    metricsEvaluated: number;
    metricsPassing: number;
    benchmarkType: string;
    benchmarkId?: string;
    datasetHash?: string;
    threshold?: number;
    score?: number;
    modelUnderTest?: string;
  }): WitnessPayload {
    const fa = options.metricsEvaluated;
    const fb = options.metricsPassing;
    const fc = BENCHMARK_TYPE_CODES[options.benchmarkType] ?? 5;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-PERF.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-PERF.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = options.modelUnderTest ? `perf-${options.modelUnderTest}` : `perf-${options.benchmarkType}`;
      const ctx: Record<string, unknown> = { provider: "performance-metrics", benchmark_type: options.benchmarkType };
      if (options.benchmarkId) ctx.benchmark_id = options.benchmarkId;
      if (options.datasetHash) ctx.dataset_hash = options.datasetHash;
      if (options.threshold != null) ctx.threshold = options.threshold;
      if (options.score != null) ctx.score = options.score;
      if (options.modelUnderTest) ctx.model_under_test = options.modelUnderTest;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Robustness Testing (AI-ROBUST.1) ──────────────────────────

  /**
   * Witness robustness testing (AI-ROBUST.1).
   *
   * Records resilience against errors, faults, and inconsistencies
   * per EU AI Act Art. 15(3) and NIST AI RMF MEASURE 2.6.
   */
  witnessRobustness(options: {
    perturbationsTested: number;
    perturbationsSurvived: number;
    perturbationType: string;
    testSuiteId?: string;
    degradationPct?: number;
    baselineScore?: number;
    perturbedScore?: number;
  }): WitnessPayload {
    const fa = options.perturbationsTested;
    const fb = options.perturbationsSurvived;
    const fc = PERTURBATION_TYPE_CODES[options.perturbationType] ?? 5;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-ROBUST.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-ROBUST.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `robust-${options.perturbationType}`;
      const ctx: Record<string, unknown> = { provider: "robustness-testing", perturbation_type: options.perturbationType };
      if (options.testSuiteId) ctx.test_suite_id = options.testSuiteId;
      if (options.degradationPct != null) ctx.degradation_pct = options.degradationPct;
      if (options.baselineScore != null) ctx.baseline_score = options.baselineScore;
      if (options.perturbedScore != null) ctx.perturbed_score = options.perturbedScore;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Cybersecurity Attestation (AI-CYBER.1) ────────────────────

  /**
   * Witness cybersecurity measure attestation (AI-CYBER.1).
   *
   * Records cybersecurity assessment results per EU AI Act Art. 15(4)
   * and NIST Cybersecurity Framework.
   */
  witnessCybersecurity(options: {
    controlsAssessed: number;
    controlsCompliant: number;
    framework: string;
    assessmentId?: string;
    frameworkVersion?: string;
    findingsCount?: number;
    criticalFindings?: number;
  }): WitnessPayload {
    const fa = options.controlsAssessed;
    const fb = options.controlsCompliant;
    const fc = CYBER_FRAMEWORK_CODES[options.framework] ?? 4;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-CYBER.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-CYBER.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `cyber-${options.framework}`;
      const ctx: Record<string, unknown> = { provider: "cybersecurity-assessment", framework: options.framework };
      if (options.assessmentId) ctx.assessment_id = options.assessmentId;
      if (options.frameworkVersion) ctx.framework_version = options.frameworkVersion;
      if (options.findingsCount != null) ctx.findings_count = options.findingsCount;
      if (options.criticalFindings != null) ctx.critical_findings = options.criticalFindings;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Transparency Disclosure (AI-TRANS.1) ──────────────────────

  /**
   * Witness transparency disclosure (AI-TRANS.1).
   *
   * Records AI usage disclosures to deployers, end users, or data
   * subjects per EU AI Act Art. 13 and GDPR Art. 13/14.
   */
  witnessTransparency(options: {
    disclosuresMade: number;
    disclosureType: string;
    recipientType: string;
    disclosureId?: string;
    contentHash?: string;
    channel?: string;
  }): WitnessPayload {
    const fa = options.disclosuresMade;
    const fb = DISCLOSURE_TYPE_CODES[options.disclosureType] ?? 0;
    const fc = RECIPIENT_TYPE_CODES[options.recipientType] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-TRANS.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-TRANS.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `trans-${options.disclosureType}`;
      const ctx: Record<string, unknown> = { provider: "transparency-disclosure", disclosure_type: options.disclosureType, recipient_type: options.recipientType };
      if (options.disclosureId) ctx.disclosure_id = options.disclosureId;
      if (options.contentHash) ctx.content_hash = options.contentHash;
      if (options.channel) ctx.channel = options.channel;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Watermark Verification (AI-WATERMARK.1) ──────────────────

  /**
   * Witness watermark verification (AI-WATERMARK.1).
   *
   * Records verification that AI content marking survived downstream
   * processing per EU AI Act Art. 50(2). Distinct from AI-MARK.1
   * which witnesses marking; this witnesses verification.
   */
  witnessWatermarkVerification(options: {
    itemsChecked: number;
    watermarksDetected: number;
    detectionMethod: string;
    contentHash?: string;
    watermarkProvider?: string;
    confidenceScore?: number;
    strippedCount?: number;
  }): WitnessPayload {
    const fa = options.itemsChecked;
    const fb = options.watermarksDetected;
    const fc = DETECTION_METHOD_CODES[options.detectionMethod] ?? 4;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-WATERMARK.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-WATERMARK.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `watermark-${options.detectionMethod}`;
      const ctx: Record<string, unknown> = { provider: "watermark-verification", detection_method: options.detectionMethod };
      if (options.contentHash) ctx.content_hash = options.contentHash;
      if (options.watermarkProvider) ctx.watermark_provider = options.watermarkProvider;
      if (options.confidenceScore != null) ctx.confidence_score = options.confidenceScore;
      if (options.strippedCount != null) ctx.stripped_count = options.strippedCount;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Data Protection Impact Assessment (AI-DPIA.1) ─────────────

  /**
   * Witness data protection impact assessment (AI-DPIA.1).
   *
   * Records DPIA completion per GDPR Art. 35 and EU AI Act Art. 27
   * for high-risk AI processing.
   */
  witnessDpia(options: {
    risksIdentified: number;
    risksMitigated: number;
    processingType: string;
    dpiaId?: string;
    assessmentDate?: string;
    dpoConsulted?: boolean;
    residualRiskLevel?: string;
    supervisoryAuthorityConsulted?: boolean;
  }): WitnessPayload {
    const fa = options.risksIdentified;
    const fb = options.risksMitigated;
    const fc = PROCESSING_TYPE_CODES[options.processingType] ?? 4;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-DPIA.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-DPIA.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `dpia-${options.processingType}`;
      const ctx: Record<string, unknown> = { provider: "impact-assessment", processing_type: options.processingType };
      if (options.dpiaId) ctx.dpia_id = options.dpiaId;
      if (options.assessmentDate) ctx.assessment_date = options.assessmentDate;
      if (options.dpoConsulted != null) ctx.dpo_consulted = options.dpoConsulted;
      if (options.residualRiskLevel) ctx.residual_risk_level = options.residualRiskLevel;
      if (options.supervisoryAuthorityConsulted != null) ctx.supervisory_authority_consulted = options.supervisoryAuthorityConsulted;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Automated Decision Notification (AI-AUTO.1) ───────────────

  /**
   * Witness automated decision notification (AI-AUTO.1).
   *
   * Records notification of automated decisions with legal effects
   * per GDPR Art. 22 and EU AI Act Art. 14.
   */
  witnessAutomatedDecision(options: {
    decisionsMade: number;
    humanReviewed: number;
    decisionType: string;
    decisionId?: string;
    subjectNotified?: boolean;
    optOutAvailable?: boolean;
    humanReviewRequested?: boolean;
  }): WitnessPayload {
    const fa = options.decisionsMade;
    const fb = options.humanReviewed;
    const fc = DECISION_TYPE_CODES[options.decisionType] ?? 5;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-AUTO.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-AUTO.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `auto-${options.decisionType}`;
      const ctx: Record<string, unknown> = { provider: "automated-decision", decision_type: options.decisionType };
      if (options.decisionId) ctx.decision_id = options.decisionId;
      if (options.subjectNotified != null) ctx.subject_notified = options.subjectNotified;
      if (options.optOutAvailable != null) ctx.opt_out_available = options.optOutAvailable;
      if (options.humanReviewRequested != null) ctx.human_review_requested = options.humanReviewRequested;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Autonomous Generation Depth (AI-AUTO.2) ──────────────────

  /**
   * Witness autonomous generation depth (AI-AUTO.2).
   *
   * Records the depth of AI-to-AI generation cycles and whether
   * a human approval gate was present. EU AI Act Art. 14, EO 14110 Sec. 3.
   */
  witnessGenerationDepth(options: {
    maxDepth: number;
    observedDepth: number;
    humanGatePresent: boolean;
    generationContext?: string;
    sourceAgentId?: string;
    mergeTarget?: string;
  }): WitnessPayload {
    const fa = options.maxDepth;
    const fb = options.observedDepth;
    const fc = options.humanGatePresent ? 1 : 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-AUTO.2", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-AUTO.2", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = options.sourceAgentId || "autonomous-generator";
      const ctx: Record<string, unknown> = { provider: "generation-depth", max_depth: fa, observed_depth: fb };
      if (options.generationContext) ctx.generation_context = options.generationContext;
      if (options.sourceAgentId) ctx.source_agent_id = options.sourceAgentId;
      if (options.mergeTarget) ctx.merge_target = options.mergeTarget;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── External Timestamp Attestation (AI-AUDIT.2) ──────────────

  /**
   * Witness external timestamp attestation (AI-AUDIT.2).
   *
   * Records that a batch of anchors was anchored to an independent
   * RFC 3161 Timestamp Authority. NIST 800-53 AU-10 (Non-repudiation).
   */
  witnessTimestampAttestation(options: {
    anchorCount: number;
    tsaVerified: boolean;
    tsaProvider: string;
    merkleRoot?: string;
    tsaUrl?: string;
    tsaSerial?: string;
  }): WitnessPayload {
    const fa = options.anchorCount;
    const fb = options.tsaVerified ? 1 : 0;
    const TSA_CODES: Record<string, number> = { none: 0, freetsa: 1, digicert: 2, sectigo: 3, custom: 4 };
    const fc = TSA_CODES[options.tsaProvider] ?? 4;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-AUDIT.2", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-AUDIT.2", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "merkle-rollup";
      const ctx: Record<string, unknown> = { provider: "timestamp-attestation", tsa_provider: options.tsaProvider };
      if (options.merkleRoot) ctx.merkle_root = options.merkleRoot;
      if (options.tsaUrl) ctx.tsa_url = options.tsaUrl;
      if (options.tsaSerial) ctx.tsa_serial = options.tsaSerial;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Dual-Use Model Classification (AI-DUALUSE.1) ─────────────

  /**
   * Witness dual-use model classification (AI-DUALUSE.1).
   *
   * Records classification and reporting of dual-use foundation
   * models per EO 14110 Sec 4(a) and NIST AI RMF GOVERN 1.1.
   */
  witnessDualUse(options: {
    classificationCode: number;
    reportingStatus: string;
    daysSinceClassification: number;
    modelId?: string;
    classificationBasis?: string;
    computeThreshold?: string;
    authorityNotified?: string;
  }): WitnessPayload {
    const fa = options.classificationCode;
    const fb = REPORTING_STATUS_CODES[options.reportingStatus] ?? 0;
    const fc = options.daysSinceClassification;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-DUALUSE.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-DUALUSE.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = options.modelId ?? `dualuse-class-${options.classificationCode}`;
      const ctx: Record<string, unknown> = { provider: "dual-use-classification", reporting_status: options.reportingStatus };
      if (options.modelId) ctx.model_id = options.modelId;
      if (options.classificationBasis) ctx.classification_basis = options.classificationBasis;
      if (options.computeThreshold) ctx.compute_threshold = options.computeThreshold;
      if (options.authorityNotified) ctx.authority_notified = options.authorityNotified;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Supply Chain Risk (AI-SUPPLY.1) ───────────────────────────

  /**
   * Witness supply chain risk assessment (AI-SUPPLY.1).
   *
   * Records third-party AI supply chain risk metrics per NIST AI
   * RMF MEASURE 3.1, G7/CISA SBOM-AI, and EO 14028.
   */
  witnessSupplyChainRisk(options: {
    suppliersAssessed: number;
    suppliersCompliant: number;
    riskLevel: string;
    supplierIdHash?: string;
    vulnerabilityCount?: number;
    lastAuditDate?: string;
    updateCadenceDays?: number;
  }): WitnessPayload {
    const fa = options.suppliersAssessed;
    const fb = options.suppliersCompliant;
    const fc = SUPPLY_RISK_CODES[options.riskLevel] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-SUPPLY.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-SUPPLY.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `supply-risk-${options.riskLevel}`;
      const ctx: Record<string, unknown> = { provider: "supply-chain-risk", risk_level: options.riskLevel };
      if (options.supplierIdHash) ctx.supplier_id_hash = options.supplierIdHash;
      if (options.vulnerabilityCount != null) ctx.vulnerability_count = options.vulnerabilityCount;
      if (options.lastAuditDate) ctx.last_audit_date = options.lastAuditDate;
      if (options.updateCadenceDays != null) ctx.update_cadence_days = options.updateCadenceDays;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Post-Market Monitoring (AI-PMM.1) ─────────────────────────

  /**
   * Witness post-market monitoring attestation (AI-PMM.1).
   *
   * Records execution of post-market monitoring plans per EU AI Act
   * Art. 72 and NIST AI RMF MANAGE 4.1.
   */
  witnessPostMarketMonitoring(options: {
    monitoringChecksRun: number;
    anomaliesDetected: number;
    monitoringType: string;
    monitoringPlanHash?: string;
    periodStart?: string;
    periodEnd?: string;
    reportGenerated?: boolean;
  }): WitnessPayload {
    const fa = options.monitoringChecksRun;
    const fb = options.anomaliesDetected;
    const fc = PMM_TYPE_CODES[options.monitoringType] ?? 4;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-PMM.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-PMM.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `pmm-${options.monitoringType}`;
      const ctx: Record<string, unknown> = { provider: "post-market-monitoring", monitoring_type: options.monitoringType };
      if (options.monitoringPlanHash) ctx.monitoring_plan_hash = options.monitoringPlanHash;
      if (options.periodStart) ctx.period_start = options.periodStart;
      if (options.periodEnd) ctx.period_end = options.periodEnd;
      if (options.reportGenerated != null) ctx.report_generated = options.reportGenerated;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Chain, Violation, Charter, Registry, Reviewer, Safe State ───

  /**
   * Witness a multi-agent chain handoff (AI-CHAIN.1).
   */
  witnessChainHandoff(
    depth: number,
    targetAgent: string,
    options?: { accepted?: boolean },
  ): WitnessPayload {
    const accepted = options?.accepted ?? true;
    const [ts, epoch] = timestampMs();
    const fa = depth;
    const fb = this.config.cycleId ? 1 : 0;
    const fc = accepted ? 1 : 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-CHAIN.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-CHAIN.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = targetAgent;
      payload.ai_context = {
        provider: "chain", target_agent: targetAgent, depth, accepted,
      };
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness a trust-level-aware chain handoff (AI-CHAIN.1 + optional AI-CHAIN.2).
   *
   * Tracks the effective trust level across all agents in the chain.
   * If chainMinTrustLevel is configured and strict mode is active,
   * throws ChainTrustError when the effective level drops below the minimum.
   *
   * Auto-mints AI-CHAIN.2 (trust degradation) when the effective trust
   * level drops compared to the previous handoff.
   */
  witnessChainTrustHandoff(
    targetAgentId: string,
    targetTrustLevel: number,
    options?: { cycleId?: string; accepted?: boolean },
  ): WitnessPayload {
    const accepted = options?.accepted ?? true;
    const prevEffective = this._chainTrustLevels.length > 0
      ? Math.min(...this._chainTrustLevels)
      : targetTrustLevel;

    this._chainTrustLevels.push(targetTrustLevel);
    const effectiveTrustLevel = Math.min(...this._chainTrustLevels);

    // Enforce minimum if configured
    const minLevel = this.config.chainMinTrustLevel;
    if (minLevel !== undefined && effectiveTrustLevel < minLevel && this._strict) {
      throw new ChainTrustError(effectiveTrustLevel, minLevel);
    }

    const [ts, epoch] = timestampMs();
    const fa = this._chainTrustLevels.length;
    const fb = targetTrustLevel;
    const fc = effectiveTrustLevel;
    const fp = mintFingerprint(this.config.tenantId, "AI-CHAIN.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-CHAIN.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = targetAgentId;
      payload.ai_context = {
        provider: "chain-trust",
        target_agent: targetAgentId,
        target_trust_level: targetTrustLevel,
        effective_trust_level: effectiveTrustLevel,
        chain_depth: this._chainTrustLevels.length,
      };
    }
    const cycleId = options?.cycleId ?? this.config.cycleId;
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    if (cycleId) payload.cycle_id = cycleId;

    const payloads: WitnessPayload[] = [payload];

    // Auto-mint AI-CHAIN.2 if trust degraded
    if (this._chainTrustLevels.length > 1 && effectiveTrustLevel < prevEffective) {
      const degradation = extractChainTrustDegradationPayload(
        this.config.tenantId, prevEffective, effectiveTrustLevel,
        this.config.clearingLevel as 0 | 1 | 2 | 3,
        this.config.agentId, this.config.signingKey,
        this.config.signingKeyId, this.config.signingKeyVersion,
        cycleId, policyHash, this.config.signingAlgorithm,
      );
      if (this.config.clearingLevel <= 1) {
        degradation.ai_context = {
          provider: "chain-trust-degradation",
          previous_effective: prevEffective,
          new_effective: effectiveTrustLevel,
          target_agent: targetAgentId,
        };
      }
      payloads.push(degradation);
    }

    this.buffer.enqueueMany(payloads);
    return payload;
  }

  /** The effective (minimum) trust level across all chain handoffs. Returns 4 if no handoffs yet. */
  get chainEffectiveTrustLevel(): number {
    return this._chainTrustLevels.length === 0 ? 4 : Math.min(...this._chainTrustLevels);
  }

  /** The trust levels recorded at each chain handoff. */
  get chainTrustLevels(): readonly number[] {
    return this._chainTrustLevels;
  }

  /**
   * Witness a policy violation (AI-VIO.1).
   */
  witnessViolation(
    severity: number,
    description: string,
    options?: { autoDetected?: boolean; policyCategory?: string },
  ): WitnessPayload {
    const autoDetected = options?.autoDetected ?? false;
    const policyCategory = options?.policyCategory ?? "unspecified";
    const [ts, epoch] = timestampMs();
    const fa = Math.max(1, Math.min(4, severity));
    const fb = autoDetected ? 1 : 0;
    const fc = POLICY_CATEGORIES[policyCategory] ?? 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-VIO.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-VIO.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `violation-sev${fa}`;
      payload.ai_context = {
        provider: "violation", severity: fa, description, auto_detected: autoDetected, policy_category: policyCategory,
      };
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness an agent charter or system prompt hash (AI-CHR.1).
   */
  witnessCharter(options: {
    charterText?: string;
    charterHash?: string;
    expectedHash?: string;
  }): WitnessPayload {
    if (!options.charterText && !options.charterHash) {
      throw new Error("Provide charterText or charterHash");
    }
    const computed = options.charterHash ?? sha256Truncated(options.charterText!);
    const match = options.expectedHash ? computed === options.expectedHash : true;
    const [ts, epoch] = timestampMs();
    const fa = 1, fb = match ? 1 : 0, fc = 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-CHR.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-CHR.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "charter";
      const ctx: Record<string, unknown> = { provider: "charter", charter_hash: computed };
      if (options.expectedHash) ctx.expected_hash = options.expectedHash;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness a model registry check (AI-MDL.8).
   */
  witnessModelRegistry(
    modelId: string,
    registryId: string,
    options?: { found?: boolean; status?: string },
  ): WitnessPayload {
    const found = options?.found ?? true;
    const status = options?.status ?? "approved";
    const [ts, epoch] = timestampMs();
    const fa = 1, fb = found ? 1 : 0, fc = APPROVAL_STATUS[status] ?? 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-MDL.8", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-MDL.8", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = modelId;
      payload.ai_context = {
        provider: "model-registry", model_id: modelId, registry_id: registryId, found, status,
      };
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness reviewer identity binding (AI-HITL.3).
   */
  witnessReviewerIdentity(
    required: number,
    actual: number,
    options?: { method?: string; reviewerIdHash?: string },
  ): WitnessPayload {
    const method = options?.method ?? "session";
    const [ts, epoch] = timestampMs();
    const fa = required, fb = actual, fc = BINDING_METHODS[method] ?? 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-HITL.3", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-HITL.3", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "reviewer-identity";
      const ctx: Record<string, unknown> = {
        provider: "reviewer", required, actual, method,
      };
      if (options?.reviewerIdHash) ctx.reviewer_id_hash = options.reviewerIdHash;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness safe state attestation (AI-SAFE.1).
   */
  witnessSafeState(options?: {
    mechanismExists?: boolean;
    safeStateConfirmed?: boolean;
    mechanismType?: string;
  }): WitnessPayload {
    const mechanismExists = options?.mechanismExists ?? true;
    const safeStateConfirmed = options?.safeStateConfirmed ?? true;
    const [ts, epoch] = timestampMs();
    const fa = 1, fb = mechanismExists ? 1 : 0, fc = safeStateConfirmed ? 1 : 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-SAFE.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-SAFE.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "safe-state";
      const ctx: Record<string, unknown> = {
        provider: "safe-state", mechanism_exists: mechanismExists, safe_state_confirmed: safeStateConfirmed,
      };
      if (options?.mechanismType) ctx.mechanism_type = options.mechanismType;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Training Data (AI-DATA.3 / AI-DATA.4) ──────────────────────

  /**
   * Witness training dataset summary statistics (AI-DATA.3).
   */
  witnessTrainingStats(
    rowCount: number,
    featureCount: number,
    options?: {
      classBalanceRatio?: number;
      distributionHash?: string;
      classLabels?: string[];
      summary?: string;
    },
  ): WitnessPayload {
    const [ts, epoch] = timestampMs();
    const fa = rowCount;
    const fb = featureCount;
    const fc = options?.classBalanceRatio != null ? Math.floor(options.classBalanceRatio * 1000) : 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-DATA.3", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-DATA.3", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "training-stats";
      const ctx: Record<string, unknown> = {
        provider: "training-stats", row_count: rowCount, feature_count: featureCount,
      };
      if (options?.classBalanceRatio != null) ctx.class_balance_ratio = options.classBalanceRatio;
      if (options?.distributionHash) ctx.distribution_hash = options.distributionHash;
      if (options?.classLabels) ctx.class_labels = options.classLabels;
      if (options?.summary) ctx.summary = options.summary;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness a training data PII lifecycle event (AI-DATA.4).
   */
  witnessTrainingPiiLifecycle(
    recordsAffected: number,
    options?: {
      completed?: boolean;
      eventType?: string;
      datasetId?: string;
      scope?: string;
    },
  ): WitnessPayload {
    const completed = options?.completed ?? true;
    const eventType = options?.eventType ?? "unspecified";
    const [ts, epoch] = timestampMs();
    const fa = recordsAffected;
    const fb = completed ? 1 : 0;
    const fc = PII_EVENT_TYPES[eventType] ?? 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-DATA.4", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-DATA.4", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "pii-lifecycle";
      const ctx: Record<string, unknown> = {
        provider: "pii-lifecycle", event_type: eventType,
        records_affected: recordsAffected, completed,
      };
      if (options?.datasetId) ctx.dataset_id = options.datasetId;
      if (options?.scope) ctx.scope = options.scope;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Bias Assessment (AI-FAIR.3) ─────────────────────────────────

  /**
   * Witness a bias assessment (AI-FAIR.3).
   * Records that a bias assessment was conducted, how many protected
   * attributes were tested, and whether all fairness thresholds were met.
   *
   * @param protectedAttributeCount - Number of demographic dimensions tested
   * @param allThresholdsMet - true if all fairness thresholds passed
   * @param options.maxDisparityPct - Worst-case disparity percentage (0-100)
   * @param options.methodology - Assessment methodology name
   * @param options.protectedAttributes - List of protected attributes tested
   */
  witnessBiasAssessment(
    protectedAttributeCount: number,
    allThresholdsMet: boolean,
    options?: {
      maxDisparityPct?: number;
      methodology?: string;
      protectedAttributes?: string[];
    },
  ): WitnessPayload {
    const [ts, epoch] = timestampMs();
    const fa = protectedAttributeCount;
    const fb = allThresholdsMet ? 1 : 0;
    const fc = options?.maxDisparityPct != null ? Math.round(options.maxDisparityPct) : 0;
    const fp = mintFingerprint(this.config.tenantId, "AI-FAIR.3", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-FAIR.3", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = "bias-assessment";
      const ctx: Record<string, unknown> = {
        provider: "bias-assessment",
        protected_attribute_count: protectedAttributeCount,
        all_thresholds_met: allThresholdsMet,
      };
      if (options?.methodology) ctx.methodology = options.methodology;
      if (options?.protectedAttributes) ctx.protected_attributes = options.protectedAttributes;
      if (options?.maxDisparityPct != null) ctx.max_disparity_pct = options.maxDisparityPct;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Trust Mesh (AI-TRUST.1 / AI-TRUST.2) ────────────────────────

  private _trustRegistry?: TrustRegistry;
  private _witnessedProcedures = new Set<string>();

  get trustRegistry(): TrustRegistry {
    if (!this._trustRegistry) this._trustRegistry = new TrustRegistry();
    return this._trustRegistry;
  }

  set trustRegistry(registry: TrustRegistry) {
    this._trustRegistry = registry;
  }

  presentCredential(): TrustCredential {
    const ts = Date.now();
    const fpInput = `${this.config.agentId || "anonymous"}:${this.config.tenantId}:${ts}`;
    const credential: TrustCredential = {
      agentId: this.config.agentId || "anonymous",
      tenantId: this.config.tenantId,
      anchorFingerprint: sha256Truncated(fpInput, 12),
      anchorTimestampMs: ts,
      isSigned: Boolean(this.config.signingKey),
      procedures: [...this._witnessedProcedures],
      clearingLevel: this.config.clearingLevel,
      hasHardwareAttestation: this._witnessedProcedures.has("AI-HW.1") || this._witnessedProcedures.has("AI-HW.3"),
      hasGuardrails: this.config.guardrailsRequired > 0 || this.config.guardrailNames.length > 0,
    };
    if (this.config.signingKey) {
      credential.credentialSignature = signCredential(credential, this.config.signingKey);
    }
    return credential;
  }

  verifyTrust(credential: TrustCredential): TrustResult {
    const result = verifyCredential(credential, this.trustRegistry, this.config.tenantId);

    // Mint AI-TRUST.1
    const [ts1, ep1] = timestampMs();
    const fa1 = 1, fb1 = result.granted ? 1 : 0, fc1 = result.trustLevel;
    const fp1 = mintFingerprint(this.config.tenantId, "AI-TRUST.1", fa1, fb1, fc1, ts1);
    const p1: WitnessPayload = {
      procedure_id: "AI-TRUST.1",
      factor_a: fa1, factor_b: fb1, factor_c: fc1,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp1, anchor_epoch: ep1, fingerprint_timestamp_ms: ts1,
    };

    if (this.config.clearingLevel <= 1) {
      p1.ai_model_id = `trust-${TRUST_LEVEL_NAMES[result.trustLevel] ?? "unknown"}`;
      const ctx: Record<string, unknown> = {
        provider: "trust-mesh",
        counterpart_agent_id: credential.agentId,
        counterpart_tenant_id: credential.tenantId,
        trust_level: result.trustLevel,
        trust_level_name: TRUST_LEVEL_NAMES[result.trustLevel] ?? "unknown",
        checks_performed: result.checksPerformed,
        checks_passed: result.checksPassed,
        granted: result.granted,
      };
      if (result.denialReason) ctx.denial_reason = result.denialReason;
      p1.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(p1, policyHash);
    this.buffer.enqueueMany([p1]);

    // Mint AI-TRUST.2
    const [ts2, ep2] = timestampMs();
    const fa2 = result.checksPerformed, fb2 = result.checksPassed;
    const fc2 = result.granted ? 1 : 0;
    const fp2 = mintFingerprint(this.config.tenantId, "AI-TRUST.2", fa2, fb2, fc2, ts2);
    const p2: WitnessPayload = {
      procedure_id: "AI-TRUST.2",
      factor_a: fa2, factor_b: fb2, factor_c: fc2,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp2, anchor_epoch: ep2, fingerprint_timestamp_ms: ts2,
    };

    if (this.config.clearingLevel <= 1) {
      p2.ai_model_id = "trust-handshake";
      p2.ai_context = {
        provider: "trust-mesh",
        counterpart_agent_id: credential.agentId,
        handshake_result: result.granted ? "granted" : "denied",
      };
    }

    this._applyOperationalMetadata(p2, policyHash);
    this.buffer.enqueueMany([p2]);

    return result;
  }

  revoke(fingerprint: string, reason: string = "unspecified"): string {
    if (!fingerprint?.trim()) {
      throw new Error("fingerprint is required for revocation");
    }
    if (!Object.prototype.hasOwnProperty.call(REVOCATION_REASONS, reason)) {
      throw new Error(
        `Unknown revocation reason: "${reason}". Valid: ${Object.keys(REVOCATION_REASONS).sort().join(", ")}`,
      );
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;
    const payload = extractRevocationPayload(
      this.config.tenantId,
      fingerprint.trim(),
      reason,
      this.config.clearingLevel,
      this.config.agentId,
      this.config.signingKey,
      this.config.signingKeyId,
      this.config.signingKeyVersion,
      this.config.cycleId,
      policyHash,
      this.config.jurisdiction,
      this.config.legalBasis,
      this.config.purposeClass,
      this.config.signingAlgorithm,
    );
    this.buffer.enqueueMany([payload]);

    return payload.anchor_fingerprint;
  }

  /**
   * Query the Compliance Manifest API for this tenant's anchors.
   *
   * Returns a structured compliance manifest with summary, coverage,
   * and individual anchor records.
   */
  async manifest(filters: {
    model?: string;
    procedure?: string;
    framework?: string;
    verdict?: string;
    since?: string;
    until?: string;
    agent_id?: string;
    limit?: number;
  } = {}): Promise<Record<string, unknown>> {
    const params = new URLSearchParams({ format: "json" });
    if (filters.model) params.set("model", filters.model);
    if (filters.procedure) params.set("procedure", filters.procedure);
    if (filters.framework) params.set("framework", filters.framework);
    if (filters.verdict) params.set("verdict", filters.verdict);
    if (filters.since) params.set("since", filters.since);
    if (filters.until) params.set("until", filters.until);
    if (filters.agent_id) params.set("agent_id", filters.agent_id);
    if (filters.limit) params.set("limit", String(filters.limit));

    const url = `${this.config.endpoint.replace(/\/$/, "")}/manifest?${params.toString()}`;
    const resp = await fetch(url, {
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        Accept: "application/json",
      },
    });

    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`Manifest API returned ${resp.status}: ${body}`);
    }

    return resp.json() as Promise<Record<string, unknown>>;
  }

  /**
   * Record a witnessed inference. Extracts factors, applies clearing,
   * and enqueues payloads for background flush.
   *
   * If factorHandoff is configured, factors are written to the handoff
   * destination BEFORE clearing proceeds. If the handoff fails, the
   * payload is NOT transmitted.
   */
  record(inference: InferenceRecord, authorizationId?: string): void {
    if (this._gatewayMode) return;

    // Merge guardrail config
    if (this.config.guardrailNames.length > 0 && inference.guardrailNames.length === 0) {
      inference.guardrailNames = this.config.guardrailNames;
      inference.guardrailsActive = this.config.guardrailNames.length;
      inference.guardrailsRequired = this.config.guardrailsRequired;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;
    const payloads = extractPayloads(
      inference,
      this.config.tenantId,
      this.config.clearingLevel,
      this.config.latencyThresholdMs,
      this.config.guardrailsRequired,
      this.config.procedures,
      this.config.agentId,
      this.config.signingKey,
      this.config.signingKeyId,
      this.config.signingKeyVersion,
      this.config.cycleId,
      policyHash,
      this.config.jurisdiction,
      this.config.legalBasis,
      this.config.purposeClass,
      authorizationId,
      this.config.signingAlgorithm,
    );

    // Factor handoff: write full (uncleared) data to custody destination
    // BEFORE enqueuing the cleared payload for transmission.
    // If this fails, we do NOT proceed.
    if (this.config.factorHandoff === "file" && this.config.factorHandoffPath) {
      writeHandoffFiles(payloads, inference, this.config.tenantId, this.config.factorHandoffPath);
      if (!this.handoffWarned) {
        this.handoffWarned = true;
        console.info(
          `\n  [SWT3] ${payloads.length} anchors saved locally to ${this.config.factorHandoffPath}` +
          `\n  [SWT3] \u26a0 Local anchors won\u2019t survive a compliance audit.` +
          `\n  [SWT3] Connect to Axiom Engine \u2192 https://sovereign.tenova.io/signup?ref=sdk (free)\n`
        );
      }
    }

    this.buffer.enqueueMany(payloads);
  }

  /**
   * Create a Vercel AI SDK `onFinish` callback for streamText / generateText.
   *
   * Usage:
   *   const result = await streamText({
   *     model: openai("gpt-4o"),
   *     prompt: myPrompt,
   *     onFinish: witness.vercelOnFinish({ promptText: myPrompt }),
   *   });
   */
  vercelOnFinish(options?: VercelOnFinishOptions): (result: unknown) => void {
    return createVercelOnFinish(this, options) as (result: unknown) => void;
  }

  /**
   * Export a self-contained evidence bundle from the local WAL.
   *
   * Returns an EvidenceExporter pre-configured with the witness's
   * tenant, agent, clearing level, and credential state.
   */
  exportEvidence(): import("./exporters/evidence.js").EvidenceExporter {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { EvidenceExporter } = require("./exporters/evidence.js");
    return new EvidenceExporter({
      walDir: this._walPath,
      tenantId: this.config.tenantId,
      agentId: this.config.agentId,
      clearingLevel: this.config.clearingLevel,
      apiKey: this.config.apiKey,
      signingKey: this.config.signingKey,
      hasHardwareAttestation: !!this._hardwareConfig?.requireAttestation,
      merkleRoots: this._merkleAccumulator?.roots,
    });
  }

  /** Force-flush all buffered payloads. */
  async flush(): Promise<WitnessReceipt[]> {
    return this.buffer.flush();
  }

  /** Stop the witness and flush remaining payloads. */
  async stop(): Promise<WitnessReceipt[]> {
    return this.buffer.stop();
  }

  /** Number of payloads waiting. */
  get pending(): number {
    return this.buffer.pending;
  }

  /** All receipts from completed flushes. */
  get receipts(): WitnessReceipt[] {
    return this.buffer.receipts;
  }
}
