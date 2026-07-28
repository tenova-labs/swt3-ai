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
import { sha256Truncated, mintFingerprint, timestampMs, generateLifecycleChainId } from "./fingerprint.js";
import { extractPayloads, extractGatekeeperPayload, extractRevocationPayload, extractChainTrustDegradationPayload, REVOCATION_REASONS } from "./clearing.js";
import { signPayload } from "./signing.js";
import { WitnessBuffer } from "./buffer.js";
import { resolve as crosswalkResolve, resolveFramework as crosswalkResolveFramework } from "./crosswalk.js";
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
import { QUANTIZATION_CODES, POLICY_CATEGORIES, BINDING_METHODS, APPROVAL_STATUS, PII_EVENT_TYPES, CONTENT_TYPE_CODES, BASELINE_MODE_CODES, LICENSE_TYPE_CODES, SBOM_FORMAT_CODES, REDTEAM_CATEGORY_CODES, CONSENT_BASIS_CODES, DRIFT_TYPE_CODES, LOG_FORMAT_CODES, INCIDENT_SEVERITY_CODES, INCIDENT_TYPE_CODES, BENCHMARK_TYPE_CODES, PERTURBATION_TYPE_CODES, CYBER_FRAMEWORK_CODES, DISCLOSURE_TYPE_CODES, RECIPIENT_TYPE_CODES, DETECTION_METHOD_CODES, PROCESSING_TYPE_CODES, DECISION_TYPE_CODES, CLASSIFICATION_CODES, REPORTING_STATUS_CODES, SUPPLY_RISK_CODES, PMM_TYPE_CODES, LIFECYCLE_STAGE_CODES, METAGOV_SCOPE_CODES, METAGOV_PERMISSION_CODES, METAGOV_OVERRIDE_REASON_CODES, METAGOV_REVIEW_STATUS_CODES, METAGOV_DIVERGENCE_CODES, METAGOV_PURITY_TIERS, DESIGN_DOMAIN_CODES, SIMULATION_TYPE_CODES, APPROVAL_TYPE_CODES, MATERIAL_STANDARD_CODES, CHAIN_STATUS_CODES, RELEASE_TYPE_CODES } from "./types.js";
import { loadConfig as loadConfigFromFile, loadFullConfig, validatePolicy } from "./config.js";
import type { TrustMeshConfig, HardwareConfig, DensityPolicyConfig, McpPolicyConfig, MerkleConfig, ChainRule, ChainPolicyViolation, RuntimeProfileConfig } from "./types.js";
import { MerkleAccumulator } from "./merkle.js";

// ── Lifecycle Chain Stages (v6.0) ────────────────────────────────────

export const LIFECYCLE_CHAIN_STAGES: Record<string, number> = {
  initiated: 0, checkpoint: 1, escalated: 2,
  resolved: 3, abandoned: 4, superseded: 5,
};
const TERMINAL_STAGES = new Set(["resolved", "abandoned", "superseded"]);

// ── Operational Governance Codes (v6.0) ────────────────────────────
export const OVERRIDE_TRIGGER_CODES: Record<string, number> = { emergency_stop: 0, operator_command: 1, escalation_protocol: 2, external_responder: 3 };
export const AUTHORIZATION_LEVEL_CODES: Record<string, number> = { operator: 0, supervisor: 1, site_manager: 2, emergency_responder: 3 };
export const FALLBACK_STATE_CODES: Record<string, number> = { safe_state: 0, legacy_controller: 1, manual_mode: 2, degraded_operation: 3, full_shutdown: 4 };
export const CONSEQUENCE_CATEGORY_CODES: Record<string, number> = { safety: 0, environmental: 1, financial: 2, operational: 3, reputational: 4 };
export const DRIFT_RESPONSE_CODES: Record<string, number> = { notification_only: 0, increased_monitoring: 1, throttle: 2, circuit_breaker: 3, forced_failover: 4, emergency_shutdown: 5 };

// ── Chain Density Enforcement ──────────────────────────────────────────

function globToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp("^" + escaped + "$");
}

/** Parse first 8 hex chars as int mod 1M, falling back to hash for non-hex input. */
function safeHexInt(s: string): number {
  const v = parseInt(s.slice(0, 8), 16);
  if (!isNaN(v)) return v % 1000000;
  return parseInt(sha256Truncated(s, 8), 16) % 1000000;
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
  endpoint?: string;
  apiKey?: string;
  tenantId?: string;
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
  private _localMode: boolean;
  private _localCtaCount = 0;
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
  private _lastKnownGoodVersion = 0;

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

  constructor(options: WitnessOptions = {}) {
    this._gatewayMode = options.gatewayMode ?? false;

    // Local mode: no endpoint, no API key, no account required.
    // Anchors generated locally via SHA-256, persisted to disk.
    this._localMode = !options.endpoint && !options.apiKey && !this._gatewayMode;
    if (this._localMode) {
      const { mkdirSync } = require("node:fs");
      const { join } = require("node:path");
      const localPath = options.factorHandoffPath || join(process.cwd(), "swt3-local");
      try { mkdirSync(localPath, { recursive: true }); } catch { /* exists */ }
      options = {
        ...options,
        endpoint: "local",
        apiKey: "axm_local",
        tenantId: options.tenantId || "LOCAL",
        factorHandoff: "file",
        factorHandoffPath: localPath,
        bufferSize: 9999,
        flushInterval: 86400,
        maxRetries: 0,
      };
    }

    // Gateway mode: SDK defers all witnessing to the SWT3 Gateway.
    if (!this._gatewayMode && !this._localMode) {
      if (!options.endpoint) throw new Error("endpoint is required (or use new Witness() for local mode)");
      if (!options.apiKey) throw new Error("apiKey is required (or use new Witness() for local mode)");
      if (!options.apiKey.startsWith("axm_")) throw new Error("apiKey must start with 'axm_'");
    }
    if (!options.tenantId && !this._gatewayMode && !this._localMode) throw new Error("tenantId is required");
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

  /**
   * Auto-chaining: all witness calls inside the callback share the same cycle_id.
   *
   * Usage:
   *   await witness.chain("credit-decision", async (ctx) => {
   *     witness.record(inference1);
   *     witness.witnessDrift(...);
   *     // ctx.cycleId available for correlation
   *   });
   */
  async chain<T>(
    name: string,
    fn: (ctx: ChainContext) => Promise<T>,
    options?: { cycleId?: string },
  ): Promise<T> {
    const cycleId = options?.cycleId ?? `CHAIN-${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const previousCycleId = this.config.cycleId;
    const ctx = new ChainContext(cycleId, name);
    this.config.cycleId = cycleId;
    try {
      return await fn(ctx);
    } finally {
      this.config.cycleId = previousCycleId;
    }
  }

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

    // Local mode: show framework coverage for witnessed procedures
    if (this._localMode && this._localCtaCount < 3) {
      this._localCtaCount++;
      try {
        const fwSet = new Set<string>();
        const procIds = payloads.map((p) => p.procedure_id);
        for (const pid of procIds) {
          for (const fw of Object.keys(crosswalkResolve(pid))) fwSet.add(fw);
        }
        if (fwSet.size > 0) {
          const topFw = [...fwSet].sort().slice(0, 5);
          const more = fwSet.size > 5 ? `, +${fwSet.size - 5} more` : "";
          console.info(`  [SWT3] ${procIds.length} procedures witnessed across ${fwSet.size} frameworks (${topFw.join(", ")}${more})`);
        }
        if (this._localCtaCount === 1) {
          console.info(`  [SWT3] Run witness.coverage("EU-AI-ACT") to see your coverage score`);
          console.info(`  [SWT3] Add swt3-local/ to .gitignore`);
          console.info(`  [SWT3] Connect to persist & audit: https://sovereign.tenova.io/signup?ref=sdk_local\n`);
        }
      } catch { /* never break witness for summary */ }
    }

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
    options?: { expectedHash?: string; lifecycleStage?: string },
  ): WitnessPayload {
    const info: ModelWeightInfo = typeof weights === "string"
      ? Witness.hashModelFile(weights)
      : weights;

    const match = options?.expectedHash ? info.fileHash === options.expectedHash : true;
    const stageCode = options?.lifecycleStage ? (LIFECYCLE_STAGE_CODES[options.lifecycleStage] ?? 0) : 0;
    const [ts, epoch] = timestampMs();
    const fa = 1, fb = match ? 1 : 0, fc = stageCode;
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
      if (options?.lifecycleStage) ctx.lifecycle_stage = options.lifecycleStage;
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
    const accelCount = snapshot.accelerators?.length ?? snapshot.gpus.length;
    let allHealthy = accelCount > 0;
    if (options?.expectedTopology && snapshot.topology !== options.expectedTopology) {
      allHealthy = false;
    }

    const fa = accelCount;
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
      const sv = snapshot.siliconVendor ?? (snapshot.gpus.length > 0 ? "nvidia" : "none");
      payload.ai_model_id = `hw-${sv}-${snapshot.topology}`;
      const ctx: Record<string, unknown> = {
        provider: sv,
        silicon_vendor: sv,
        discovery_method: snapshot.discoveryMethod ?? (snapshot.gpus.length > 0 ? "nvidia-smi" : ""),
        topology: snapshot.topology,
        interconnect: snapshot.interconnect,
        total_memory_mb: snapshot.totalMemoryMb,
        accelerator_count: accelCount,
        gpu_count: snapshot.gpus.length,
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
      if (snapshot.accelerators && snapshot.accelerators.length > 0) {
        ctx.accelerators = snapshot.accelerators.map((a) => ({
          vendor: a.vendor,
          name: a.name,
          memory_mb: a.memoryMb,
          id_hash: a.idHash,
          bus_id_hash: a.busIdHash,
          discovery_method: a.discoveryMethod,
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

  // ── Delegation Tree Witnessing (AI-DEL.1) ──────────────────────

  /**
   * Witness a delegation tree grant (AI-DEL.1).
   *
   * Records hierarchical permission delegation with scope binding and
   * cascade revocation intent. Complements AI-MULTI.1 (single-hop)
   * by witnessing the TREE structure per EU AI Act Art. 9 and
   * NIST AI RMF GOVERN 1.3.
   *
   * Factor semantics:
   *   factor_a: SHA256(delegatorId)[:8] as uint32
   *   factor_b: SHA256(scope)[:8] as uint32
   *   factor_c: delegationDepth
   *
   * @param options.delegatorId - Identity of the granting agent.
   * @param options.scope - Permission scope descriptor (e.g., "read_file,write_file").
   * @param options.delegationDepth - Tree depth from root authorization (0=root).
   * @param options.delegates - Agent IDs receiving delegation (hashed in context).
   * @param options.treeHash - SHA-256 of the complete delegation tree manifest.
   * @param options.cascadeRevocation - Whether revoking this grant cascades to children.
   * @param options.timeBoundMinutes - Minutes until grant expires (0 = unbounded).
   * @param options.parentGrantFingerprint - Anchor fingerprint of the parent grant.
   */
  witnessDelegationTree(options: {
    delegatorId: string;
    scope: string;
    delegationDepth: number;
    delegates?: string[];
    treeHash?: string;
    cascadeRevocation?: boolean;
    timeBoundMinutes?: number;
    parentGrantFingerprint?: string;
  }): WitnessPayload {
    const delegatorHash = sha256Truncated(options.delegatorId, 16);
    const scopeHash = sha256Truncated(options.scope, 16);
    const fa = parseInt(delegatorHash.slice(0, 8), 16);
    const fb = parseInt(scopeHash.slice(0, 8), 16);
    const fc = options.delegationDepth;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-DEL.1", fa, fb, fc, ts);

    const payload: WitnessPayload = {
      procedure_id: "AI-DEL.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };

    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `delegation-tree-depth-${options.delegationDepth}`;
      const ctx: Record<string, unknown> = {
        provider: "delegation-tree",
        delegator_hash: delegatorHash,
        scope_hash: scopeHash,
        cascade_revocation: options.cascadeRevocation ?? false,
        time_bound_minutes: options.timeBoundMinutes ?? 0,
      };
      if (options.delegates) {
        ctx.delegates = options.delegates.map((d) => sha256Truncated(d));
      }
      if (options.treeHash) ctx.tree_hash = options.treeHash;
      if (options.parentGrantFingerprint) {
        ctx.parent_grant_fingerprint = options.parentGrantFingerprint;
      }
      payload.ai_context = ctx;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Helper: witness a delegation tree scoped to a list of tools.
   * Scope is computed as the sorted, comma-joined tool names.
   */
  delegationTreeFromTools(options: {
    delegatorId: string;
    tools: string[];
    delegationDepth?: number;
    delegates?: string[];
    treeHash?: string;
    cascadeRevocation?: boolean;
    timeBoundMinutes?: number;
    parentGrantFingerprint?: string;
  }): WitnessPayload {
    const scope = [...options.tools].sort().join(",");
    return this.witnessDelegationTree({
      delegatorId: options.delegatorId,
      scope,
      delegationDepth: options.delegationDepth ?? 1,
      delegates: options.delegates,
      treeHash: options.treeHash,
      cascadeRevocation: options.cascadeRevocation,
      timeBoundMinutes: options.timeBoundMinutes,
      parentGrantFingerprint: options.parentGrantFingerprint,
    });
  }

  /**
   * Helper: witness a delegation tree scoped to a list of capabilities.
   * Scope is computed as the sorted, comma-joined capability names.
   */
  delegationTreeFromCapabilities(options: {
    delegatorId: string;
    capabilities: string[];
    delegationDepth?: number;
    delegates?: string[];
    treeHash?: string;
    cascadeRevocation?: boolean;
    timeBoundMinutes?: number;
    parentGrantFingerprint?: string;
  }): WitnessPayload {
    const scope = [...options.capabilities].sort().join(",");
    return this.witnessDelegationTree({
      delegatorId: options.delegatorId,
      scope,
      delegationDepth: options.delegationDepth ?? 1,
      delegates: options.delegates,
      treeHash: options.treeHash,
      cascadeRevocation: options.cascadeRevocation,
      timeBoundMinutes: options.timeBoundMinutes,
      parentGrantFingerprint: options.parentGrantFingerprint,
    });
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

  // ── Governance Infrastructure Attestation (AI-METAGOV.1) ──────────────

  /**
   * Witness governance infrastructure configuration (AI-METAGOV.1).
   *
   * Attests the governance system's own configuration using the same
   * protocol it enforces, per the Recursive Governance architecture.
   * The governance config must be attested before operational events
   * can be processed.
   */
  witnessGovernanceConfig(options: {
    rules: { id: string; expression: string; version?: string }[];
    governanceVersion: number;
    operatorId?: string;
  }): WitnessPayload {
    // Canonical serialization: sort rules by id, concat id+expression+version, hash with domain separator
    const sorted = [...options.rules].sort((a, b) => a.id.localeCompare(b.id));
    const canonical = sorted.map(r => `${r.id}:${r.expression}:${r.version ?? ""}`).join("|");
    const configHash = sha256Truncated(`SWT3:GOVERNANCE:${canonical}`, 12);
    const fa = options.rules.length;
    const fb = parseInt(configHash.slice(0, 8), 16) % 1000000;
    const fc = options.governanceVersion;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-METAGOV.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-METAGOV.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `governance-v${options.governanceVersion}`;
      const ctx: Record<string, unknown> = {
        provider: "governance-infrastructure",
        config_hash: configHash,
        rule_count: options.rules.length,
        governance_version: options.governanceVersion,
      };
      if (options.operatorId) ctx.operator_id = options.operatorId;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Policy Downgrade Detection (AI-METAGOV.3) ──────────────────────

  /**
   * Check policy version and witness downgrade if detected (AI-METAGOV.3).
   *
   * Enforces monotonic policy version progression. If the provided version
   * is lower than the last known good version, mints a downgrade alert anchor.
   * Returns the payload if a downgrade was detected, or null if version is normal.
   */
  checkPolicyDowngrade(options: {
    policyVersion: number;
    policyContentHash: string;
    strict?: boolean;
  }): WitnessPayload | null {
    const isDowngrade = options.policyVersion < this._lastKnownGoodVersion;
    if (!isDowngrade) {
      this._lastKnownGoodVersion = Math.max(this._lastKnownGoodVersion, options.policyVersion);
      return null;
    }
    const fa = options.policyVersion;
    const fb = safeHexInt(options.policyContentHash);
    const fc = 1; // downgrade detected
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-METAGOV.3", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-METAGOV.3", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `policy-downgrade`;
      payload.ai_context = {
        provider: "policy-monitor",
        expected_version: this._lastKnownGoodVersion,
        loaded_version: options.policyVersion,
        content_hash: options.policyContentHash,
        downgrade: true,
      };
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    if (options.strict) {
      throw new Error(`SWT3: Policy downgrade detected: version ${options.policyVersion} < ${this._lastKnownGoodVersion}`);
    }
    return payload;
  }

  // ── Governance Layer Registration (AI-METAGOV.2) ──────────────────────

  /**
   * Register an AI governance layer with the witness layer (AI-METAGOV.2).
   *
   * Each AI governance layer must register before its outputs are
   * considered authoritative. Computes governance stack fingerprint
   * with SWT3:GOVSTACK: domain separator.
   */
  registerGovernanceLayer(options: {
    layerId: string;
    modelId?: string;
    configHash: string;
    stackPosition: number;
  }): WitnessPayload {
    const stackInput = `${options.layerId}:${options.configHash}:${options.stackPosition}`;
    const regFingerprint = sha256Truncated(`SWT3:GOVSTACK:${stackInput}`, 12);
    const fa = 1;
    const fb = parseInt(regFingerprint.slice(0, 8), 16) % 1000000;
    const fc = options.stackPosition;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-METAGOV.2", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-METAGOV.2", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = options.modelId ?? options.layerId;
      const ctx: Record<string, unknown> = {
        provider: "governance-layer-registration",
        layer_id: options.layerId,
        config_hash: options.configHash,
        stack_position: options.stackPosition,
        registration_fingerprint: regFingerprint,
      };
      if (options.modelId) ctx.model_id = options.modelId;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness an AI governance layer's output/verdict (AI-METAGOV.2).
   *
   * Records the governance layer's compliance decision in the non-AI
   * witness layer, creating an independently verifiable record.
   */
  witnessGovernanceOutput(options: {
    layerId: string;
    verdict: "PASS" | "FAIL";
    evidenceHash: string;
    modelId?: string;
  }): WitnessPayload {
    const fa = 1;
    const fb = safeHexInt(options.evidenceHash);
    const fc = options.verdict === "PASS" ? 1 : 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-METAGOV.2", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-METAGOV.2", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = options.modelId ?? options.layerId;
      payload.ai_context = {
        provider: "governance-output",
        layer_id: options.layerId,
        verdict: options.verdict,
        evidence_hash: options.evidenceHash,
      };
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Governance Authorization (AI-METAGOV.5) ──────────────────────

  /**
   * Authorize a governance configuration change (AI-METAGOV.5).
   *
   * Records the operator identity, authority scope, and signature
   * for governance changes. Supports separation of duties enforcement.
   */
  authorizeGovernanceChange(options: {
    scopeDomain: string;
    permissionLevel: string;
    operatorId: string;
    changeDescription: string;
    operatorCredentialHash: string;
  }): WitnessPayload {
    const fa = METAGOV_SCOPE_CODES[options.scopeDomain] ?? 0;
    const fb = METAGOV_PERMISSION_CODES[options.permissionLevel] ?? 0;
    const fc = safeHexInt(options.operatorCredentialHash);
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-METAGOV.5", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-METAGOV.5", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `governance-auth-${options.scopeDomain}`;
      payload.ai_context = {
        provider: "governance-authorization",
        scope_domain: options.scopeDomain,
        permission_level: options.permissionLevel,
        operator_id: options.operatorId,
        change_description: options.changeDescription,
      };
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Emergency Override Attestation (AI-METAGOV.6) ──────────────────

  /**
   * Witness an emergency governance override (AI-METAGOV.6).
   *
   * Records governance changes made outside normal approval workflow.
   * Triggers mandatory review requirement.
   */
  witnessEmergencyOverride(options: {
    overrideReason: string;
    reviewWindowHours: number;
    operatorId: string;
    changeDescription: string;
  }): WitnessPayload {
    const fa = METAGOV_OVERRIDE_REASON_CODES[options.overrideReason] ?? 0;
    const fb = options.reviewWindowHours;
    const fc = METAGOV_REVIEW_STATUS_CODES.unreviewed; // always starts unreviewed
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-METAGOV.6", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-METAGOV.6", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `emergency-override`;
      payload.ai_context = {
        provider: "governance-emergency",
        override_reason: options.overrideReason,
        review_window_hours: options.reviewWindowHours,
        operator_id: options.operatorId,
        change_description: options.changeDescription,
        review_status: "unreviewed",
      };
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Governance Sync Verification (AI-METAGOV.7) ──────────────────────

  /**
   * Witness governance policy divergence between organizations (AI-METAGOV.7).
   *
   * Records whether federated organizations have equivalent, compatible,
   * or divergent governance policies during trust credential exchange.
   */
  witnessGovernanceSync(options: {
    divergenceType: string;
    localPolicyHash: string;
    remotePolicyHash: string;
    remoteTenantId?: string;
  }): WitnessPayload {
    const fa = METAGOV_DIVERGENCE_CODES[options.divergenceType] ?? 0;
    const fb = safeHexInt(options.localPolicyHash);
    const fc = safeHexInt(options.remotePolicyHash);
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-METAGOV.7", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-METAGOV.7", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `governance-sync`;
      const ctx: Record<string, unknown> = {
        provider: "governance-sync",
        divergence_type: options.divergenceType,
        local_policy_hash: options.localPolicyHash,
        remote_policy_hash: options.remotePolicyHash,
      };
      if (options.remoteTenantId) ctx.remote_tenant_id = options.remoteTenantId;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Attestation Purity Verification (AI-METAGOV.8) ──────────────────

  /**
   * Verify and attest that the attestation engine is free of AI (AI-METAGOV.8).
   *
   * Computes a combined hash of attestation path source files to prove
   * the witness layer contains no machine learning components.
   */
  verifyAttestationPurity(options: {
    sourceFiles: { path: string; hash: string }[];
    buildHash?: string;
  }): WitnessPayload {
    const combinedInput = options.sourceFiles
      .sort((a, b) => a.path.localeCompare(b.path))
      .map(f => `${f.path}:${f.hash}`)
      .join("|");
    const combinedHash = sha256Truncated(combinedInput, 12);
    const fa = options.sourceFiles.length;
    const fb = parseInt(combinedHash.slice(0, 8), 16) % 1000000;
    const fc = 1; // pure by definition (this SDK has no AI in attestation path)
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-METAGOV.8", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-METAGOV.8", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `attestation-purity`;
      const ctx: Record<string, unknown> = {
        provider: "purity-verification",
        source_file_count: options.sourceFiles.length,
        combined_source_hash: combinedHash,
        purity_tier: "verified_pure",
      };
      if (options.buildHash) ctx.build_hash = options.buildHash;
      payload.ai_context = ctx;
    }
    const policyHash = this.config.policyVersion ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Physical AI / Large Engineering Model (AI-ENG.1-5) ──────────

  /**
   * Witness AI-generated design provenance (AI-ENG.1).
   * DO-178C 5.1, ASME V&V 10 3.1, FDA 21 CFR 11.10(a).
   */
  witnessDesignProvenance(options: {
    constraintsApplied: number;
    parametersGenerated: number;
    designDomain: string;
    designHash?: string;
    modelVersion?: string;
  }): WitnessPayload {
    const fa = options.constraintsApplied;
    const fb = options.parametersGenerated;
    const fc = DESIGN_DOMAIN_CODES[options.designDomain] ?? 7;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-ENG.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-ENG.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `design-${options.designDomain}`;
      const ctx: Record<string, unknown> = { provider: "design-generation", design_domain: options.designDomain };
      if (options.designHash) ctx.design_hash = options.designHash;
      if (options.modelVersion) ctx.model_version = options.modelVersion;
      payload.ai_context = ctx;
    }
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness simulation validation of AI-generated design (AI-ENG.2).
   * DO-178C 6.3, ASME V&V 10 4.1, ISO 26262-4.
   */
  witnessSimulationValidation(options: {
    simulationsRun: number;
    simulationsPassed: number;
    simulationType: string;
    simulationHash?: string;
    acceptanceCriteria?: string;
  }): WitnessPayload {
    const fa = options.simulationsRun;
    const fb = options.simulationsPassed;
    const fc = SIMULATION_TYPE_CODES[options.simulationType] ?? 6;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-ENG.2", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-ENG.2", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `sim-${options.simulationType}`;
      const ctx: Record<string, unknown> = { provider: "simulation-validation", simulation_type: options.simulationType };
      if (options.simulationHash) ctx.simulation_hash = options.simulationHash;
      if (options.acceptanceCriteria) ctx.acceptance_criteria = options.acceptanceCriteria;
      payload.ai_context = ctx;
    }
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness safety-critical review gate (AI-ENG.3).
   * DO-178C 7.2, FDA 21 CFR 11.10(g), ISO 26262-2.
   */
  witnessSafetyReview(options: {
    reviewersRequired: number;
    reviewersApproved: number;
    approvalType: string;
    reviewId?: string;
    peLicense?: string;
  }): WitnessPayload {
    const fa = options.reviewersRequired;
    const fb = options.reviewersApproved;
    const fc = APPROVAL_TYPE_CODES[options.approvalType] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-ENG.3", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-ENG.3", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `review-${options.approvalType}`;
      const ctx: Record<string, unknown> = { provider: "safety-review", approval_type: options.approvalType };
      if (options.reviewId) ctx.review_id = options.reviewId;
      if (options.peLicense) ctx.pe_license = options.peLicense;
      payload.ai_context = ctx;
    }
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness material specification compliance (AI-ENG.4).
   * ASME V&V 10 3.3, DO-254 5.3, ISO 26262-8.
   */
  witnessMaterialCompliance(options: {
    specificationsChecked: number;
    specificationsMet: number;
    standard: string;
    materialId?: string;
    specificationRef?: string;
  }): WitnessPayload {
    const fa = options.specificationsChecked;
    const fb = options.specificationsMet;
    const fc = MATERIAL_STANDARD_CODES[options.standard] ?? 6;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-ENG.4", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-ENG.4", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `material-${options.standard}`;
      const ctx: Record<string, unknown> = { provider: "material-compliance", standard: options.standard };
      if (options.materialId) ctx.material_id = options.materialId;
      if (options.specificationRef) ctx.specification_ref = options.specificationRef;
      payload.ai_context = ctx;
    }
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness design revision chain (AI-ENG.5).
   * DO-178C 7.3, FDA 21 CFR 11.10(e), ASME V&V 10 2.4.
   */
  witnessDesignChain(options: {
    totalRevisions: number;
    aiGeneratedRevisions: number;
    chainStatus: string;
    designId?: string;
    finalHash?: string;
  }): WitnessPayload {
    const fa = options.totalRevisions;
    const fb = options.aiGeneratedRevisions;
    const fc = CHAIN_STATUS_CODES[options.chainStatus] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-ENG.5", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-ENG.5", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `design-chain-${options.chainStatus}`;
      const ctx: Record<string, unknown> = { provider: "design-revision-chain", chain_status: options.chainStatus, ai_revision_ratio: options.aiGeneratedRevisions / Math.max(options.totalRevisions, 1) };
      if (options.designId) ctx.design_id = options.designId;
      if (options.finalHash) ctx.final_hash = options.finalHash;
      payload.ai_context = ctx;
    }
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness fabrication release attestation (AI-ENG.6).
   * DO-178C 5.5, FDA 21 CFR 11.10(f), ISO 26262-4 7.4.4.
   */
  witnessFabricationRelease(options: {
    designHashVerified: boolean;
    authorizationCount: number;
    releaseType: string;
    productionSystemId?: string;
    approvedDesignHash?: string;
    finalDesignHash?: string;
  }): WitnessPayload {
    const fa = options.designHashVerified ? 1 : 0;
    const fb = options.authorizationCount;
    const fc = RELEASE_TYPE_CODES[options.releaseType] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-ENG.6", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-ENG.6", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `fabrication-${options.releaseType}`;
      const ctx: Record<string, unknown> = { provider: "fabrication-release", release_type: options.releaseType, design_hash_verified: options.designHashVerified };
      if (options.productionSystemId) ctx.production_system_id = options.productionSystemId;
      if (options.approvedDesignHash) ctx.approved_design_hash = options.approvedDesignHash;
      if (options.finalDesignHash) ctx.final_design_hash = options.finalDesignHash;
      payload.ai_context = ctx;
    }
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Agent Transaction Witnessing (AI-FIN.1) ─────────────────────

  /**
   * Witness an agent-initiated financial transaction (AI-FIN.1).
   * Factors: fa=authorization_type code, fb=amount_cents, fc=status code.
   */
  witnessTransaction(options: {
    amountCents: number;
    authorizationType: string;
    status: string;
    currency?: string;
    recipientHash?: string;
    purpose?: string;
    transactionRef?: string;
  }): WitnessPayload {
    const authCodes: Record<string, number> = { none: 0, pre_approved: 1, human: 2, policy: 3, budget_limit: 4 };
    const statusCodes: Record<string, number> = { pending: 0, authorized: 1, denied: 2, escalated: 3 };
    const fa = authCodes[options.authorizationType] ?? 0;
    const fb = options.amountCents;
    const fc = statusCodes[options.status] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-FIN.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-FIN.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `transaction-${options.authorizationType}`;
      const ctx: Record<string, unknown> = {
        provider: "transaction-witness",
        authorization_type: options.authorizationType,
        status: options.status,
      };
      if (options.currency) ctx.currency = options.currency;
      if (options.recipientHash) ctx.recipient_hash = options.recipientHash;
      if (options.purpose) ctx.purpose = options.purpose;
      if (options.transactionRef) ctx.transaction_ref = options.transactionRef;
      payload.ai_context = ctx;
    }
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Tool Permission Attestation (AI-TOOL.2) ────────────────────

  /**
   * Witness tool permission grants and changes (AI-TOOL.2).
   * Factors: fa=granted_tool_count, fb=charter_match (1/0), fc=permission_change_type code.
   */
  witnessToolPermissions(options: {
    tools: string[];
    charterMatch: boolean;
    charterHash?: string;
    changeType?: string;
    driftDetails?: string;
  }): WitnessPayload {
    const changeCodes: Record<string, number> = { none: 0, added: 1, removed: 2, escalated: 3 };
    const fa = options.tools.length;
    const fb = options.charterMatch ? 1 : 0;
    const fc = changeCodes[options.changeType ?? "initial"] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-TOOL.2", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-TOOL.2", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `tool-permissions-${options.changeType ?? "initial"}`;
      const ctx: Record<string, unknown> = {
        provider: "tool-permission-witness",
        tools: options.tools,
        charter_match: options.charterMatch,
        change_type: options.changeType ?? "initial",
      };
      if (options.charterHash) ctx.charter_hash = options.charterHash;
      if (options.driftDetails) ctx.drift_details = options.driftDetails;
      payload.ai_context = ctx;
    }
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Agent Lifecycle Witnessing (AI-LCM.1) ──────────────────────

  /**
   * Witness agent lifecycle events (AI-LCM.1).
   * Factors: fa=event_type code, fb=context_tokens, fc=state_hash_present (1/0).
   */
  witnessLifecycle(options: {
    event: string;
    contextTokens?: number;
    stateHash?: string;
    parentAgentId?: string;
    uptimeMs?: number;
    terminationReason?: string;
  }): WitnessPayload {
    const eventCodes: Record<string, number> = { spawn: 0, checkpoint: 1, migrate: 2, terminate: 3, crash: 4 };
    const fa = eventCodes[options.event] ?? 0;
    const fb = options.contextTokens ?? 0;
    const fc = options.stateHash ? 1 : 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-LCM.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-LCM.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `lifecycle-${options.event}`;
      const ctx: Record<string, unknown> = {
        provider: "lifecycle-witness",
        event: options.event,
      };
      if (options.contextTokens !== undefined) ctx.context_tokens = options.contextTokens;
      if (options.stateHash) ctx.state_hash = options.stateHash;
      if (options.parentAgentId) ctx.parent_agent_id = options.parentAgentId;
      if (options.uptimeMs !== undefined) ctx.uptime_ms = options.uptimeMs;
      if (options.terminationReason) ctx.termination_reason = options.terminationReason;
      payload.ai_context = ctx;
    }
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Cross-Border Inference Routing (AI-JUR.1) ──────────────────

  /**
   * Witness cross-border inference routing decisions (AI-JUR.1).
   * Factors: fa=serving_region ISO numeric, fb=user_region ISO numeric, fc=compliance_status code.
   */
  witnessRouting(options: {
    servingRegion: string;
    userRegion: string;
    complianceStatus?: string;
    routingDecision?: string;
    applicableFrameworks?: string[];
    dataResidencyRequired?: boolean;
  }): WitnessPayload {
    const regionCodes: Record<string, number> = {
      US: 840, GB: 826, DE: 276, FR: 250, JP: 392, KR: 410, CN: 156,
      IN: 356, BR: 76, AU: 36, CA: 124, SG: 702, NL: 528, SE: 752, IE: 372,
      IL: 376, AE: 784, CH: 756, IT: 380, ES: 724,
    };
    const complianceCodes: Record<string, number> = { unchecked: 0, compliant: 1, blocked: 2, override: 3 };
    const fa = regionCodes[options.servingRegion] ?? 0;
    const fb = regionCodes[options.userRegion] ?? 0;
    const fc = complianceCodes[options.complianceStatus ?? "compliant"] ?? 0;
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-JUR.1", fa, fb, fc, ts);
    const payload: WitnessPayload = {
      procedure_id: "AI-JUR.1", factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = `routing-${options.servingRegion}-${options.userRegion}`;
      const ctx: Record<string, unknown> = {
        provider: "routing-witness",
        serving_region: options.servingRegion,
        user_region: options.userRegion,
        compliance_status: options.complianceStatus ?? "compliant",
      };
      if (options.routingDecision) ctx.routing_decision = options.routingDecision;
      if (options.applicableFrameworks) ctx.applicable_frameworks = options.applicableFrameworks;
      if (options.dataResidencyRequired !== undefined) ctx.data_residency_required = options.dataResidencyRequired;
      payload.ai_context = ctx;
    }
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
        if (this._localMode) {
          console.info(`\n  [SWT3] Local mode -- anchors saved to ${this.config.factorHandoffPath}/`);
        } else {
          console.info(
            `\n  [SWT3] ${payloads.length} anchors saved locally to ${this.config.factorHandoffPath}` +
            `\n  [SWT3] Local anchors are not persisted to the ledger.` +
            `\n  [SWT3] Connect to persist: https://sovereign.tenova.io/signup?ref=sdk (free)\n`
          );
        }
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

  /** Return framework coverage of procedures witnessed this session. */
  coverage(framework?: string): Record<string, unknown> {
    const witnessed = [...this.buffer.witnessedProcedures].sort();
    const fwCovered: Record<string, Set<string>> = {};
    for (const pid of witnessed) {
      const mappings = crosswalkResolve(pid);
      for (const [fw, ref] of Object.entries(mappings)) {
        if (!fwCovered[fw]) fwCovered[fw] = new Set();
        fwCovered[fw].add(ref);
      }
    }
    const result: Record<string, unknown> = {
      witnessed_procedures: witnessed,
      procedure_count: witnessed.length,
      frameworks_covered: Object.fromEntries(
        Object.entries(fwCovered).map(([fw, refs]) => [fw, [...refs].sort()]),
      ),
    };
    if (framework) {
      const fwMap = crosswalkResolveFramework(framework);
      const allProcs = new Set<string>();
      for (const procs of Object.values(fwMap)) {
        for (const p of procs) allProcs.add(p);
      }
      const covered = witnessed.filter((p: string) => allProcs.has(p));
      const missing = [...allProcs].filter((p) => !this.buffer.witnessedProcedures.has(p)).sort();
      result.framework = framework;
      result.total_controls = allProcs.size;
      result.covered = covered;
      result.covered_count = covered.length;
      result.remaining = missing;
      result.remaining_count = missing.length;
      result.score = allProcs.size > 0 ? Math.round((covered.length / allProcs.size) * 1000) / 1000 : 0;
    }
    return result;
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

  // ── Operational Governance Methods (v6.0) ─────────────────────

  /**
   * Witness a CI emergency override event (AI-EMRG.1).
   *
   * For governance policy overrides, use witnessEmergencyOverride() (AI-METAGOV.6).
   */
  witnessOperationalOverride(options: {
    triggerType: string;
    authorizationLevel: string;
    fallbackState: string;
    overrideReason?: string;
    systemId?: string;
    operatorId?: string;
  }): WitnessPayload {
    const fa = OVERRIDE_TRIGGER_CODES[options.triggerType] ?? 0;
    const fb = AUTHORIZATION_LEVEL_CODES[options.authorizationLevel] ?? 0;
    const fc = FALLBACK_STATE_CODES[options.fallbackState] ?? 0;
    const [ts, ep] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-EMRG.1", fa, fb, fc, ts);
    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    const payload: WitnessPayload = {
      procedure_id: "AI-EMRG.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: ep,
      fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = options.systemId ?? "unknown-system";
      const ctx: Record<string, unknown> = {
        provider: "emergency_override",
        trigger_type: options.triggerType,
        authorization_level: options.authorizationLevel,
        fallback_state: options.fallbackState,
      };
      if (options.overrideReason) ctx.override_reason = options.overrideReason;
      if (options.operatorId) ctx.operator_id = options.operatorId;
      payload.ai_context = ctx;
    }
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness a consequence-mapped drift response (AI-DRIFT.2).
   */
  witnessDriftConsequence(options: {
    driftMagnitude: number;
    consequenceCategory: string;
    responseAction: string;
    driftMetric?: string;
    modelId?: string;
    mappingVersion?: string;
  }): WitnessPayload {
    const fa = options.driftMagnitude;
    const fb = CONSEQUENCE_CATEGORY_CODES[options.consequenceCategory] ?? 0;
    const fc = DRIFT_RESPONSE_CODES[options.responseAction] ?? 0;
    const [ts, ep] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-DRIFT.2", fa, fb, fc, ts);
    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    const payload: WitnessPayload = {
      procedure_id: "AI-DRIFT.2",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: ep,
      fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = options.modelId ?? "unknown-model";
      const ctx: Record<string, unknown> = {
        provider: "drift_consequence",
        consequence_category: options.consequenceCategory,
        response_action: options.responseAction,
      };
      if (options.driftMetric) ctx.drift_metric = options.driftMetric;
      if (options.mappingVersion) ctx.mapping_version = options.mappingVersion;
      payload.ai_context = ctx;
    }
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness a champion-challenger assessment result (AI-ASSESS.1).
   */
  witnessChampionChallenger(options: {
    inputsProcessed: number;
    maxDivergence: number;
    thresholdBreached: boolean;
    championId?: string;
    challengerId?: string;
    divergenceMetric?: string;
    evaluationPeriod?: string;
  }): WitnessPayload {
    const fa = options.inputsProcessed;
    const fb = options.maxDivergence * 1000; // x1000 quantization per spec
    const fc = options.thresholdBreached ? 1 : 0;
    const [ts, ep] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-ASSESS.1", fa, fb, fc, ts);
    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    const payload: WitnessPayload = {
      procedure_id: "AI-ASSESS.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: ep,
      fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = options.championId ?? "unknown-champion";
      const ctx: Record<string, unknown> = {
        provider: "champion_challenger",
        threshold_breached: options.thresholdBreached,
      };
      if (options.challengerId) ctx.challenger_id = options.challengerId;
      if (options.divergenceMetric) ctx.divergence_metric = options.divergenceMetric;
      if (options.evaluationPeriod) ctx.evaluation_period = options.evaluationPeriod;
      payload.ai_context = ctx;
    }
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  /**
   * Witness cumulative resource consumption (AI-COST.1).
   *
   * Records token usage, API call counts, and estimated cost for
   * accountability and budget governance. Verdict is always PASS --
   * this procedure witnesses consumption, it does not enforce budgets.
   */
  witnessResourceConsumption(options: {
    tokensIn: number;
    tokensOut: number;
    apiCalls: number;
    costCents?: number;
    provider?: string;
    modelId?: string;
    computeSeconds?: number;
    costTableVersion?: string;
    deploymentContext?: Record<string, unknown>;
  }): WitnessPayload {
    const costCents = options.costCents ?? -1;
    const provider = options.provider ?? "unknown";
    const fa = options.tokensIn + options.tokensOut;
    const fb = options.apiCalls;
    const fc = costCents;
    const [ts, ep] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, "AI-COST.1", fa, fb, fc, ts);
    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12) : undefined;
    const payload: WitnessPayload = {
      procedure_id: "AI-COST.1",
      factor_a: fa, factor_b: fb, factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp, anchor_epoch: ep,
      fingerprint_timestamp_ms: ts,
    };
    if (this.config.clearingLevel <= 1) {
      payload.ai_model_id = options.modelId ?? "unknown-model";
      const ctx: Record<string, unknown> = {
        provider,
        tokens_in: options.tokensIn,
        tokens_out: options.tokensOut,
        api_calls: options.apiCalls,
        cost_cents: costCents,
      };
      if (options.computeSeconds !== undefined) ctx.compute_seconds = options.computeSeconds;
      if (options.costTableVersion) ctx.cost_table_version = options.costTableVersion;
      if (options.deploymentContext) ctx.deployment_context = options.deploymentContext;
      payload.ai_context = ctx;
    } else if (this.config.clearingLevel === 2) {
      payload.ai_model_id = options.modelId ?? "unknown-model";
      const ctx2: Record<string, unknown> = { provider_category: "llm_provider" };
      if (options.deploymentContext) {
        ctx2.deployment_context = {
          cloud_provider: options.deploymentContext.cloud_provider,
          runtime: options.deploymentContext.runtime,
        };
      }
      payload.ai_context = ctx2;
    }
    // clearing_level 3: factors only, no metadata
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return payload;
  }

  // ── Lifecycle Chain API (v6.0) ──────────────────────────────────

  /**
   * Start a new lifecycle chain for a governance procedure.
   *
   * Mints the first anchor with lifecycle_stage="initiated" and generates
   * a deterministic lifecycle_chain_id. Returns a LifecycleChain handle
   * that auto-links subsequent anchors.
   */
  beginLifecycle(
    procedureId: string,
    fa: number,
    fb: number,
    fc: number,
    options?: { modelId?: string; context?: Record<string, unknown> },
  ): LifecycleChain {
    const [ts, ep] = timestampMs();
    const fp = mintFingerprint(this.config.tenantId, procedureId, fa, fb, fc, ts);
    const chainId = generateLifecycleChainId(this.config.tenantId, procedureId, fp, ts);
    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;

    const payload: WitnessPayload = {
      procedure_id: procedureId,
      factor_a: fa,
      factor_b: fb,
      factor_c: fc,
      clearing_level: this.config.clearingLevel,
      anchor_fingerprint: fp,
      anchor_epoch: ep,
      fingerprint_timestamp_ms: ts,
      lifecycle_chain_id: chainId,
      lifecycle_stage: "initiated",
    };
    if (options?.modelId && this.config.clearingLevel <= 1) {
      payload.ai_model_id = options.modelId;
    }
    if (options?.context && this.config.clearingLevel <= 1) {
      payload.ai_context = options.context;
    }
    this._applyOperationalMetadata(payload, policyHash);
    this.buffer.enqueueMany([payload]);
    return new LifecycleChain(this, procedureId, chainId, fp);
  }

  /**
   * Resume a lifecycle chain after crash recovery or process restart.
   *
   * Reconstructs a LifecycleChain handle from known state without
   * minting any new anchors.
   */
  resumeLifecycle(
    procedureId: string,
    chainId: string,
    lastFingerprint: string,
    anchorCount: number = 1,
  ): LifecycleChain {
    if (!chainId.startsWith("LC-") || chainId.length !== 19) {
      throw new Error(`Invalid lifecycle chain ID: "${chainId}" (expected LC- + 16 hex chars)`);
    }
    return new LifecycleChain(this, procedureId, chainId, lastFingerprint, anchorCount);
  }
}

/**
 * Handle for a multi-anchor lifecycle chain.
 *
 * Auto-links anchors via lifecycle_chain_id and lifecycle_parent.
 * Enforces terminal stage finality (no minting after resolve/abandon).
 *
 * Usage:
 *   const chain = witness.beginLifecycle("AI-EMRG.1", 1.0, 1.0, 0.0);
 *   chain.checkpoint(1.0, 0.8, 0.0);
 *   chain.resolve(1.0, 1.0, 0.0);
 */

/**
 * Scoped cycle_id injection for auto-chaining.
 * All witness calls inside the callback share the same cycle_id.
 */
export class ChainContext {
  readonly cycleId: string;
  readonly name: string;
  constructor(cycleId: string, name: string) {
    this.cycleId = cycleId;
    this.name = name;
  }
}

export class LifecycleChain {
  private _witness: Witness;
  private _procedureId: string;
  private _chainId: string;
  private _lastFingerprint: string;
  private _anchorCount: number;
  private _closed: boolean;

  constructor(
    witness: Witness,
    procedureId: string,
    chainId: string,
    lastFingerprint: string,
    anchorCount: number = 1,
  ) {
    this._witness = witness;
    this._procedureId = procedureId;
    this._chainId = chainId;
    this._lastFingerprint = lastFingerprint;
    this._anchorCount = anchorCount;
    this._closed = false;
  }

  get chainId(): string { return this._chainId; }
  get lastFingerprint(): string { return this._lastFingerprint; }
  get anchorCount(): number { return this._anchorCount; }
  get closed(): boolean { return this._closed; }

  private _assertOpen(): void {
    if (this._closed) {
      throw new Error(
        `Lifecycle chain ${this._chainId} is closed (terminal stage reached). Cannot mint further anchors.`,
      );
    }
  }

  private _mint(
    fa: number,
    fb: number,
    fc: number,
    stage: string,
    options?: {
      procedureId?: string;
      escalationChainId?: string;
      context?: Record<string, unknown>;
    },
  ): WitnessPayload {
    this._assertOpen();
    const w = this._witness as any;
    const proc = options?.procedureId ?? this._procedureId;
    const [ts, ep] = timestampMs();
    const fp = mintFingerprint(w.config.tenantId, proc, fa, fb, fc, ts);
    const policyHash = w.config.policyVersion
      ? sha256Truncated(w.config.policyVersion, 12)
      : undefined;

    const payload: WitnessPayload = {
      procedure_id: proc,
      factor_a: fa,
      factor_b: fb,
      factor_c: fc,
      clearing_level: w.config.clearingLevel,
      anchor_fingerprint: fp,
      anchor_epoch: ep,
      fingerprint_timestamp_ms: ts,
      lifecycle_chain_id: this._chainId,
      lifecycle_parent: this._lastFingerprint,
      lifecycle_stage: stage,
    };
    if (options?.escalationChainId) {
      payload.escalation_chain_id = options.escalationChainId;
    }
    if (options?.context && w.config.clearingLevel <= 1) {
      payload.ai_context = options.context;
    }
    w._applyOperationalMetadata(payload, policyHash);
    w.buffer.enqueueMany([payload]);
    this._lastFingerprint = fp;
    this._anchorCount++;
    if (TERMINAL_STAGES.has(stage)) {
      this._closed = true;
    }
    return payload;
  }

  /** Mint a checkpoint anchor in this lifecycle chain. */
  checkpoint(
    fa: number,
    fb: number,
    fc: number,
    options?: { context?: Record<string, unknown> },
  ): WitnessPayload {
    return this._mint(fa, fb, fc, "checkpoint", { context: options?.context });
  }

  /**
   * Escalate to a new lifecycle chain for a different procedure.
   *
   * Mints an "escalated" anchor on THIS chain, then starts a new chain
   * for the target procedure. The two chains are linked via escalation_chain_id.
   */
  escalate(
    targetProcedureId: string,
    fa: number = 0.0,
    fb: number = 0.0,
    fc: number = 0.0,
    options?: { context?: Record<string, unknown> },
  ): LifecycleChain {
    const targetChain = this._witness.beginLifecycle(
      targetProcedureId, fa, fb, fc, { context: options?.context },
    );
    this._mint(fa, fb, fc, "escalated", {
      escalationChainId: targetChain.chainId,
      context: options?.context,
    });
    return targetChain;
  }

  /** Mint a resolution anchor, closing this lifecycle chain. */
  resolve(
    fa: number,
    fb: number,
    fc: number,
    options?: { context?: Record<string, unknown> },
  ): WitnessPayload {
    return this._mint(fa, fb, fc, "resolved", { context: options?.context });
  }

  /** Mint an abandonment anchor, closing this lifecycle chain. */
  abandon(options?: { reason?: string; context?: Record<string, unknown> }): WitnessPayload {
    const ctx = { ...(options?.context ?? {}) };
    if (options?.reason) {
      (ctx as any).abandon_reason = options.reason;
    }
    return this._mint(0.0, 0.0, 0.0, "abandoned", { context: Object.keys(ctx).length ? ctx : undefined });
  }
}

/**
 * Validate a governance rule graph for circular dependencies (AI-METAGOV.4).
 *
 * Uses Kahn's algorithm (BFS topological sort) to detect cycles in governance
 * rule dependency graphs. Returns validation results including any detected cycles.
 */
export function validateGovernanceGraph(rules: {
  id: string;
  dependencies?: string[];
}[]): { valid: boolean; cycles: string[][]; maxDepth: number; ruleCount: number } {
  // Build adjacency list and in-degree map
  const adj = new Map<string, string[]>();
  const inDegree = new Map<string, number>();
  for (const rule of rules) {
    if (!adj.has(rule.id)) adj.set(rule.id, []);
    if (!inDegree.has(rule.id)) inDegree.set(rule.id, 0);
    for (const dep of rule.dependencies ?? []) {
      if (!adj.has(dep)) adj.set(dep, []);
      if (!inDegree.has(dep)) inDegree.set(dep, 0);
      adj.get(dep)!.push(rule.id);
      inDegree.set(rule.id, (inDegree.get(rule.id) ?? 0) + 1);
    }
  }

  // Kahn's algorithm
  const queue: string[] = [];
  for (const [node, deg] of inDegree) {
    if (deg === 0) queue.push(node);
  }
  const sorted: string[] = [];
  const depths = new Map<string, number>();
  for (const node of queue) depths.set(node, 0);

  while (queue.length > 0) {
    const node = queue.shift()!;
    sorted.push(node);
    for (const neighbor of adj.get(node) ?? []) {
      const newDeg = (inDegree.get(neighbor) ?? 1) - 1;
      inDegree.set(neighbor, newDeg);
      depths.set(neighbor, Math.max(depths.get(neighbor) ?? 0, (depths.get(node) ?? 0) + 1));
      if (newDeg === 0) queue.push(neighbor);
    }
  }

  // Nodes not in sorted = part of cycles
  const cycleNodes = new Set<string>();
  for (const [node, deg] of inDegree) {
    if (deg > 0) cycleNodes.add(node);
  }

  // Extract cycle paths from remaining nodes
  const cycles: string[][] = [];
  if (cycleNodes.size > 0) {
    const visited = new Set<string>();
    for (const start of cycleNodes) {
      if (visited.has(start)) continue;
      const cycle: string[] = [];
      let current: string | undefined = start;
      while (current && !visited.has(current) && cycleNodes.has(current)) {
        visited.add(current);
        cycle.push(current);
        current = (adj.get(current) ?? []).find(n => cycleNodes.has(n) && !visited.has(n));
      }
      if (cycle.length > 0) cycles.push(cycle);
    }
  }

  const maxDepth = Math.max(0, ...Array.from(depths.values()));
  return {
    valid: cycles.length === 0,
    cycles,
    maxDepth,
    ruleCount: rules.length,
  };
}
