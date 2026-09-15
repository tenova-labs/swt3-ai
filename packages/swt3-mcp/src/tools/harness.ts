/**
 * SWT3 MCP Server: Harness Governance witness tools (v0.7.2).
 *
 * 5 tools for orchestration, delegation, context management, sandbox,
 * and eval gate attestation. Evidence only -- never blocks execution.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

// ── Code Maps ───────────────────────────────────────────────────────

const ORCHESTRATION_TOPOLOGY_CODES: Record<string, number> = {
  sequential: 0, parallel: 1, hierarchical: 2, hybrid: 3, mesh: 4,
};

const EVICTION_METHOD_CODES: Record<string, number> = {
  none: 0, truncation: 1, summarization: 2, sliding_window: 3, priority_eviction: 4,
};

// ── Internal helpers ────────────────────────────────────────────────

function buildPayload(
  config: McpConfig, procedureId: string, fa: number, fb: number, fc: number,
  args: { agent_id?: string; cycle_id?: string; clearing_level?: number },
): { payload: WitnessPayload; fp: string; epoch: number; clearingLevel: number } {
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(config.tenantId, procedureId, fa, fb, fc, ts);
  const payload: WitnessPayload = {
    procedure_id: procedureId, factor_a: fa, factor_b: fb, factor_c: fc,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
    witness_source: "mcp",
  };
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  return { payload, fp, epoch, clearingLevel };
}

async function submit(
  config: McpConfig, client: AxiomClient, payload: WitnessPayload,
  fp: string, epoch: number, label: string, procedureId: string, extra: string[],
): Promise<string> {
  if (config.demo) {
    const pid = procedureId.replace(/[.-]/g, "");
    return [
      `[DEMO MODE: local only, not persisted]`, ``,
      `${label} Witnessed (${procedureId})`, `Verdict: PASS`,
      `Anchor: SWT3-DEMO-LOCAL-AI-${pid}-PASS-${epoch}-${fp}`,
      ...extra, `Fingerprint: ${fp}`,
    ].join("\n");
  }
  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;
  return [
    `${label} Witnessed (${procedureId})`, `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`, ...extra,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}

// ── Harness Governance Tools ────────────────────────────────────────

export async function handleOrchestrationTopology(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const topology = (args.topology as string) || "sequential";
  const fa = ORCHESTRATION_TOPOLOGY_CODES[topology] ?? 0;
  const fb = Math.max(args.agent_count ?? 1, 0);
  const fc = Math.max(args.dependency_depth ?? 0, 0);
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "AI-ORCH.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `orch-topology-${topology}`;
    payload.ai_context = { provider: "harness-governance", topology, agent_count: fb, dependency_depth: fc };
  }
  return submit(config, client, payload, fp, epoch, "Orchestration Topology", "AI-ORCH.1", [`Topology: ${topology}`, `Agents: ${fb}`, `Depth: ${fc}`]);
}

export async function handleAgentHandoff(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const d1Hash = sha256Truncated(args.delegator_id);
  const d2Hash = sha256Truncated(args.delegate_id);
  const fa = parseInt(d1Hash.slice(0, 8), 16);
  const fb = parseInt(d2Hash.slice(0, 8), 16);
  const delta = Math.max(-1, Math.min(1, args.permission_delta ?? 0));
  const fc = delta;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "AI-ORCH.2", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    const deltaLabel = delta > 0 ? "escalation" : (delta < 0 ? "restriction" : "lateral");
    payload.ai_model_id = `orch-handoff-${deltaLabel}`;
    payload.ai_context = { provider: "harness-governance", delegator_hash: d1Hash, delegate_hash: d2Hash, permission_delta: delta };
  }
  const deltaDesc = delta > 0 ? "escalation" : (delta < 0 ? "restriction" : "lateral");
  return submit(config, client, payload, fp, epoch, "Agent Handoff", "AI-ORCH.2", [`Delta: ${deltaDesc}`, `Delegator: [hashed]`, `Delegate: [hashed]`]);
}

export async function handleContextWindow(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const eviction = (args.eviction_method as string) || "none";
  const fa = Math.max(args.tokens_before ?? 0, 0);
  const fb = Math.max(args.tokens_after ?? 0, 0);
  const fc = EVICTION_METHOD_CODES[eviction] ?? 0;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "AI-CTX.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `ctx-window-${eviction}`;
    payload.ai_context = { provider: "harness-governance", tokens_before: fa, tokens_after: fb, eviction_method: eviction };
  }
  return submit(config, client, payload, fp, epoch, "Context Window", "AI-CTX.1", [`Before: ${fa} tokens`, `After: ${fb} tokens`, `Method: ${eviction}`]);
}

export async function handleSandboxEnforcement(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = Math.max(args.tools_declared ?? 0, 0);
  const fb = Math.max(args.tools_invoked ?? 0, 0);
  const fc = Math.max(args.violations ?? 0, 0);
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "AI-SAND.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `sandbox-${fc === 0 ? "clean" : "violation"}`;
    payload.ai_context = { provider: "harness-governance", tools_declared: fa, tools_invoked: fb, violations: fc };
  }
  return submit(config, client, payload, fp, epoch, "Sandbox Enforcement", "AI-SAND.1", [`Declared: ${fa}`, `Invoked: ${fb}`, `Violations: ${fc}`]);
}

export async function handleEvalGate(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = Math.max(args.total_evals ?? 0, 0);
  const fb = Math.max(args.evals_passed ?? 0, 0);
  let score = args.gate_score;
  if (score == null) {
    score = Math.round((fb / Math.max(fa, 1)) * 100);
  }
  const fc = Math.max(0, Math.min(100, score));
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "AI-GATE.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `eval-gate-${fc >= 70 ? "pass" : "fail"}`;
    payload.ai_context = { provider: "harness-governance", total_evals: fa, evals_passed: fb, gate_score: fc };
  }
  return submit(config, client, payload, fp, epoch, "Eval Gate", "AI-GATE.1", [`Evals: ${fb}/${fa}`, `Score: ${fc}/100`, `Gate: ${fc >= 70 ? "PASS" : "FAIL"}`]);
}
