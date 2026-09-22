/**
 * SWT3 MCP Server: A2A (Agent-to-Agent) protocol tools.
 *
 * Witnesses A2A task delegation lifecycle, Agent Card discovery,
 * and context chain linking. Duck-typed -- no A2A protocol import.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

// ── AI-A2A.1: Task Delegation Lifecycle ───────────────────────────────

interface TaskLifecycleArgs {
  state_code: number;
  latency_ms: number;
  depth?: number;
  task_id?: string;
  from_agent?: string;
  to_agent?: string;
  context_id?: string;
  previous_state?: number;
  clearing_level?: 0 | 1 | 2 | 3;
}

const STATE_LABELS: Record<number, string> = {
  0: "submitted", 1: "working", 2: "input_required",
  3: "completed", 4: "failed", 5: "canceled", 6: "rejected",
};

export async function handleWitnessTaskLifecycle(
  args: TaskLifecycleArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-A2A.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const fa = args.state_code;
  const fb = args.latency_ms;
  const fc = args.depth ?? 1;

  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(config.tenantId, procedureId, fa, fb, fc, ts);

  const payload: WitnessPayload = {
    procedure_id: procedureId,
    factor_a: fa, factor_b: fb, factor_c: fc,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
  };

  const stateLabel = STATE_LABELS[args.state_code] ?? `state-${args.state_code}`;

  if (clearingLevel <= 1) {
    payload.ai_model_id = `a2a-task-${stateLabel}`;
    const ctx: Record<string, unknown> = {
      provider: "a2a",
      state_code: args.state_code,
      latency_ms: args.latency_ms,
      depth: args.depth ?? 1,
    };
    if (args.task_id) ctx.task_id_hash = sha256Truncated(args.task_id, 12);
    if (args.from_agent) ctx.from_agent_hash = sha256Truncated(args.from_agent, 12);
    if (args.to_agent) ctx.to_agent_hash = sha256Truncated(args.to_agent, 12);
    if (args.context_id) ctx.context_id_hash = sha256Truncated(args.context_id, 12);
    if (args.previous_state !== undefined) ctx.previous_state = args.previous_state;
    payload.ai_context = ctx;
  } else {
    payload.ai_model_id = `a2a-task-${stateLabel}`;
  }

  payload.witness_source = "mcp";
  if (config.agentId) payload.agent_id = config.agentId;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, config.agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `A2A Task Lifecycle Witnessed`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `State: ${stateLabel}`,
      `Latency: ${args.latency_ms}ms`,
      `Depth: ${args.depth ?? 1}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt.tenant_id;
  }

  return [
    `A2A Task Lifecycle Witnessed`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Procedure: ${receipt.procedure_id}`,
    `State: ${stateLabel}`,
    `Latency: ${args.latency_ms}ms`,
    `Depth: ${args.depth ?? 1}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}

// ── AI-A2A.2: Agent Card Discovery ────────────────────────────────────

interface AgentCardDiscoveryArgs {
  discovery_method: number;
  agents_discovered: number;
  verified_count?: number;
  card_hash?: string;
  capabilities_count?: number;
  auth_schemes?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

const DISCOVERY_LABELS: Record<number, string> = {
  0: "direct_url", 1: "well_known", 2: "registry", 3: "referral",
};

export async function handleWitnessAgentCardDiscovery(
  args: AgentCardDiscoveryArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-A2A.2";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const fa = args.discovery_method;
  const fb = args.agents_discovered;
  const fc = args.verified_count ?? 0;

  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(config.tenantId, procedureId, fa, fb, fc, ts);

  const payload: WitnessPayload = {
    procedure_id: procedureId,
    factor_a: fa, factor_b: fb, factor_c: fc,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
  };

  const methodLabel = DISCOVERY_LABELS[args.discovery_method] ?? `method-${args.discovery_method}`;

  if (clearingLevel <= 1) {
    payload.ai_model_id = `a2a-discovery-${methodLabel}`;
    const ctx: Record<string, unknown> = {
      provider: "a2a",
      discovery_method: args.discovery_method,
      agents_discovered: args.agents_discovered,
      verified_count: args.verified_count ?? 0,
    };
    if (args.card_hash) ctx.card_hash = args.card_hash;
    if (args.capabilities_count !== undefined) ctx.capabilities_count = args.capabilities_count;
    if (args.auth_schemes) ctx.auth_schemes = args.auth_schemes;
    payload.ai_context = ctx;
  } else {
    payload.ai_model_id = `a2a-discovery-${methodLabel}`;
  }

  payload.witness_source = "mcp";
  if (config.agentId) payload.agent_id = config.agentId;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, config.agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `A2A Agent Card Discovery Witnessed`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Method: ${methodLabel}`,
      `Agents Discovered: ${args.agents_discovered}`,
      `Verified: ${args.verified_count ?? 0}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt.tenant_id;
  }

  return [
    `A2A Agent Card Discovery Witnessed`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Procedure: ${receipt.procedure_id}`,
    `Method: ${methodLabel}`,
    `Agents Discovered: ${args.agents_discovered}`,
    `Verified: ${args.verified_count ?? 0}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}

// ── AI-A2A.3: Context Chain Linking ───────────────────────────────────

interface ContextChainArgs {
  chain_length: number;
  context_id: string;
  agents_in_chain: number;
  originator_id?: string;
  current_agent_id?: string;
  chain_complete?: boolean;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessContextChain(
  args: ContextChainArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-A2A.3";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const fa = args.chain_length;
  const ctxHash = sha256Truncated(args.context_id, 8);
  const fb = parseInt(ctxHash, 16);
  const fc = args.agents_in_chain;

  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(config.tenantId, procedureId, fa, fb, fc, ts);

  const payload: WitnessPayload = {
    procedure_id: procedureId,
    factor_a: fa, factor_b: fb, factor_c: fc,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
  };

  if (clearingLevel <= 1) {
    payload.ai_model_id = `a2a-chain-${sha256Truncated(args.context_id, 6)}`;
    payload.ai_context = {
      provider: "a2a",
      chain_length: args.chain_length,
      context_id_hash: sha256Truncated(args.context_id, 12),
      agents_in_chain: args.agents_in_chain,
      chain_complete: args.chain_complete ?? true,
      ...(args.originator_id && { originator_hash: sha256Truncated(args.originator_id, 12) }),
      ...(args.current_agent_id && { current_agent_hash: sha256Truncated(args.current_agent_id, 12) }),
    };
  } else {
    payload.ai_model_id = `a2a-chain-${sha256Truncated(args.context_id, 6)}`;
  }

  payload.witness_source = "mcp";
  if (config.agentId) payload.agent_id = config.agentId;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, config.agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `A2A Context Chain Witnessed`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Chain Length: ${args.chain_length}`,
      `Agents: ${args.agents_in_chain}`,
      `Complete: ${args.chain_complete ?? true}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt.tenant_id;
  }

  return [
    `A2A Context Chain Witnessed`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Procedure: ${receipt.procedure_id}`,
    `Chain Length: ${args.chain_length}`,
    `Agents: ${args.agents_in_chain}`,
    `Complete: ${args.chain_complete ?? true}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
