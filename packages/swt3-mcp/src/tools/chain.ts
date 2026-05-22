/**
 * SWT3 MCP Server: multi-agent chain tools.
 *
 * Metadata tagging for multi-agent pipelines. start_chain generates a
 * cycle_id, chain_handoff witnesses custody transfer. Neither blocks
 * execution.
 */

import { randomUUID } from "node:crypto";
import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import type { SessionState } from "../state.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

interface StartChainArgs {
  description?: string;
}

interface HandoffArgs {
  cycle_id: string;
  from_agent: string;
  to_agent: string;
  context?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export function handleStartChain(
  args: StartChainArgs,
  state: SessionState,
): string {
  // Idempotent: return existing chain if active
  if (state.activeChain) {
    return [
      `Chain already active.`,
      `Cycle ID: ${state.activeChain.cycleId}`,
      `Description: ${state.activeChain.description}`,
      `Started: ${new Date(state.activeChain.startedAt).toISOString()}`,
      ``,
      `Pass this cycle_id to witness_inference and chain_handoff calls.`,
    ].join("\n");
  }

  const cycleId = randomUUID();
  state.activeChain = {
    cycleId,
    description: args.description || "unnamed chain",
    startedAt: Date.now(),
  };

  return [
    `Chain started.`,
    `Cycle ID: ${cycleId}`,
    `Description: ${args.description || "unnamed chain"}`,
    ``,
    `Pass this cycle_id to witness_inference and chain_handoff calls`,
    `to link all anchors in this multi-agent chain.`,
  ].join("\n");
}

export async function handleChainHandoff(
  args: HandoffArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-CHAIN.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;

  // AI-CHAIN.1 factors: handoff occurred (always 1), transfer complete (always 1), reserved
  const factorA = 1;
  const factorB = 1;
  const factorC = 0;

  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(
    config.tenantId,
    procedureId,
    factorA,
    factorB,
    factorC,
    ts,
  );

  const payload: WitnessPayload = {
    procedure_id: procedureId,
    factor_a: factorA,
    factor_b: factorB,
    factor_c: factorC,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
  };

  // Apply clearing level to handoff context
  if (clearingLevel <= 1) {
    payload.ai_model_id = `${args.from_agent} -> ${args.to_agent}`;
    payload.ai_context = {
      provider: "chain",
      from_agent: args.from_agent,
      to_agent: args.to_agent,
      handoff_context: args.context || "unspecified",
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = `${args.from_agent} -> ${args.to_agent}`;
  } else {
    payload.ai_model_id = sha256Truncated(`${args.from_agent}:${args.to_agent}`);
  }

  payload.witness_source = "mcp";
  payload.cycle_id = args.cycle_id;

  const agentId = config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  // Demo mode
  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Chain Handoff Witnessed`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `From: ${args.from_agent}`,
      `To: ${args.to_agent}`,
      `Cycle ID: ${args.cycle_id}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);

  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt.tenant_id;
  }

  return [
    `Chain Handoff Witnessed`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Procedure: ${receipt.procedure_id}`,
    `From: ${args.from_agent}`,
    `To: ${args.to_agent}`,
    `Cycle ID: ${args.cycle_id}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
