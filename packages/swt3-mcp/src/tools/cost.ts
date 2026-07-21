/**
 * SWT3 MCP Server: witness_resource_consumption tool (AI-COST.1).
 *
 * Records token usage, API call counts, and estimated cost for
 * accountability and budget governance. Verdict is always PASS --
 * this procedure witnesses consumption, it does not enforce budgets.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

interface ResourceConsumptionArgs {
  tokens_in: number;
  tokens_out: number;
  api_calls: number;
  cost_cents?: number;
  provider?: string;
  model_id?: string;
  compute_seconds?: number;
  cost_table_version?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessResourceConsumption(
  args: ResourceConsumptionArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-COST.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const costCents = args.cost_cents ?? -1;
  const provider = args.provider ?? "unknown";

  const factorA = args.tokens_in + args.tokens_out;
  const factorB = args.api_calls;
  const factorC = costCents;

  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(config.tenantId, procedureId, factorA, factorB, factorC, ts);

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

  if (clearingLevel <= 1) {
    payload.ai_model_id = args.model_id ?? "unknown-model";
    const ctx: Record<string, unknown> = {
      provider,
      tokens_in: args.tokens_in,
      tokens_out: args.tokens_out,
      api_calls: args.api_calls,
      cost_cents: costCents,
    };
    if (args.compute_seconds !== undefined) ctx.compute_seconds = args.compute_seconds;
    if (args.cost_table_version) ctx.cost_table_version = args.cost_table_version;
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.model_id ?? "unknown-model";
    payload.ai_context = { provider_category: "llm_provider" };
  } else {
    payload.ai_model_id = sha256Truncated(args.model_id ?? "unknown-model");
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AICOST1-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Resource Consumption Witnessed`,
      `Verdict: PASS`,
      `Anchor: ${demoAnchor}`,
      `Provider: ${provider}`,
      `Model: ${args.model_id ?? "unknown-model"}`,
      `Tokens: ${args.tokens_in} in + ${args.tokens_out} out = ${factorA} total`,
      `API Calls: ${args.api_calls}`,
      `Cost: ${costCents === -1 ? "unknown" : `${costCents} cents`}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Resource Consumption Witnessed`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Provider: ${provider}`,
    `Model: ${args.model_id ?? "unknown-model"}`,
    `Tokens: ${args.tokens_in} in + ${args.tokens_out} out = ${factorA} total`,
    `API Calls: ${args.api_calls}`,
    `Cost: ${costCents === -1 ? "unknown" : `${costCents} cents`}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
