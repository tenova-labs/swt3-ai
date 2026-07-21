/**
 * SWT3 MCP Server: witness_delegation_tree tool (AI-DEL.1).
 *
 * Witnesses hierarchical permission delegation with scope binding,
 * tree binding, and cascade revocation intent.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

interface DelegationTreeArgs {
  delegator_id: string;
  scope: string;
  delegation_depth: number;
  delegates?: string[];
  tree_hash?: string;
  cascade_revocation?: boolean;
  time_bound_minutes?: number;
  parent_grant_fingerprint?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessDelegationTree(
  args: DelegationTreeArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-DEL.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;

  const delegatorHash = sha256Truncated(args.delegator_id, 16);
  const scopeHash = sha256Truncated(args.scope, 16);
  const factorA = parseInt(delegatorHash.slice(0, 8), 16);
  const factorB = parseInt(scopeHash.slice(0, 8), 16);
  const factorC = args.delegation_depth;

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
    payload.ai_model_id = `delegation-tree-depth-${args.delegation_depth}`;
    const ctx: Record<string, unknown> = {
      provider: "delegation-tree",
      delegator_hash: delegatorHash,
      scope_hash: scopeHash,
      cascade_revocation: args.cascade_revocation ?? false,
      time_bound_minutes: args.time_bound_minutes ?? 0,
    };
    if (args.delegates) {
      ctx.delegates = args.delegates.map((d) => sha256Truncated(d));
    }
    if (args.tree_hash) ctx.tree_hash = args.tree_hash;
    if (args.parent_grant_fingerprint) {
      ctx.parent_grant_fingerprint = args.parent_grant_fingerprint;
    }
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = `delegation-tree-depth-${args.delegation_depth}`;
  } else {
    payload.ai_model_id = sha256Truncated(`delegation-tree-depth-${args.delegation_depth}`);
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIDEL1-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Delegation Tree Witnessed`,
      `Verdict: PASS`,
      `Anchor: ${demoAnchor}`,
      `Delegator: ${delegatorHash.slice(0, 8)}...`,
      `Scope: ${scopeHash.slice(0, 8)}...`,
      `Depth: ${args.delegation_depth}`,
      `Cascade Revocation: ${args.cascade_revocation ?? false}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Delegation Tree Witnessed`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Delegator: ${delegatorHash.slice(0, 8)}...`,
    `Scope: ${scopeHash.slice(0, 8)}...`,
    `Depth: ${args.delegation_depth}`,
    `Cascade Revocation: ${args.cascade_revocation ?? false}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
