/**
 * SWT3 MCP Server: OAuth token binding tool.
 *
 * Witnesses OAuth lifecycle events for MCP servers: discovery,
 * registration, grant, token binding, validation, refresh,
 * scope changes, and revocation. Provides confused deputy
 * prevention evidence and scope governance.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

interface OauthTokenBindingArgs {
  event_type: number;
  scope_count: number;
  binding_strength: number;
  server_name?: string;
  grant_type?: string;
  audience_hash?: string;
  scope_list?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

const EVENT_LABELS: Record<number, string> = {
  0: "discovery", 1: "registration", 2: "grant", 3: "token_bind",
  4: "validation", 5: "refresh", 6: "scope_change", 7: "revocation",
};

export async function handleWitnessOauthTokenBinding(
  args: OauthTokenBindingArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-MCP.5";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const fa = args.event_type;
  const fb = args.scope_count;
  const fc = args.binding_strength;

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

  const eventLabel = EVENT_LABELS[args.event_type] ?? `event-${args.event_type}`;

  if (clearingLevel <= 1) {
    payload.ai_model_id = `mcp-oauth-${eventLabel}`;
    const ctx: Record<string, unknown> = {
      provider: "mcp-oauth",
      event_type: args.event_type,
      scope_count: args.scope_count,
      binding_strength: args.binding_strength,
    };
    if (args.server_name) ctx.server_name = args.server_name;
    if (args.grant_type) ctx.grant_type = args.grant_type;
    if (args.audience_hash) ctx.audience_hash = args.audience_hash;
    if (args.scope_list) ctx.scope_list = args.scope_list;
    payload.ai_context = ctx;
  } else {
    payload.ai_model_id = `mcp-oauth-${eventLabel}`;
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
      `OAuth Token Binding Witnessed`,
      `Anchor: ${demoAnchor}`,
      `Procedure: ${procedureId}`,
      `Event: ${eventLabel}`,
      `Scopes: ${args.scope_count}`,
      `Binding: ${args.binding_strength}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt.tenant_id;
  }

  return [
    `OAuth Token Binding Witnessed`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Procedure: ${receipt.procedure_id}`,
    `Event: ${eventLabel}`,
    `Scopes: ${args.scope_count}`,
    `Binding: ${args.binding_strength}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
