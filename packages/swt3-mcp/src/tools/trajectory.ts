/**
 * SWT3 MCP Server: witness_trajectory tool (AI-MOB.6).
 *
 * Witnesses safety-critical trajectory decisions from VLA or
 * autonomous planning models. Model-agnostic -- works with any
 * VLA, path planner, or motion model.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

const SAFETY_CLASSIFICATION_CODES: Record<string, number> = {
  reserved: 0, nominal: 1, cautionary: 2,
  degraded: 3, emergency: 4, abort: 5,
};

interface TrajectoryArgs {
  safety_validated: boolean;
  waypoint_count?: number;
  trajectory_hash?: string;
  coc_trace_hash?: string;
  coc_node_count?: number;
  action_class?: string;
  safety_classification?: string;
  sensor_sources?: string[];
  model_id?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessTrajectory(
  args: TrajectoryArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-MOB.6";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const safetyClass = args.safety_classification ?? "nominal";

  const factorA = 1; // attestation required
  const factorB = args.safety_validated ? 1 : 0;
  const factorC = SAFETY_CLASSIFICATION_CODES[safetyClass] ?? 0;

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
    payload.ai_model_id = args.model_id ?? "trajectory-planner";
    const ctx: Record<string, unknown> = {
      provider: "trajectory",
      safety_validated: args.safety_validated,
      safety_classification: safetyClass,
    };
    if (args.waypoint_count != null) ctx.waypoint_count = args.waypoint_count;
    if (args.trajectory_hash) ctx.trajectory_hash = args.trajectory_hash;
    if (args.coc_trace_hash) ctx.coc_trace_hash = args.coc_trace_hash;
    if (args.coc_node_count != null) ctx.coc_node_count = args.coc_node_count;
    if (args.action_class) ctx.action_class = args.action_class;
    if (args.sensor_sources) {
      ctx.sensor_count = args.sensor_sources.length;
      ctx.sensor_sources = args.sensor_sources;
    }
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.model_id ?? "trajectory-planner";
    const ctx2: Record<string, unknown> = { provider_category: "trajectory" };
    if (args.sensor_sources) ctx2.sensor_count = args.sensor_sources.length;
    payload.ai_context = ctx2;
  } else {
    payload.ai_model_id = sha256Truncated(args.model_id ?? "trajectory-planner");
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIMOB6-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Trajectory Witnessed (AI-MOB.6)`,
      `Verdict: PASS`,
      `Anchor: ${demoAnchor}`,
      `Safety Validated: ${args.safety_validated ? "YES" : "NO"}`,
      `Safety Classification: ${safetyClass}`,
      args.waypoint_count != null ? `Waypoints: ${args.waypoint_count}` : null,
      args.action_class ? `Action: ${args.action_class}` : null,
      `Model: ${args.model_id ?? "trajectory-planner"}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].filter(Boolean).join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Trajectory Witnessed (AI-MOB.6)`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Safety Validated: ${args.safety_validated ? "YES" : "NO"}`,
    `Safety Classification: ${safetyClass}`,
    args.waypoint_count != null ? `Waypoints: ${args.waypoint_count}` : null,
    args.action_class ? `Action: ${args.action_class}` : null,
    `Model: ${args.model_id ?? "trajectory-planner"}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].filter(Boolean).join("\n");
}
