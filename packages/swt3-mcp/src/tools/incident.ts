/**
 * SWT3 MCP Server: witness_incident tool (AI-INCIDENT.1).
 *
 * Witnesses incident detection and reporting. Creates a tamper-evident
 * record of when an incident was detected, its severity, and whether
 * authorities were notified -- critical for NIS-2 24h/72h windows.
 * Evidence only -- never blocks execution.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

const SEVERITY_CODES: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const INCIDENT_TYPE_CODES: Record<string, number> = {
  safety: 0,
  rights: 1,
  security: 2,
  performance: 3,
  bias: 4,
  other: 5,
};

interface IncidentArgs {
  severity: string;
  incident_type?: string;
  authority_notified?: boolean;
  description_hash?: string;
  detection_method?: string;
  reporting_deadline_hours?: number;
  incident_id?: string;
  model_id?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleWitnessIncident(
  args: IncidentArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-INCIDENT.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const incidentType = args.incident_type ?? "other";

  const factorA = SEVERITY_CODES[args.severity] ?? 2;
  const factorB = args.authority_notified ? 1 : 0;
  const factorC = INCIDENT_TYPE_CODES[incidentType] ?? 5;

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
    payload.ai_model_id = args.model_id ?? `incident-${incidentType}`;
    const ctx: Record<string, unknown> = {
      provider: "incident-reporting",
      severity: args.severity,
      incident_type: incidentType,
      authority_notified: args.authority_notified ?? false,
    };
    if (args.description_hash) ctx.description_hash = args.description_hash;
    if (args.detection_method) ctx.detection_method = args.detection_method;
    if (args.reporting_deadline_hours != null) ctx.reporting_deadline_hours = args.reporting_deadline_hours;
    if (args.incident_id) ctx.incident_id = args.incident_id;
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.model_id ?? `incident-${incidentType}`;
    payload.ai_context = { provider_category: "incident-reporting" };
  } else {
    payload.ai_model_id = sha256Truncated(args.model_id ?? `incident-${incidentType}`);
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  const sevLabel = args.severity.charAt(0).toUpperCase() + args.severity.slice(1);

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-AIINCIDENT1-PASS-${epoch}-${fp}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Incident Witnessed (AI-INCIDENT.1)`,
      `Verdict: PASS`,
      `Anchor: ${demoAnchor}`,
      `Severity: ${sevLabel}`,
      `Type: ${incidentType}`,
      `Authority Notified: ${args.authority_notified ? "YES" : "NO"}`,
      args.reporting_deadline_hours != null ? `Reporting Deadline: ${args.reporting_deadline_hours}h` : null,
      `Model: ${args.model_id ?? "unknown"}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].filter(Boolean).join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  return [
    `Incident Witnessed (AI-INCIDENT.1)`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Severity: ${sevLabel}`,
    `Type: ${incidentType}`,
    `Authority Notified: ${args.authority_notified ? "YES" : "NO"}`,
    args.reporting_deadline_hours != null ? `Reporting Deadline: ${args.reporting_deadline_hours}h` : null,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].filter(Boolean).join("\n");
}
