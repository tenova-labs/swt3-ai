/**
 * SWT3 MCP Server: NHI / HBOM / DPP / ADR vertical witness tools (v6.7).
 *
 * 22 tools across 4 new namespaces. Each tool witnesses a specific governance
 * event by minting an SWT3 anchor with computed factors. Evidence only --
 * never blocks execution.
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

const NHI_LIFECYCLE_CODES: Record<string, number> = { issued: 1, activated: 2, suspended: 3, expired: 4, revoked: 5 };
const NHI_ROTATION_CODES: Record<string, number> = { scheduled: 1, compromise: 2, policy: 3, manual: 4 };
const NHI_REVOCATION_CODES: Record<string, number> = { unspecified: 0, model_recall: 1, policy_violation: 2, data_contamination: 3, consent_withdrawal: 4, regulatory_order: 5, error_correction: 6 };
const HBOM_LIFECYCLE_CODES: Record<string, number> = { installed: 1, commissioned: 2, maintained: 3, degraded: 4, decommissioned: 5, recycled: 6 };
const HBOM_WATER_CODES: Record<string, number> = { municipal: 1, recycled: 2, rainwater: 3, groundwell: 4, mixed: 5 };
const DPP_CHARGE_CODES: Record<string, number> = { charge_start: 1, charge_complete: 2, discharge_start: 3, discharge_complete: 4 };
const DPP_DEGRAD_CODES: Record<string, number> = { calendar_aging: 1, thermal_stress: 2, overcharge: 3, deep_discharge: 4, mechanical: 5, unknown: 6 };
const DPP_DISPOSITION_CODES: Record<string, number> = { recycling: 1, repurpose: 2, refurbishment: 3, landfill: 4, hazmat_disposal: 5 };
const ADR_PHASE_CODES: Record<string, number> = { signal_received: 1, curtailment_start: 2, curtailment_end: 3, restoration: 4 };
const ADR_BASELINE_CODES: Record<string, number> = { metered_10day_avg: 1, regression: 2, real_time_meter: 3, deemed_savings: 4 };
const ADR_CREDIT_CODES: Record<string, number> = { rec: 1, carbon_offset: 2, eac: 3, guarantee_of_origin: 4 };
const ADR_SIGNAL_CODES: Record<string, number> = { emergency: 1, economic: 2, capacity: 3, frequency_regulation: 4, voltage_support: 5 };

// ── Internal helpers ────────────────────────────────────────────────

function hashToFactor(hex: string): number {
  return parseInt(hex.slice(0, 8), 16);
}

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

// ── NHI Tools ───────────────────────────────────────────────────────

export async function handleNhiScope(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const credHash = sha256Truncated(args.credential_id);
  const scopeHash = sha256Truncated((args.scope as string).toLowerCase());
  const fa = hashToFactor(credHash), fb = hashToFactor(scopeHash), fc = args.ttl_seconds ?? 0;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "NHI-SCOPE.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `nhi-scope-${credHash.slice(0, 8)}`;
    payload.ai_context = { provider: "nhi-governance", credential_id_hash: credHash, scope_hash: scopeHash, ttl_seconds: fc };
  }
  return submit(config, client, payload, fp, epoch, "Credential Scope", "NHI-SCOPE.1", [`TTL: ${fc}s`]);
}

export async function handleNhiLifecycle(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const credHash = sha256Truncated(args.credential_id);
  const issuerHash = sha256Truncated(args.issuer);
  const fa = NHI_LIFECYCLE_CODES[args.event_type] ?? 0, fb = hashToFactor(credHash), fc = hashToFactor(issuerHash);
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "NHI-CYCLE.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `nhi-lifecycle-${args.event_type}`;
    payload.ai_context = { provider: "nhi-governance", event_type: args.event_type, credential_id_hash: credHash, issuer_hash: issuerHash };
  }
  return submit(config, client, payload, fp, epoch, "Credential Lifecycle", "NHI-CYCLE.1", [`Event: ${args.event_type}`, `Issuer: [hashed]`]);
}

export async function handleNhiPrivilegeChange(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const credHash = sha256Truncated(args.credential_id);
  const fa = hashToFactor(credHash);
  const fb = args.previous_scope ? hashToFactor(sha256Truncated(args.previous_scope.toLowerCase())) : 0;
  const fc = hashToFactor(sha256Truncated(args.new_scope.toLowerCase()));
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "NHI-PRIV.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `nhi-priv-${credHash.slice(0, 8)}`;
    payload.ai_context = { provider: "nhi-governance", credential_id_hash: credHash };
  }
  return submit(config, client, payload, fp, epoch, "Privilege Change", "NHI-PRIV.1", [`Credential: [hashed]`]);
}

export async function handleNhiRotation(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const oldHash = sha256Truncated(args.old_credential_id);
  const newHash = sha256Truncated(args.new_credential_id);
  const reason = args.reason ?? "scheduled";
  const fa = hashToFactor(oldHash), fb = hashToFactor(newHash), fc = NHI_ROTATION_CODES[reason] ?? 1;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "NHI-ROTATE.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `nhi-rotate-${reason}`;
    payload.ai_context = { provider: "nhi-governance", old_credential_hash: oldHash, new_credential_hash: newHash, rotation_reason: reason };
  }
  return submit(config, client, payload, fp, epoch, "Credential Rotation", "NHI-ROTATE.1", [`Reason: ${reason}`]);
}

export async function handleNhiDelegation(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const delegatorHash = sha256Truncated(args.delegator_credential_id);
  const delegateeHash = sha256Truncated(args.delegatee_credential_id);
  const depth = Math.max(1, args.delegation_depth ?? 1);
  const fa = hashToFactor(delegatorHash), fb = hashToFactor(delegateeHash), fc = depth;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "NHI-AGENT.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `nhi-delegation-depth${depth}`;
    payload.ai_context = { provider: "nhi-governance", delegator_hash: delegatorHash, delegatee_hash: delegateeHash, delegation_depth: depth };
  }
  return submit(config, client, payload, fp, epoch, "Agent Delegation", "NHI-AGENT.1", [`Depth: ${depth}`]);
}

export async function handleNhiRevocation(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const credHash = sha256Truncated(args.credential_id);
  const reason = args.reason ?? "unspecified";
  const cascade = args.cascade ?? false;
  const fa = hashToFactor(credHash), fb = NHI_REVOCATION_CODES[reason] ?? 0, fc = cascade ? 1 : 0;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "NHI-REVOKE.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `nhi-revoke-${reason}`;
    payload.ai_context = { provider: "nhi-governance", revoked_credential_hash: credHash, reason_code: reason, cascade };
  }
  return submit(config, client, payload, fp, epoch, "Credential Revocation", "NHI-REVOKE.1", [`Reason: ${reason}`, `Cascade: ${cascade}`]);
}

export async function handleNhiExpiration(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const credHash = sha256Truncated(args.credential_id);
  const renewalPossible = args.renewal_possible ?? false;
  const gracePeriod = args.grace_period_seconds ?? 0;
  const fa = hashToFactor(credHash);
  const fb = Math.floor(args.expires_epoch_ms / 1000);
  const fc = (renewalPossible ? 1 : 0) | (Math.min(gracePeriod, 0xFFFFFF) << 8);
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "NHI-EXPIRE.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    const label = renewalPossible ? "renewable" : "permanent";
    payload.ai_model_id = `nhi-expire-${label}`;
    payload.ai_context = { provider: "nhi-governance", credential_hash: credHash, expires_epoch_ms: args.expires_epoch_ms, renewal_possible: renewalPossible, grace_period_seconds: gracePeriod };
  }
  return submit(config, client, payload, fp, epoch, "Credential Expiration", "NHI-EXPIRE.1", [`Expires: ${new Date(args.expires_epoch_ms).toISOString()}`, `Renewable: ${renewalPossible}`]);
}

// ── HBOM Tools ──────────────────────────────────────────────────────

export async function handleHbomInventory(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = args.component_count, fb = hashToFactor(args.manifest_hash), fc = args.delta_from_baseline ?? 0;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "HBOM-INV.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `hbom-inv-${fa}`;
    payload.ai_context = { provider: "hbom-governance", component_count: fa, manifest_hash: args.manifest_hash.slice(0, 16), delta_from_baseline: fc };
  }
  return submit(config, client, payload, fp, epoch, "Hardware Inventory", "HBOM-INV.1", [`Components: ${fa}`, `Delta: ${fc}`]);
}

export async function handleHbomLifecycle(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const compHash = sha256Truncated(args.component_id);
  const fa = HBOM_LIFECYCLE_CODES[args.event_type] ?? 0, fb = hashToFactor(compHash), fc = args.age_days ?? 0;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "HBOM-LIFE.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `hbom-lifecycle-${args.event_type}`;
    payload.ai_context = { provider: "hbom-governance", event_type: args.event_type, component_hash: compHash, age_days: fc };
  }
  return submit(config, client, payload, fp, epoch, "Component Lifecycle", "HBOM-LIFE.1", [`Event: ${args.event_type}`, `Age: ${fc} days`]);
}

export async function handleHbomThermal(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = args.ambient_temp_c, fb = args.component_temp_c, fc = args.threshold_exceeded ? 1 : 0;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "HBOM-THERM.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `hbom-thermal-${fc ? "alarm" : "normal"}`;
    payload.ai_context = { provider: "hbom-governance", ambient_temp_c: fa, component_temp_c: fb, threshold_exceeded: !!args.threshold_exceeded };
  }
  return submit(config, client, payload, fp, epoch, "Thermal Profile", "HBOM-THERM.1", [`Ambient: ${fa}C`, `Component: ${fb}C`, fc ? "THRESHOLD EXCEEDED" : "Within bounds"]);
}

export async function handleHbomWater(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const source = args.source_type ?? "municipal";
  const fa = args.liters_consumed, fb = args.wue_ratio_x1000, fc = HBOM_WATER_CODES[source] ?? 1;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "HBOM-WATER.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `hbom-water-${source}`;
    payload.ai_context = { provider: "hbom-governance", liters_consumed: fa, wue_ratio_x1000: fb, source_type: source };
  }
  return submit(config, client, payload, fp, epoch, "Water Consumption", "HBOM-WATER.1", [`Liters: ${fa}`, `WUE: ${fb / 1000}`, `Source: ${source}`]);
}

export async function handleHbomPue(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = args.total_facility_kw, fb = args.it_load_kw, fc = args.pue_x1000;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "HBOM-PUE.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `hbom-pue-${fc}`;
    payload.ai_context = { provider: "hbom-governance", total_facility_kw: fa, it_load_kw: fb, pue_x1000: fc };
  }
  return submit(config, client, payload, fp, epoch, "Power Usage Effectiveness", "HBOM-PUE.1", [`Facility: ${fa} kW`, `IT Load: ${fb} kW`, `PUE: ${fc / 1000}`]);
}

export async function handleHbomSupply(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const supplierHash = sha256Truncated(args.supplier_id);
  const countryHash = sha256Truncated(args.country_of_origin.toUpperCase());
  const fa = hashToFactor(supplierHash), fb = args.provenance_verified ? 1 : 0, fc = hashToFactor(countryHash);
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "HBOM-SUPPLY.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `hbom-supply-${fb ? "verified" : "unverified"}`;
    payload.ai_context = { provider: "hbom-governance", supplier_hash: supplierHash, provenance_verified: !!args.provenance_verified, country_hash: countryHash };
  }
  return submit(config, client, payload, fp, epoch, "Supply Chain Provenance", "HBOM-SUPPLY.1", [`Verified: ${!!args.provenance_verified}`]);
}

// ── DPP Tools ───────────────────────────────────────────────────────

export async function handleDppSoh(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = Math.round(args.soh_percent * 100), fb = args.cycle_count, fc = Math.round(args.capacity_kwh * 100);
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "DPP-SOH.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `dpp-soh-${Math.round(args.soh_percent)}pct`;
    payload.ai_context = { provider: "dpp-governance", soh_percent: args.soh_percent, cycle_count: fb, capacity_kwh: args.capacity_kwh };
  }
  return submit(config, client, payload, fp, epoch, "Battery State of Health", "DPP-SOH.1", [`SoH: ${args.soh_percent}%`, `Cycles: ${fb}`, `Capacity: ${args.capacity_kwh} kWh`]);
}

export async function handleDppCharge(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = DPP_CHARGE_CODES[args.event_type] ?? 0, fb = Math.round(args.energy_kwh * 100), fc = args.peak_temp_c;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "DPP-CHRG.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `dpp-chrg-${args.event_type}`;
    payload.ai_context = { provider: "dpp-governance", event_type: args.event_type, energy_kwh: args.energy_kwh, peak_temp_c: fc };
  }
  return submit(config, client, payload, fp, epoch, "Charge/Discharge Cycle", "DPP-CHRG.1", [`Event: ${args.event_type}`, `Energy: ${args.energy_kwh} kWh`, `Peak Temp: ${fc}C`]);
}

export async function handleDppDegrad(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = DPP_DEGRAD_CODES[args.degradation_type] ?? 6, fb = Math.round(args.soh_delta_percent * 100), fc = args.ambient_temp_c;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "DPP-DEGRAD.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `dpp-degrad-${args.degradation_type}`;
    payload.ai_context = { provider: "dpp-governance", degradation_type: args.degradation_type, soh_delta_percent: args.soh_delta_percent, ambient_temp_c: fc };
  }
  return submit(config, client, payload, fp, epoch, "Battery Degradation", "DPP-DEGRAD.1", [`Type: ${args.degradation_type}`, `SoH Drop: ${args.soh_delta_percent}%`]);
}

export async function handleDppEol(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const handlerHash = sha256Truncated(args.handler_id);
  const fa = DPP_DISPOSITION_CODES[args.disposition_type] ?? 1, fb = hashToFactor(handlerHash), fc = Math.round(args.final_soh_percent * 100);
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "DPP-EOL.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `dpp-eol-${args.disposition_type}`;
    payload.ai_context = { provider: "dpp-governance", disposition_type: args.disposition_type, handler_hash: handlerHash, final_soh_percent: args.final_soh_percent };
  }
  return submit(config, client, payload, fp, epoch, "End of Life Handoff", "DPP-EOL.1", [`Disposition: ${args.disposition_type}`, `Final SoH: ${args.final_soh_percent}%`]);
}

// ── ADR Tools ───────────────────────────────────────────────────────

export async function handleAdrEvent(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const signalHash = sha256Truncated(args.signal_source);
  const fa = ADR_PHASE_CODES[args.event_phase] ?? 0, fb = args.committed_kw, fc = hashToFactor(signalHash);
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "ADR-EVENT.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `adr-event-${args.event_phase}`;
    payload.ai_context = { provider: "adr-governance", event_phase: args.event_phase, committed_kw: fb, signal_source_hash: signalHash };
  }
  return submit(config, client, payload, fp, epoch, "Demand Response Event", "ADR-EVENT.1", [`Phase: ${args.event_phase}`, `Committed: ${fb} kW`]);
}

export async function handleAdrBaseline(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const method = args.measurement_method;
  const fa = args.baseline_kw, fb = ADR_BASELINE_CODES[method] ?? 1, fc = args.confidence_x1000 ?? 950;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "ADR-BASE.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `adr-baseline-${method}`;
    payload.ai_context = { provider: "adr-governance", baseline_kw: fa, measurement_method: method, confidence_x1000: fc };
  }
  return submit(config, client, payload, fp, epoch, "Baseline Consumption", "ADR-BASE.1", [`Baseline: ${fa} kW`, `Method: ${method}`, `Confidence: ${fc / 10}%`]);
}

export async function handleAdrCurtailment(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = args.actual_reduction_kw, fb = args.committed_kw, fc = args.compliance_ratio_x1000;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "ADR-CURT.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `adr-curtailment-${fc}`;
    payload.ai_context = { provider: "adr-governance", actual_reduction_kw: fa, committed_kw: fb, compliance_ratio_x1000: fc };
  }
  return submit(config, client, payload, fp, epoch, "Curtailment Verification", "ADR-CURT.1", [`Actual: ${fa} kW`, `Committed: ${fb} kW`, `Compliance: ${fc / 10}%`]);
}

export async function handleAdrSettlement(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = Math.round(args.settlement_kwh * 100), fb = Math.round(args.price_usd_per_mwh * 100), fc = args.event_count;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "ADR-SETTLE.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `adr-settlement-${fc}events`;
    payload.ai_context = { provider: "adr-governance", settlement_kwh: args.settlement_kwh, price_usd_per_mwh: args.price_usd_per_mwh, event_count: fc };
  }
  return submit(config, client, payload, fp, epoch, "Settlement Data", "ADR-SETTLE.1", [`Energy: ${args.settlement_kwh} kWh`, `Price: $${args.price_usd_per_mwh}/MWh`, `Events: ${fc}`]);
}

export async function handleAdrCarbon(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const registryHash = sha256Truncated(args.registry_id);
  const fa = ADR_CREDIT_CODES[args.credit_type] ?? 1, fb = Math.round(args.quantity_mwh * 100), fc = hashToFactor(registryHash);
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "ADR-CARBON.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `adr-carbon-${args.credit_type}`;
    payload.ai_context = { provider: "adr-governance", credit_type: args.credit_type, quantity_mwh: args.quantity_mwh, registry_hash: registryHash };
  }
  return submit(config, client, payload, fp, epoch, "Carbon Credit / REC", "ADR-CARBON.1", [`Type: ${args.credit_type}`, `Quantity: ${args.quantity_mwh} MWh`]);
}

export async function handleAdrGrid(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const operatorHash = sha256Truncated(args.grid_operator);
  const fa = ADR_SIGNAL_CODES[args.signal_type] ?? 1, fb = args.response_latency_ms, fc = hashToFactor(operatorHash);
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "ADR-GRID.1", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `adr-grid-${args.signal_type}`;
    payload.ai_context = { provider: "adr-governance", signal_type: args.signal_type, response_latency_ms: fb, grid_operator_hash: operatorHash };
  }
  return submit(config, client, payload, fp, epoch, "Grid Signal Correlation", "ADR-GRID.1", [`Signal: ${args.signal_type}`, `Latency: ${fb}ms`]);
}

// ── MCP Security Attestation (AI-MCP.2/3/4) ──────────────────────

const MCP_AUTH_LABELS: Record<number, string> = { 0: "none", 1: "api_key", 2: "oauth", 3: "mtls", 4: "did" };
const MCP_DISCOVERY_LABELS: Record<number, string> = { 0: "manual", 1: "dns-sd", 2: "mdns", 3: "registry", 4: "network" };

export async function handleMcpToolIntegrity(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const schemaStr = typeof args.tool_schema === "string" ? args.tool_schema : JSON.stringify(args.tool_schema);
  const schemaHash = sha256Truncated(schemaStr, 16);
  const fa = parseInt(schemaHash, 16) % 2 ** 32;
  const fb = args.invocation_seq ?? 0;
  const drift = args.previous_schema_hash && args.previous_schema_hash !== schemaHash ? 1 : 0;
  const fc = drift;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "AI-MCP.2", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    payload.ai_model_id = `mcp-tool-${args.tool_name}`;
    payload.ai_context = { provider: "mcp-tool-integrity", tool_name: args.tool_name, schema_hash: schemaHash, invocation_seq: fb, schema_drift: drift === 1 };
    if (args.server_name) payload.ai_context.server_name = args.server_name;
  }
  return submit(config, client, payload, fp, epoch, "Tool Integrity", "AI-MCP.2", [`Tool: ${args.tool_name}`, `Drift: ${drift === 1}`]);
}

export async function handleMcpServerAuth(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = args.auth_method ?? 0, fb = args.credential_validity_seconds ?? 0, fc = args.mutual_auth ? 1 : 0;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "AI-MCP.3", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    const label = MCP_AUTH_LABELS[fa] ?? `unknown-${fa}`;
    payload.ai_model_id = `mcp-auth-${label}`;
    payload.ai_context = { provider: "mcp-server-auth", auth_method: fa, credential_validity_seconds: fb, mutual_auth: fc === 1 };
    if (args.server_name) payload.ai_context.server_name = args.server_name;
  }
  return submit(config, client, payload, fp, epoch, "Server Authentication", "AI-MCP.3", [`Auth: ${MCP_AUTH_LABELS[fa] ?? fa}`, `Mutual: ${fc === 1}`]);
}

export async function handleMcpServerDiscovery(args: any, config: McpConfig, client: AxiomClient): Promise<string> {
  const fa = args.discovery_method ?? 0, fb = args.servers_found, fc = args.unauthorized_count ?? 0;
  const { payload, fp, epoch, clearingLevel } = buildPayload(config, "AI-MCP.4", fa, fb, fc, args);
  if (clearingLevel <= 1) {
    const label = MCP_DISCOVERY_LABELS[fa] ?? `method-${fa}`;
    payload.ai_model_id = `mcp-discovery-${label}`;
    payload.ai_context = { provider: "mcp-server-discovery", discovery_method: fa, servers_found: fb, unauthorized_count: fc };
  }
  return submit(config, client, payload, fp, epoch, "Server Discovery", "AI-MCP.4", [`Servers: ${fb}`, `Unauthorized: ${fc}`]);
}
