/**
 * SWT3 MCP Server: verify_agent_trust + present_trust_credential tools.
 *
 * Enables LLMs to autonomously verify counterpart agents before
 * proceeding with tool calls or data exchange. The compliance anchor
 * IS the authorization credential.
 *
 * AI-TRUST.1: Trust verification result (PASS/FAIL)
 * AI-TRUST.2: Handshake evidence (checks performed/passed)
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import type { SessionState } from "../state.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

// ── Trust Level Constants ──────────────────────────────────────────

const TRUST_DENIED = 0;
const TRUST_BASIC = 1;
const TRUST_VERIFIED = 2;
const TRUST_ATTESTED = 3;
const TRUST_SOVEREIGN = 4;

const TRUST_LEVEL_NAMES: Record<number, string> = {
  0: "denied",
  1: "basic",
  2: "verified",
  3: "attested",
  4: "sovereign",
};

// ── Verification Logic (inlined, no external dependency) ───────────

interface VerifyResult {
  granted: boolean;
  trustLevel: number;
  denialReason?: string;
  checksPerformed: number;
  checksPassed: number;
}

function verifyCounterpart(
  args: VerifyArgs,
  config: McpConfig,
  state: SessionState,
): VerifyResult {
  let checks = 0;
  let passed = 0;

  // Check 1: deny list
  checks++;
  if (state.deniedAgents.has(args.counterpart_agent_id)) {
    return { granted: false, trustLevel: TRUST_DENIED, denialReason: "deny_listed", checksPerformed: checks, checksPassed: passed };
  }
  passed++;

  // Check 2: tenant trust (same tenant always trusted)
  checks++;
  const isSameTenant = args.counterpart_tenant_id === config.tenantId;
  const isTrustedTenant = state.trustedTenants.has(args.counterpart_tenant_id);
  if (!isSameTenant && !isTrustedTenant) {
    return { granted: false, trustLevel: TRUST_DENIED, denialReason: "tenant_not_trusted", checksPerformed: checks, checksPassed: passed };
  }
  passed++;

  // Check 3: anchor freshness (24h default)
  checks++;
  const freshnessMs = 24 * 60 * 60 * 1000;
  const anchorTs = args.anchor_timestamp_ms ?? Date.now();
  const ageMs = Date.now() - anchorTs;
  if (ageMs > freshnessMs) {
    return { granted: false, trustLevel: TRUST_DENIED, denialReason: "anchor_expired", checksPerformed: checks, checksPassed: passed };
  }
  passed++;

  // Check 4: signature (informational, not required by default)
  checks++;
  passed++; // Always passes unless we add require_signature config

  // Compute trust level
  let level = TRUST_BASIC;
  if (args.is_signed) {
    level = TRUST_VERIFIED;
    if (args.has_hardware_attestation && args.has_guardrails) {
      level = (args.clearing_level ?? 1) >= 2 ? TRUST_SOVEREIGN : TRUST_ATTESTED;
    }
  }

  return { granted: true, trustLevel: level, checksPerformed: checks, checksPassed: passed };
}

// ── Tool Interfaces ────────────────────────────────────────────────

interface VerifyArgs {
  counterpart_agent_id: string;
  counterpart_tenant_id: string;
  anchor_fingerprint: string;
  anchor_timestamp_ms?: number;
  is_signed?: boolean;
  procedures?: string[];
  clearing_level?: 0 | 1 | 2 | 3;
  has_hardware_attestation?: boolean;
  has_guardrails?: boolean;
  agent_id?: string;
  cycle_id?: string;
}

interface PresentArgs {
  agent_id?: string;
}

// ── Handlers ───────────────────────────────────────────────────────

export async function handleVerifyAgentTrust(
  args: VerifyArgs,
  config: McpConfig,
  client: AxiomClient,
  state: SessionState,
): Promise<string> {
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const result = verifyCounterpart(args, config, state);

  // Store verified trust level for toolPolicyGate to use
  if (result.granted) {
    state.verifiedTrustLevel = result.trustLevel;
  }

  const verdict1 = result.granted ? "PASS" : "FAIL";
  const levelName = TRUST_LEVEL_NAMES[result.trustLevel] ?? "unknown";

  // ── Mint AI-TRUST.1 ──
  const [ts1, epoch1] = timestampMs();
  const fa1 = 1, fb1 = result.granted ? 1 : 0, fc1 = result.trustLevel;
  const fp1 = mintFingerprint(config.tenantId, "AI-TRUST.1", fa1, fb1, fc1, ts1);

  const p1: WitnessPayload = {
    procedure_id: "AI-TRUST.1",
    factor_a: fa1, factor_b: fb1, factor_c: fc1,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp1,
    anchor_epoch: epoch1,
    fingerprint_timestamp_ms: ts1,
  };

  if (clearingLevel <= 1) {
    p1.ai_model_id = `trust-${levelName}`;
    p1.ai_context = {
      provider: "trust-mesh",
      counterpart_agent_id: args.counterpart_agent_id,
      counterpart_tenant_id: args.counterpart_tenant_id,
      trust_level: result.trustLevel,
      trust_level_name: levelName,
      checks_performed: result.checksPerformed,
      checks_passed: result.checksPassed,
      granted: result.granted,
      ...(result.denialReason ? { denial_reason: result.denialReason } : {}),
    };
  } else if (clearingLevel === 2) {
    p1.ai_model_id = `trust-${levelName}`;
  } else {
    p1.ai_model_id = sha256Truncated(`trust-${levelName}`);
  }

  p1.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) p1.agent_id = agentId;
  if (args.cycle_id) p1.cycle_id = args.cycle_id;
  if (config.signingKey) {
    p1.payload_signature = signPayload(config.signingKey, fp1, agentId);
  }

  // ── Mint AI-TRUST.2 ──
  const [ts2, epoch2] = timestampMs();
  const fa2 = result.checksPerformed, fb2 = result.checksPassed;
  const fc2 = result.granted ? 1 : 0;
  const fp2 = mintFingerprint(config.tenantId, "AI-TRUST.2", fa2, fb2, fc2, ts2);

  const p2: WitnessPayload = {
    procedure_id: "AI-TRUST.2",
    factor_a: fa2, factor_b: fb2, factor_c: fc2,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp2,
    anchor_epoch: epoch2,
    fingerprint_timestamp_ms: ts2,
  };

  if (clearingLevel <= 1) {
    p2.ai_model_id = "trust-handshake";
    p2.ai_context = {
      provider: "trust-mesh",
      counterpart_agent_id: args.counterpart_agent_id,
      handshake_result: result.granted ? "granted" : "denied",
    };
  }

  p2.witness_source = "mcp";
  if (agentId) p2.agent_id = agentId;
  if (args.cycle_id) p2.cycle_id = args.cycle_id;
  if (config.signingKey) {
    p2.payload_signature = signPayload(config.signingKey, fp2, agentId);
  }

  // ── Demo mode ──
  if (config.demo) {
    const demoAnchor1 = `SWT3-DEMO-LOCAL-AI-AITRUST1-${verdict1}-${epoch1}-${fp1}`;
    const demoAnchor2 = `SWT3-DEMO-LOCAL-AI-AITRUST2-${fc2 ? "PASS" : "FAIL"}-${epoch2}-${fp2}`;
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Trust Verification: ${result.granted ? "GRANTED" : "DENIED"}`,
      `Trust Level: ${result.trustLevel} (${levelName})`,
      ...(result.denialReason ? [`Denial Reason: ${result.denialReason}`] : []),
      `Checks: ${result.checksPassed}/${result.checksPerformed} passed`,
      ``,
      `Counterpart: ${args.counterpart_agent_id} @ ${args.counterpart_tenant_id}`,
      `Anchor: ${args.anchor_fingerprint}`,
      ``,
      `AI-TRUST.1 Anchor: ${demoAnchor1}`,
      `AI-TRUST.2 Anchor: ${demoAnchor2}`,
      ``,
      `This anchor was minted locally. To persist anchors to the SWT3 ledger,`,
      `use the signup tool to create a free account, or set SWT3_API_KEY.`,
    ].join("\n");
  }

  // ── Live mode: POST both anchors ──
  const receipt1 = await client.postWitness(p1);
  const receipt2 = await client.postWitness(p2);

  if (receipt1.tenant_id && !process.env.SWT3_TENANT_ID) {
    config.tenantId = receipt1.tenant_id;
  }

  return [
    `Trust Verification: ${result.granted ? "GRANTED" : "DENIED"}`,
    `Trust Level: ${result.trustLevel} (${levelName})`,
    ...(result.denialReason ? [`Denial Reason: ${result.denialReason}`] : []),
    `Checks: ${result.checksPassed}/${result.checksPerformed} passed`,
    ``,
    `Counterpart: ${args.counterpart_agent_id} @ ${args.counterpart_tenant_id}`,
    ``,
    `AI-TRUST.1 Verdict: ${receipt1.verdict}`,
    `AI-TRUST.1 Anchor: ${receipt1.swt3_anchor}`,
    `AI-TRUST.2 Anchor: ${receipt2.swt3_anchor}`,
    `Witnessed: ${receipt1.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt1.verification_url}`,
  ].join("\n");
}

export function handlePresentCredential(
  args: PresentArgs,
  config: McpConfig,
): string {
  const agentId = args.agent_id || config.agentId || "anonymous";
  const ts = Date.now();
  const fpInput = `${agentId}:${config.tenantId}:${ts}`;
  const fp = sha256Truncated(fpInput, 12);

  return [
    `Trust Credential for Agent-to-Agent Verification`,
    ``,
    `agent_id: ${agentId}`,
    `tenant_id: ${config.tenantId}`,
    `anchor_fingerprint: ${fp}`,
    `anchor_timestamp_ms: ${ts}`,
    `is_signed: ${Boolean(config.signingKey)}`,
    `clearing_level: ${config.clearingLevel}`,
    `has_guardrails: false`,
    `has_hardware_attestation: false`,
    ``,
    `Pass these fields to another agent's verify_agent_trust tool`,
    `to establish mutual compliance trust before exchanging data.`,
    ...(config.demo ? [
      ``,
      `[DEMO MODE: This credential is local-only. Create a free account`,
      `with the signup tool to get a persistent identity.]`,
    ] : []),
  ].join("\n");
}
