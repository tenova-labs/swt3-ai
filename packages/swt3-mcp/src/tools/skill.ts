/**
 * SWT3 MCP Server: skill attestation tools.
 *
 * attest_skill_manifest (AI-SKILL.1): Attest active skills/tools/plugins.
 * attest_memory_context (AI-SKILL.2): Attest memory sources influencing decisions.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

// -- AI-SKILL.1: Skill Manifest Attestation --

interface SkillManifestArgs {
  skills: Array<{ name: string; version?: string; hash?: string }>;
  expected_manifest_hash?: string;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleAttestSkillManifest(
  args: SkillManifestArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-SKILL.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;

  // Compute manifest hash from sorted skill hashes
  const skillHashes = args.skills
    .map((s) => s.hash || sha256Truncated(s.name))
    .sort();
  const computedManifest = sha256Truncated(skillHashes.join(":"));

  const match = args.expected_manifest_hash
    ? computedManifest === args.expected_manifest_hash
    : true;

  const factorA = args.skills.length;
  const factorB = match ? 1 : 0;
  const factorC = 0;
  const verdict = match ? "PASS" : "FAIL";

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
    payload.ai_model_id = "skill-manifest";
    payload.ai_context = {
      provider: "skill-manifest",
      skills: args.skills,
      manifest_hash: computedManifest,
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = "skill-manifest";
  } else {
    payload.ai_model_id = sha256Truncated("skill-manifest");
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-${verdict}-${epoch}-${fp}`;
    const skillNames = args.skills.map((s) => s.name).join(", ");
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Skill Manifest Attestation`,
      `Verdict: ${verdict}`,
      `Anchor: ${demoAnchor}`,
      `Skills: ${skillNames}`,
      `Count: ${args.skills.length}`,
      `Manifest Hash: ${computedManifest}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  const skillNames = args.skills.map((s) => s.name).join(", ");
  return [
    `Skill Manifest Attestation`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Skills: ${skillNames}`,
    `Count: ${args.skills.length}`,
    `Manifest Hash: ${computedManifest}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}

// -- AI-SKILL.2: Memory Context Binding --

interface MemoryContextArgs {
  memory_sources: Array<{ type: string; id?: string; hash?: string }>;
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

export async function handleAttestMemoryContext(
  args: MemoryContextArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const procedureId = "AI-SKILL.2";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;

  const allIdentified = args.memory_sources.length > 0 &&
    args.memory_sources.every((s) => s.id || s.hash);

  const factorA = args.memory_sources.length;
  const factorB = allIdentified ? 1 : 0;
  const factorC = 0;
  const verdict = allIdentified ? "PASS" : "FAIL";

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
    payload.ai_model_id = "memory-context";
    payload.ai_context = {
      provider: "memory",
      sources: args.memory_sources,
      total_sources: args.memory_sources.length,
    };
  } else if (clearingLevel === 2) {
    payload.ai_model_id = "memory-context";
  } else {
    payload.ai_model_id = sha256Truncated("memory-context");
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  if (config.demo) {
    const demoAnchor = `SWT3-DEMO-LOCAL-AI-${procedureId.replace(/[.-]/g, "")}-${verdict}-${epoch}-${fp}`;
    const sourceTypes = args.memory_sources.map((s) => s.type).join(", ");
    return [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `Memory Context Binding`,
      `Verdict: ${verdict}`,
      `Anchor: ${demoAnchor}`,
      `Sources: ${sourceTypes}`,
      `Count: ${args.memory_sources.length}`,
      `All Identified: ${allIdentified}`,
      `Clearing Level: ${clearingLevel}`,
      `Fingerprint: ${fp}`,
    ].join("\n");
  }

  const receipt = await client.postWitness(payload);
  if (receipt.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = receipt.tenant_id;

  const sourceTypes = args.memory_sources.map((s) => s.type).join(", ");
  return [
    `Memory Context Binding`,
    `Verdict: ${receipt.verdict}`,
    `Anchor: ${receipt.swt3_anchor}`,
    `Sources: ${sourceTypes}`,
    `Count: ${args.memory_sources.length}`,
    `All Identified: ${allIdentified}`,
    `Clearing Level: ${receipt.clearing_level}`,
    `Witnessed: ${receipt.witnessed_at}`,
    `Verify: ${config.endpoint}${receipt.verification_url}`,
    `Fingerprint: ${fp}`,
  ].join("\n");
}
