/**
 * UCT procedure catalog for the SWT3 AI Witness Protocol.
 *
 * Provides a static, offline-accessible catalog of all AI procedures.
 * No network calls required. Data sourced from the UCT Registry.
 */

import { writeFileSync, existsSync } from "node:fs";

interface ProcedureEntry {
  id: string;
  name: string;
  namespace: string;
}

/** 173 AI/vertical procedures across 10 namespaces. Synced with uct-registry.json. */
export const PROCEDURE_CATALOG: ProcedureEntry[] = [
  { id: "AI-INF.1", name: "Inference Provenance", namespace: "INF" },
  { id: "AI-INF.2", name: "Inference Latency", namespace: "INF" },
  { id: "AI-INF.3", name: "Inference Volume", namespace: "INF" },
  { id: "AI-MDL.1", name: "Model Weight Integrity", namespace: "MDL" },
  { id: "AI-MDL.2", name: "Model Version Tracking", namespace: "MDL" },
  { id: "AI-MDL.3", name: "Model Provenance", namespace: "MDL" },
  { id: "AI-MDL.5", name: "Weight File Integrity", namespace: "MDL" },
  { id: "AI-MDL.6", name: "Adapter Stack Attestation", namespace: "MDL" },
  { id: "AI-MDL.7", name: "Quantization Attestation", namespace: "MDL" },
  { id: "AI-GRD.1", name: "Guardrail Enforcement", namespace: "GRD" },
  { id: "AI-GRD.2", name: "Content Safety Filter", namespace: "GRD" },
  { id: "AI-GRD.3", name: "Gatekeeper Gate", namespace: "GRD" },
  { id: "AI-SEC.1", name: "Adversarial Detection", namespace: "SEC" },
  { id: "AI-SEC.2", name: "Input Validation", namespace: "SEC" },
  { id: "AI-RAG.1", name: "Context Retrieval Provenance", namespace: "RAG" },
  { id: "AI-RAG.2", name: "Context Relevance", namespace: "RAG" },
  { id: "AI-SKILL.1", name: "Skill Manifest Attestation", namespace: "SKILL" },
  { id: "AI-SKILL.2", name: "Memory Context Binding", namespace: "SKILL" },
  { id: "AI-SKILL.3", name: "Reward Model Binding", namespace: "SKILL" },
  { id: "AI-TOOL.1", name: "Tool Call Witnessing", namespace: "TOOL" },
  { id: "AI-ID.1", name: "Agent Identity", namespace: "ID" },
  { id: "AI-ACC.1", name: "Resource Access Witnessing", namespace: "ACC" },
  { id: "AI-REV.1", name: "Anchor Revocation", namespace: "REV" },
  { id: "AI-FAIR.1", name: "Bias Detection", namespace: "FAIR" },
  { id: "AI-FAIR.2", name: "Fairness Metrics", namespace: "FAIR" },
  { id: "AI-FAIR.3", name: "Demographic Parity", namespace: "FAIR" },
  { id: "AI-DATA.1", name: "Training Data Provenance", namespace: "DATA" },
  { id: "AI-DATA.2", name: "Data Quality Attestation", namespace: "DATA" },
  { id: "AI-DATA.3", name: "Data Lineage Tracking", namespace: "DATA" },
  { id: "AI-DATA.4", name: "Data Retention Compliance", namespace: "DATA" },
  { id: "AI-DATA.5", name: "Synthetic Data Provenance", namespace: "DATA" },
  { id: "AI-HITL.1", name: "Human Override Capability", namespace: "HITL" },
  { id: "AI-HITL.2", name: "Human Review Trigger", namespace: "HITL" },
  { id: "AI-HITL.3", name: "Overseer Identity Capture", namespace: "HITL" },
  { id: "AI-EXPL.1", name: "Explainability Report", namespace: "EXPL" },
  { id: "AI-EXPL.2", name: "Confidence Scoring", namespace: "EXPL" },
  { id: "AI-CHAIN.1", name: "Multi-Agent Chain Witnessing", namespace: "CHAIN" },
  { id: "AI-CHAIN.2", name: "Chain Trust Degradation", namespace: "CHAIN" },
  { id: "AI-VIO.1", name: "Policy Violation Recording", namespace: "VIO" },
  { id: "AI-CHR.1", name: "Agent Charter Attestation", namespace: "CHR" },
  { id: "AI-SAFE.1", name: "Safety Boundary Attestation", namespace: "SAFE" },
  { id: "AI-SAFE.2", name: "Agent Interrupt Witnessing", namespace: "SAFE" },
  { id: "AI-HW.1", name: "Hardware Attestation", namespace: "HW" },
  { id: "AI-HW.3", name: "Key Attestation", namespace: "HW" },
  { id: "AI-TRUST.1", name: "Trust Credential Verification", namespace: "TRUST" },
  { id: "AI-TRUST.2", name: "Trust Credential Presentation", namespace: "TRUST" },
  { id: "AI-TRUST.3", name: "Trust Propagation Assertion", namespace: "TRUST" },
  { id: "AI-ENV.1", name: "Environment Attestation", namespace: "ENV" },
  { id: "AI-ENV.2", name: "Runtime Isolation", namespace: "ENV" },
  { id: "AI-MARK.1", name: "Content Provenance Marking", namespace: "MARK" },
  { id: "AI-BASE.1", name: "Agent Behavioral Baseline", namespace: "BASE" },
  { id: "AI-LIC.1", name: "License Provenance", namespace: "LIC" },
  { id: "AI-PROV.1", name: "Model Provenance Chain", namespace: "PROV" },
  { id: "AI-SBOM.1", name: "AI Bill of Materials", namespace: "SBOM" },
  { id: "AI-REDTEAM.1", name: "Adversarial Test Campaign", namespace: "REDTEAM" },
  { id: "AI-CONSENT.1", name: "Data Subject Consent", namespace: "CONSENT" },
  { id: "AI-MULTI.1", name: "Multi-Agent Delegation", namespace: "MULTI" },
  { id: "AI-DRIFT.1", name: "Model Drift Detection", namespace: "DRIFT" },
  { id: "AI-DRIFT.2", name: "Consequence-Mapped Drift", namespace: "DRIFT" },
  { id: "AI-AUDIT.1", name: "Audit Log Integrity", namespace: "AUDIT" },
  { id: "AI-AUDIT.2", name: "External Timestamp Attestation", namespace: "AUDIT" },
  { id: "AI-INCIDENT.1", name: "Incident Reporting", namespace: "INCIDENT" },
  { id: "AI-PERF.1", name: "Performance Metrics", namespace: "PERF" },
  { id: "AI-ROBUST.1", name: "Robustness Testing", namespace: "ROBUST" },
  { id: "AI-CYBER.1", name: "Cybersecurity Attestation", namespace: "CYBER" },
  { id: "AI-TRANS.1", name: "Transparency Disclosure", namespace: "TRANS" },
  { id: "AI-WATERMARK.1", name: "Watermark Verification", namespace: "WATERMARK" },
  { id: "AI-DPIA.1", name: "Data Protection Impact Assessment", namespace: "DPIA" },
  { id: "AI-AUTO.1", name: "Automated Decision Notification", namespace: "AUTO" },
  { id: "AI-AUTO.2", name: "Autonomous Generation Depth", namespace: "AUTO" },
  { id: "AI-DUALUSE.1", name: "Dual-Use Model Classification", namespace: "DUALUSE" },
  { id: "AI-SUPPLY.1", name: "Supply Chain Risk", namespace: "SUPPLY" },
  { id: "AI-PMM.1", name: "Post-Market Monitoring", namespace: "PMM" },
  { id: "AI-IMPACT.1", name: "Fundamental Rights Impact Assessment", namespace: "IMPACT" },
  { id: "AI-LOG.1", name: "Logging Completeness Attestation", namespace: "LOG" },
  { id: "AI-SAMPLE.1", name: "Probabilistic Witnessing Summary", namespace: "SAMPLE" },
  { id: "AI-DENSITY.1", name: "Witnessing Density Attestation", namespace: "DENSITY" },
  // Governance
  { id: "AI-GOV.1", name: "Governance Framework Attestation", namespace: "GOV" },
  { id: "AI-GOV.2", name: "Governance Review Cadence", namespace: "GOV" },
  { id: "AI-GOV.3", name: "Governance Escalation Path", namespace: "GOV" },
  { id: "AI-GOV.4", name: "Governance Update Tracking", namespace: "GOV" },
  { id: "AI-GOV.5", name: "Governance Accountability Assignment", namespace: "GOV" },
  { id: "AI-GOV.6", name: "AI Risk Management Scope Definition", namespace: "GOV" },
  { id: "AI-GOV.7", name: "AI Governance Resource Allocation", namespace: "GOV" },
  { id: "AI-RISK.1", name: "AI Risk Identification and Categorization", namespace: "RISK" },
  { id: "AI-IR.1", name: "AI Incident Response Capability", namespace: "IR" },
  // Meta-Governance
  { id: "AI-METAGOV.1", name: "Governance Infrastructure Attestation", namespace: "METAGOV" },
  { id: "AI-METAGOV.2", name: "Governance Layer Registration", namespace: "METAGOV" },
  { id: "AI-METAGOV.3", name: "Policy Downgrade Detection", namespace: "METAGOV" },
  { id: "AI-METAGOV.4", name: "Circular Dependency Check", namespace: "METAGOV" },
  { id: "AI-METAGOV.5", name: "Governance Authorization", namespace: "METAGOV" },
  { id: "AI-METAGOV.6", name: "Emergency Override Attestation", namespace: "METAGOV" },
  { id: "AI-METAGOV.7", name: "Governance Sync Verification", namespace: "METAGOV" },
  { id: "AI-METAGOV.8", name: "Attestation Purity Verification", namespace: "METAGOV" },
  // Engineering / Design
  { id: "AI-ENG.1", name: "Design Generation Provenance", namespace: "ENG" },
  { id: "AI-ENG.2", name: "Simulation Validation", namespace: "ENG" },
  { id: "AI-ENG.3", name: "Safety-Critical Review Gate", namespace: "ENG" },
  { id: "AI-ENG.4", name: "Material Specification Compliance", namespace: "ENG" },
  { id: "AI-ENG.5", name: "Design Revision Chain", namespace: "ENG" },
  { id: "AI-ENG.6", name: "Fabrication Release Attestation", namespace: "ENG" },
  // Agentic Infrastructure
  { id: "AI-FIN.1", name: "Agent Transaction Witnessing", namespace: "FIN" },
  { id: "AI-TOOL.2", name: "Tool Permission Attestation", namespace: "TOOL" },
  { id: "AI-LCM.1", name: "Agent Lifecycle Witnessing", namespace: "LCM" },
  { id: "AI-JUR.1", name: "Cross-Border Inference Routing", namespace: "JUR" },
  { id: "AI-EMRG.1", name: "Emergency Override Lifecycle", namespace: "EMRG" },
  { id: "AI-ASSESS.1", name: "Champion-Challenger Assessment", namespace: "ASSESS" },
  { id: "AI-COST.1", name: "Resource Consumption Witnessing", namespace: "COST" },
  { id: "AI-DEL.1", name: "Delegation Tree Witnessing", namespace: "DEL" },
  { id: "AI-DEL.2", name: "Delegation Boundary Attestation", namespace: "DEL" },
  { id: "AI-DEL.3", name: "Delegation Chain Integrity", namespace: "DEL" },
  // Lifecycle
  { id: "AI-REACH.1", name: "Hazard Reachability Attestation", namespace: "REACH" },
  { id: "AI-DECOM.1", name: "Decommissioning Lifecycle Witness", namespace: "DECOM" },
  { id: "AI-RECOMM.1", name: "Re-commissioning Validation Witness", namespace: "RECOMM" },
  { id: "AI-FREEZE.1", name: "Model Parameter Freeze Attestation", namespace: "FREEZE" },
  { id: "AI-MDL.4", name: "Feedback Loop Control", namespace: "MDL" },
  { id: "AI-MDL.8", name: "Model Registry Attestation", namespace: "MDL" },
  // Mobile / Edge
  { id: "AI-MOB.1", name: "SIM-Bound Attestation", namespace: "MOB" },
  { id: "AI-MOB.2", name: "Roaming Attestation", namespace: "MOB" },
  { id: "AI-MOB.3", name: "Dual-SIM Policy Enforcement", namespace: "MOB" },
  { id: "AI-MOB.4", name: "Peer-to-Peer Trust Mesh", namespace: "MOB" },
  { id: "AI-MOB.5", name: "Bilateral Flush Correlation", namespace: "MOB" },
  { id: "AI-MOB.6", name: "Trajectory Decision Attestation", namespace: "MOB" },
  { id: "AI-MOB.7", name: "VLA Inference Witnessing", namespace: "MOB" },
  { id: "AI-MOB.8", name: "Network Slice Isolation Verification", namespace: "MOB" },
  // MCP
  { id: "AI-MCP.1", name: "MCP Security Posture Attestation", namespace: "MCP" },
  { id: "AI-MCP.2", name: "Tool Integrity Attestation", namespace: "MCP" },
  { id: "AI-MCP.3", name: "Server Authentication Attestation", namespace: "MCP" },
  { id: "AI-MCP.4", name: "Server Discovery Attestation", namespace: "MCP" },
  { id: "AI-MCP.5", name: "OAuth Token Binding Attestation", namespace: "MCP" },
  { id: "AI-MCP.6", name: "MCP Elicitation Consent Witnessing", namespace: "MCP" },
  // Orchestration
  { id: "AI-ORCH.1", name: "Orchestration Topology Attestation", namespace: "ORCH" },
  { id: "AI-ORCH.2", name: "Agent Handoff Attestation", namespace: "ORCH" },
  { id: "AI-CTX.1", name: "Context Window Management Attestation", namespace: "CTX" },
  { id: "AI-SAND.1", name: "Sandbox Enforcement Attestation", namespace: "SAND" },
  { id: "AI-SAND.2", name: "Scope Boundary Attestation", namespace: "SAND" },
  { id: "AI-GATE.1", name: "Eval Gate Decision Attestation", namespace: "GATE" },
  // A2A Protocol
  { id: "AI-A2A.1", name: "Task Delegation Lifecycle Attestation", namespace: "A2A" },
  { id: "AI-A2A.2", name: "Agent Card Discovery Attestation", namespace: "A2A" },
  { id: "AI-A2A.3", name: "Context Chain Linking Attestation", namespace: "A2A" },
  // Distillation / Containment
  { id: "AI-DIST.1", name: "Knowledge Distillation Provenance", namespace: "DIST" },
  { id: "AI-DIST.2", name: "Distillation Lineage Attestation", namespace: "DIST" },
  { id: "AI-SHELL.1", name: "Runtime Containment Attestation", namespace: "SHELL" },
  // Federated Learning
  { id: "AI-FL.1", name: "Federated Round Provenance", namespace: "FL" },
  { id: "AI-FL.2", name: "Federated Session Admission", namespace: "FL" },
  // Vertical: Non-Human Identity (NHI)
  { id: "NHI-AGENT.1", name: "Agent-to-Agent Credential Delegation", namespace: "NHI" },
  { id: "NHI-CYCLE.1", name: "Credential Lifecycle Event Witnessing", namespace: "NHI" },
  { id: "NHI-PRIV.1", name: "Privilege Change Witnessing", namespace: "NHI" },
  { id: "NHI-REVOKE.1", name: "Credential Revocation Attestation", namespace: "NHI" },
  { id: "NHI-ROTATE.1", name: "Credential Rotation Attestation", namespace: "NHI" },
  { id: "NHI-SCOPE.1", name: "Credential Scope Attestation", namespace: "NHI" },
  // Vertical: Hardware Bill of Materials (HBOM)
  { id: "HBOM-INV.1", name: "Hardware Inventory Attestation", namespace: "HBOM" },
  { id: "HBOM-LIFE.1", name: "Component Lifecycle Witnessing", namespace: "HBOM" },
  { id: "HBOM-PUE.1", name: "Power Usage Effectiveness Attestation", namespace: "HBOM" },
  { id: "HBOM-SUPPLY.1", name: "Hardware Supply Chain Provenance", namespace: "HBOM" },
  { id: "HBOM-THERM.1", name: "Thermal Profile Attestation", namespace: "HBOM" },
  { id: "HBOM-WATER.1", name: "Water Consumption Witnessing", namespace: "HBOM" },
  // Vertical: Digital Product Passport (DPP)
  { id: "DPP-CHRG.1", name: "Charge/Discharge Cycle Witnessing", namespace: "DPP" },
  { id: "DPP-DEGRAD.1", name: "Battery Degradation Event Witnessing", namespace: "DPP" },
  { id: "DPP-EOL.1", name: "End-of-Life / Recycling Handoff Witnessing", namespace: "DPP" },
  { id: "DPP-SOH.1", name: "Battery State of Health Attestation", namespace: "DPP" },
  // Vertical: Automated Demand Response (ADR)
  { id: "ADR-BASE.1", name: "Baseline Consumption Attestation", namespace: "ADR" },
  { id: "ADR-CARBON.1", name: "Carbon Credit / REC Attestation", namespace: "ADR" },
  { id: "ADR-CURT.1", name: "Curtailment Verification", namespace: "ADR" },
  { id: "ADR-EVENT.1", name: "Demand Response Event Witnessing", namespace: "ADR" },
  { id: "ADR-GRID.1", name: "Grid Signal Correlation Attestation", namespace: "ADR" },
  { id: "ADR-SETTLE.1", name: "Settlement Data Attestation", namespace: "ADR" },
  { id: "ADR-VOLT.1", name: "Autonomous Voltage Regulation Witnessing", namespace: "ADR" },
  // Vertical: Financial Model Risk (FIN)
  { id: "FIN-GOV.1", name: "Model Governance Committee Approval", namespace: "FIN" },
  { id: "FIN-MON.1", name: "Ongoing Performance Monitoring", namespace: "FIN" },
  { id: "FIN-MRM.1", name: "Model Inventory and Lineage", namespace: "FIN" },
  { id: "FIN-OUT.1", name: "Outcomes Analysis (Back-testing)", namespace: "FIN" },
  { id: "FIN-VAL.1", name: "Independent Model Validation", namespace: "FIN" },
  // Vertical: Construction (CON)
  { id: "CON-ENV.1", name: "Environmental Monitoring", namespace: "CON" },
  { id: "CON-FIN.1", name: "Payment Attestation", namespace: "CON" },
  { id: "CON-INS.1", name: "Inspection Attestation", namespace: "CON" },
  { id: "CON-SAF.1", name: "Safety Compliance", namespace: "CON" },
  { id: "CON-STR.1", name: "Structural Verification", namespace: "CON" },
  // Vertical: Healthcare / Clinical AI (HCF)
  { id: "HCF-DX.1", name: "Diagnostic Accountability", namespace: "HCF" },
  { id: "HCF-PRIV.1", name: "PHI Access Audit", namespace: "HCF" },
  { id: "HCF-RX.1", name: "Prescription Safety", namespace: "HCF" },
];

export function handleProcedures(opts: { namespace?: string; json?: boolean }): void {
  let filtered = PROCEDURE_CATALOG;
  if (opts.namespace) {
    const ns = opts.namespace.toUpperCase();
    filtered = filtered.filter((p) => p.namespace === ns);
  }

  if (filtered.length === 0) {
    console.error(`No procedures found for namespace '${opts.namespace}'.`);
    process.exit(1);
  }

  if (opts.json) {
    console.log(JSON.stringify(filtered, null, 2));
    return;
  }

  const namespaces = new Set(filtered.map((p) => p.namespace));
  const header = opts.namespace
    ? `UCT Procedures (${opts.namespace.toUpperCase()}): ${filtered.length} found`
    : `UCT Procedures: ${filtered.length} total, ${namespaces.size} namespaces`;

  console.log(`\n${header}`);
  console.log("-".repeat(50));
  for (const p of filtered) {
    console.log(`  ${p.id.padEnd(20)} ${p.name}`);
  }
  console.log();
}

const QUICKSTART_TS = `/**
 * SWT3 AI Witness quickstart -- generated by \`swt3 quickstart\`.
 */

import { Witness } from "@tenova/swt3-ai";

const witness = new Witness({
  tenantId: "QUICKSTART_TENANT",
  clearingLevel: 1,
});

const response = witness.wrap({
  prompt: "What are the three laws of robotics?",
  response: "1. A robot may not injure a human being...",
  modelId: "quickstart-model",
  provider: "local",
});

console.log(\`Response: \${response.response.slice(0, 60)}...\`);
console.log(\`Anchors minted: \${witness.pending.length}\`);

const results = witness.flush();
for (const r of results) {
  console.log(\`  \${r.procedure_id}: \${r.anchor_fingerprint}\`);
}

console.log("\\nDone. See https://sovereign.tenova.io/docs/ for full documentation.");
`;

export function handleQuickstart(): void {
  const out = "swt3_quickstart.ts";
  if (existsSync(out)) {
    console.error(`  ${out} already exists. Remove it first.`);
    process.exit(1);
  }
  writeFileSync(out, QUICKSTART_TS, "utf-8");
  console.log(`\n  Created: ${out}`);
  console.log(`  Run it:  npx tsx ${out}\n`);
}
