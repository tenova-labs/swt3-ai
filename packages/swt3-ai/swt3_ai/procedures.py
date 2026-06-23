"""UCT procedure catalog for the SWT3 AI Witness Protocol.

Provides a static, offline-accessible catalog of all AI procedures.
No network calls required. Data sourced from the UCT Registry.
"""

import json
import sys
from typing import Optional, List, Dict

# 98 AI procedures across 51 namespaces
PROCEDURE_CATALOG: List[Dict[str, str]] = [
    {"id": "AI-INF.1", "name": "Inference Provenance", "namespace": "INF"},
    {"id": "AI-INF.2", "name": "Inference Latency", "namespace": "INF"},
    {"id": "AI-INF.3", "name": "Inference Volume", "namespace": "INF"},
    {"id": "AI-MDL.1", "name": "Model Weight Integrity", "namespace": "MDL"},
    {"id": "AI-MDL.2", "name": "Model Version Tracking", "namespace": "MDL"},
    {"id": "AI-MDL.3", "name": "Model Provenance", "namespace": "MDL"},
    {"id": "AI-MDL.5", "name": "Weight File Integrity", "namespace": "MDL"},
    {"id": "AI-MDL.6", "name": "Adapter Stack Attestation", "namespace": "MDL"},
    {"id": "AI-MDL.7", "name": "Quantization Attestation", "namespace": "MDL"},
    {"id": "AI-GRD.1", "name": "Guardrail Enforcement", "namespace": "GRD"},
    {"id": "AI-GRD.2", "name": "Content Safety Filter", "namespace": "GRD"},
    {"id": "AI-GRD.3", "name": "Gatekeeper Gate", "namespace": "GRD"},
    {"id": "AI-SEC.1", "name": "Adversarial Detection", "namespace": "SEC"},
    {"id": "AI-SEC.2", "name": "Input Validation", "namespace": "SEC"},
    {"id": "AI-RAG.1", "name": "Context Retrieval Provenance", "namespace": "RAG"},
    {"id": "AI-RAG.2", "name": "Context Relevance", "namespace": "RAG"},
    {"id": "AI-SKILL.1", "name": "Skill Manifest Attestation", "namespace": "SKILL"},
    {"id": "AI-SKILL.2", "name": "Memory Context Binding", "namespace": "SKILL"},
    {"id": "AI-SKILL.3", "name": "Reward Model Binding", "namespace": "SKILL"},
    {"id": "AI-TOOL.1", "name": "Tool Call Witnessing", "namespace": "TOOL"},
    {"id": "AI-ID.1", "name": "Agent Identity", "namespace": "ID"},
    {"id": "AI-ACC.1", "name": "Resource Access Witnessing", "namespace": "ACC"},
    {"id": "AI-REV.1", "name": "Anchor Revocation", "namespace": "REV"},
    {"id": "AI-FAIR.1", "name": "Bias Detection", "namespace": "FAIR"},
    {"id": "AI-FAIR.2", "name": "Fairness Metrics", "namespace": "FAIR"},
    {"id": "AI-FAIR.3", "name": "Demographic Parity", "namespace": "FAIR"},
    {"id": "AI-DATA.1", "name": "Training Data Provenance", "namespace": "DATA"},
    {"id": "AI-DATA.2", "name": "Data Quality Attestation", "namespace": "DATA"},
    {"id": "AI-DATA.3", "name": "Data Lineage Tracking", "namespace": "DATA"},
    {"id": "AI-DATA.4", "name": "Data Retention Compliance", "namespace": "DATA"},
    {"id": "AI-HITL.1", "name": "Human Override Capability", "namespace": "HITL"},
    {"id": "AI-HITL.2", "name": "Human Review Trigger", "namespace": "HITL"},
    {"id": "AI-EXPL.1", "name": "Explainability Report", "namespace": "EXPL"},
    {"id": "AI-EXPL.2", "name": "Confidence Scoring", "namespace": "EXPL"},
    {"id": "AI-CHAIN.1", "name": "Multi-Agent Chain Witnessing", "namespace": "CHAIN"},
    {"id": "AI-CHAIN.2", "name": "Chain Trust Degradation", "namespace": "CHAIN"},
    {"id": "AI-VIO.1", "name": "Policy Violation Recording", "namespace": "VIO"},
    {"id": "AI-CHR.1", "name": "Agent Charter Attestation", "namespace": "CHR"},
    {"id": "AI-SAFE.1", "name": "Safety Boundary Attestation", "namespace": "SAFE"},
    {"id": "AI-HW.1", "name": "Hardware Attestation", "namespace": "HW"},
    {"id": "AI-HW.3", "name": "Key Attestation", "namespace": "HW"},
    {"id": "AI-TRUST.1", "name": "Trust Credential Verification", "namespace": "TRUST"},
    {"id": "AI-TRUST.2", "name": "Trust Credential Presentation", "namespace": "TRUST"},
    {"id": "AI-ENV.1", "name": "Environment Attestation", "namespace": "ENV"},
    {"id": "AI-ENV.2", "name": "Runtime Isolation", "namespace": "ENV"},
    {"id": "AI-MARK.1", "name": "Content Provenance Marking", "namespace": "MARK"},
    {"id": "AI-BASE.1", "name": "Agent Behavioral Baseline", "namespace": "BASE"},
    {"id": "AI-LIC.1", "name": "License Provenance", "namespace": "LIC"},
    {"id": "AI-SBOM.1", "name": "AI Bill of Materials", "namespace": "SBOM"},
    {"id": "AI-REDTEAM.1", "name": "Adversarial Test Campaign", "namespace": "REDTEAM"},
    {"id": "AI-CONSENT.1", "name": "Data Subject Consent", "namespace": "CONSENT"},
    {"id": "AI-MULTI.1", "name": "Multi-Agent Delegation", "namespace": "MULTI"},
    {"id": "AI-DRIFT.1", "name": "Model Drift Detection", "namespace": "DRIFT"},
    {"id": "AI-AUDIT.1", "name": "Audit Log Integrity", "namespace": "AUDIT"},
    {"id": "AI-AUDIT.2", "name": "External Timestamp Attestation", "namespace": "AUDIT"},
    {"id": "AI-INCIDENT.1", "name": "Incident Reporting", "namespace": "INCIDENT"},
    {"id": "AI-PERF.1", "name": "Performance Metrics", "namespace": "PERF"},
    {"id": "AI-ROBUST.1", "name": "Robustness Testing", "namespace": "ROBUST"},
    {"id": "AI-CYBER.1", "name": "Cybersecurity Attestation", "namespace": "CYBER"},
    {"id": "AI-TRANS.1", "name": "Transparency Disclosure", "namespace": "TRANS"},
    {"id": "AI-WATERMARK.1", "name": "Watermark Verification", "namespace": "WATERMARK"},
    {"id": "AI-DPIA.1", "name": "Data Protection Impact Assessment", "namespace": "DPIA"},
    {"id": "AI-AUTO.1", "name": "Automated Decision Notification", "namespace": "AUTO"},
    {"id": "AI-AUTO.2", "name": "Autonomous Generation Depth", "namespace": "AUTO"},
    {"id": "AI-DUALUSE.1", "name": "Dual-Use Model Classification", "namespace": "DUALUSE"},
    {"id": "AI-SUPPLY.1", "name": "Supply Chain Risk", "namespace": "SUPPLY"},
    {"id": "AI-PMM.1", "name": "Post-Market Monitoring", "namespace": "PMM"},
    {"id": "AI-GOV.6", "name": "AI Risk Management Scope Definition", "namespace": "GOV"},
    {"id": "AI-RISK.1", "name": "AI Risk Identification and Categorization", "namespace": "RISK"},
    {"id": "AI-IR.1", "name": "AI Incident Response Capability", "namespace": "IR"},
    {"id": "AI-METAGOV.1", "name": "Governance Infrastructure Attestation", "namespace": "METAGOV"},
    {"id": "AI-METAGOV.2", "name": "Governance Layer Registration", "namespace": "METAGOV"},
    {"id": "AI-METAGOV.3", "name": "Policy Downgrade Detection", "namespace": "METAGOV"},
    {"id": "AI-METAGOV.4", "name": "Circular Dependency Check", "namespace": "METAGOV"},
    {"id": "AI-METAGOV.5", "name": "Governance Authorization", "namespace": "METAGOV"},
    {"id": "AI-METAGOV.6", "name": "Emergency Override Attestation", "namespace": "METAGOV"},
    {"id": "AI-METAGOV.7", "name": "Governance Sync Verification", "namespace": "METAGOV"},
    {"id": "AI-METAGOV.8", "name": "Attestation Purity Verification", "namespace": "METAGOV"},
    {"id": "AI-ENG.1", "name": "Design Generation Provenance", "namespace": "ENG"},
    {"id": "AI-ENG.2", "name": "Simulation Validation", "namespace": "ENG"},
    {"id": "AI-ENG.3", "name": "Safety-Critical Review Gate", "namespace": "ENG"},
    {"id": "AI-ENG.4", "name": "Material Specification Compliance", "namespace": "ENG"},
    {"id": "AI-ENG.5", "name": "Design Revision Chain", "namespace": "ENG"},
    {"id": "AI-ENG.6", "name": "Fabrication Release Attestation", "namespace": "ENG"},
    # Frontier (v0.5.7: agentic infrastructure)
    {"id": "AI-FIN.1", "name": "Agent Transaction Witnessing", "namespace": "FIN"},
    {"id": "AI-TOOL.2", "name": "Tool Permission Attestation", "namespace": "TOOL"},
    {"id": "AI-LCM.1", "name": "Agent Lifecycle Witnessing", "namespace": "LCM"},
    {"id": "AI-JUR.1", "name": "Cross-Border Inference Routing", "namespace": "JUR"},
    # Agent Lifecycle (PPA #23)
    {"id": "AI-COST.1", "name": "Resource Consumption Witnessing", "namespace": "COST"},
    {"id": "AI-DEL.1", "name": "Delegation Tree Witnessing", "namespace": "DEL"},
    {"id": "AI-CAP.1", "name": "Capability Attestation", "namespace": "CAP"},
    {"id": "AI-AUTO.3", "name": "Autonomy Level Transition", "namespace": "AUTO"},
    {"id": "AI-CLR.2", "name": "Clearing Fidelity Attestation", "namespace": "CLR"},
    # Healthcare / Clinical AI (HCF)
    {"id": "HCF-DX.1", "name": "Diagnostic Accountability", "namespace": "HCF"},
    {"id": "HCF-RX.1", "name": "Prescription Safety", "namespace": "HCF"},
    {"id": "HCF-PRIV.1", "name": "PHI Access Audit", "namespace": "HCF"},
]


def handle_procedures(
    *,
    namespace: Optional[str] = None,
    use_json: bool = False,
) -> None:
    """Print procedure catalog, optionally filtered by namespace."""
    filtered = PROCEDURE_CATALOG
    if namespace:
        ns = namespace.upper()
        filtered = [p for p in filtered if p["namespace"] == ns]

    if not filtered:
        print(f"No procedures found for namespace '{namespace}'.", file=sys.stderr)
        sys.exit(1)

    if use_json:
        print(json.dumps(filtered, indent=2))
        return

    namespaces = sorted(set(p["namespace"] for p in filtered))
    header = f"UCT Procedures: {len(filtered)} total, {len(namespaces)} namespaces"
    if namespace:
        header = f"UCT Procedures ({namespace.upper()}): {len(filtered)} found"

    print(f"\n{header}")
    print("-" * 50)
    for p in filtered:
        print(f"  {p['id']:<20s} {p['name']}")
    print()
