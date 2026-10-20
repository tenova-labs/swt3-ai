"""SWT3 AI Witness SDK — Clearing Engine (Levels 0-3).

The Clearing Engine implements the "Sovereign Wire" protocol from
SWT3 Spec v1.2.0 Section 9. It controls what leaves the developer's
infrastructure when anchors are flushed to the witness endpoint.

CRITICAL DESIGN PRINCIPLE:
    Clearing operates on the WIRE PAYLOAD, not the developer's response.
    The developer always gets their full response object back untouched.
    We clear our internal copy before it hits the network.

Levels:
    0 — Analytics:   Everything retained in payload (prompt hash, response hash,
                     model ID, latency, tokens, ai_context with guardrails/provider).
    1 — Standard:    Hashes + factors + model_id + ai_context. No raw text ever
                     reaches the endpoint (hashes were derived from text that stays local).
    2 — Sensitive:   Hashes + factors + model_id only. ai_context stripped
                     (no provider name, no guardrail names, no system_fingerprint).
    3 — Classified:  Factors only. model_id hashed. No hashes, no metadata.
                     The endpoint sees numeric factors and nothing else.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .types import InferenceRecord, WitnessPayload
from .fingerprint import mint_fingerprint, sha256_truncated, timestamp_ms


# All SWT3 procedures recognized by the clearing engine.
# Kept in sync with uct-registry.json and procedures.py.
# INF-namespace (NIST 800-53) procedures are adjudicated server-side, not in the SDK.
AI_PROCEDURES = [
    # ── Core Inference ──
    "AI-INF.1",       # Inference Provenance
    "AI-INF.2",       # Inference Latency
    "AI-INF.3",       # Inference Volume
    # ── Model Governance ──
    "AI-MDL.1",       # Model Weight Integrity
    "AI-MDL.2",       # Model Version Tracking
    "AI-MDL.3",       # Model Provenance
    "AI-MDL.4",       # Feedback Loop Control
    "AI-MDL.5",       # Weight File Integrity
    "AI-MDL.6",       # Adapter Stack Attestation
    "AI-MDL.7",       # Quantization Attestation
    "AI-MDL.8",       # Model Registry Attestation
    # ── Guardrails ──
    "AI-GRD.1",       # Guardrail Enforcement
    "AI-GRD.2",       # Content Safety Filter
    "AI-GRD.3",       # Gatekeeper Gate
    # ── Security ──
    "AI-SEC.1",       # Adversarial Detection
    "AI-SEC.2",       # Input Validation
    # ── RAG ──
    "AI-RAG.1",       # Context Retrieval Provenance
    "AI-RAG.2",       # Context Relevance
    # ── Procedural Knowledge ──
    "AI-SKILL.1",     # Skill Manifest Attestation
    "AI-SKILL.2",     # Memory Context Binding
    "AI-SKILL.3",     # Reward Model Binding
    # ── Identity & Access ──
    "AI-ID.1",        # Agent Identity
    "AI-ACC.1",       # Resource Access Witnessing
    "AI-TOOL.1",      # Tool Call Witnessing
    "AI-TOOL.2",      # Tool Permission Attestation
    # ── Revocation ──
    "AI-REV.1",       # Anchor Revocation
    # ── Fairness ──
    "AI-FAIR.1",      # Bias Detection
    "AI-FAIR.2",      # Fairness Metrics
    "AI-FAIR.3",      # Demographic Parity
    # ── Data Governance ──
    "AI-DATA.1",      # Training Data Provenance
    "AI-DATA.2",      # Data Quality Attestation
    "AI-DATA.3",      # Data Lineage Tracking
    "AI-DATA.4",      # Data Retention Compliance
    "AI-DATA.5",      # Synthetic Data Provenance
    # ── Human Oversight ──
    "AI-HITL.1",      # Human Override Capability
    "AI-HITL.2",      # Human Review Trigger
    "AI-HITL.3",      # Overseer Identity Capture
    # ── Explainability ──
    "AI-EXPL.1",      # Explainability Report
    "AI-EXPL.2",      # Confidence Scoring
    # ── Chain / Multi-Agent ──
    "AI-CHAIN.1",     # Multi-Agent Chain Witnessing
    "AI-CHAIN.2",     # Chain Trust Degradation
    "AI-MULTI.1",     # Multi-Agent Delegation
    # ── Policy & Safety ──
    "AI-VIO.1",       # Policy Violation Recording
    "AI-CHR.1",       # Agent Charter Attestation
    "AI-SAFE.1",      # Safety Boundary Attestation
    "AI-SAFE.2",      # Agent Interrupt Witnessing
    # ── Hardware ──
    "AI-HW.1",        # Hardware Attestation
    "AI-HW.3",        # Key Attestation
    # ── Trust ──
    "AI-TRUST.1",     # Trust Credential Verification
    "AI-TRUST.2",     # Trust Credential Presentation
    "AI-TRUST.3",     # Trust Propagation Assertion
    # ── Environment ──
    "AI-ENV.1",       # Environment Attestation
    "AI-ENV.2",       # Runtime Isolation
    # ── Content & Provenance ──
    "AI-MARK.1",      # Content Provenance Marking
    "AI-BASE.1",      # Agent Behavioral Baseline
    "AI-LIC.1",       # License Provenance
    "AI-PROV.1",      # Model Provenance Chain
    # ── Compliance & Reporting ──
    "AI-SBOM.1",      # AI Bill of Materials
    "AI-REDTEAM.1",   # Adversarial Test Campaign
    "AI-CONSENT.1",   # Data Subject Consent
    "AI-DRIFT.1",     # Model Drift Detection
    "AI-DRIFT.2",     # Consequence-Mapped Drift
    "AI-AUDIT.1",     # Audit Log Integrity
    "AI-AUDIT.2",     # External Timestamp Attestation
    "AI-INCIDENT.1",  # Incident Reporting
    "AI-PERF.1",      # Performance Metrics
    "AI-ROBUST.1",    # Robustness Testing
    "AI-CYBER.1",     # Cybersecurity Attestation
    "AI-TRANS.1",     # Transparency Disclosure
    "AI-WATERMARK.1", # Watermark Verification
    "AI-DPIA.1",      # Data Protection Impact Assessment
    "AI-AUTO.1",      # Automated Decision Notification
    "AI-AUTO.2",      # Autonomous Generation Depth
    "AI-DUALUSE.1",   # Dual-Use Model Classification
    "AI-SUPPLY.1",    # Supply Chain Risk
    "AI-PMM.1",       # Post-Market Monitoring
    "AI-IMPACT.1",    # Fundamental Rights Impact Assessment
    "AI-LOG.1",       # Logging Completeness Attestation
    "AI-SAMPLE.1",    # Probabilistic Witnessing Summary
    "AI-DENSITY.1",   # Witnessing Density Attestation
    # ── Governance ──
    "AI-GOV.1",       # Governance Framework Attestation
    "AI-GOV.2",       # Governance Review Cadence
    "AI-GOV.3",       # Governance Escalation Path
    "AI-GOV.4",       # Governance Update Tracking
    "AI-GOV.5",       # Governance Accountability Assignment
    "AI-GOV.6",       # AI Risk Management Scope Definition
    "AI-GOV.7",       # AI Governance Resource Allocation
    "AI-RISK.1",      # AI Risk Identification and Categorization
    "AI-IR.1",        # AI Incident Response Capability
    # ── Meta-Governance ──
    "AI-METAGOV.1",   # Governance Infrastructure Attestation
    "AI-METAGOV.2",   # Governance Layer Registration
    "AI-METAGOV.3",   # Policy Downgrade Detection
    "AI-METAGOV.4",   # Circular Dependency Check
    "AI-METAGOV.5",   # Governance Authorization
    "AI-METAGOV.6",   # Emergency Override Attestation
    "AI-METAGOV.7",   # Governance Sync Verification
    "AI-METAGOV.8",   # Attestation Purity Verification
    # ── Engineering / Design ──
    "AI-ENG.1",       # Design Generation Provenance
    "AI-ENG.2",       # Simulation Validation
    "AI-ENG.3",       # Safety-Critical Review Gate
    "AI-ENG.4",       # Material Specification Compliance
    "AI-ENG.5",       # Design Revision Chain
    "AI-ENG.6",       # Fabrication Release Attestation
    # ── Agentic Infrastructure ──
    "AI-FIN.1",       # Agent Transaction Witnessing
    "AI-LCM.1",       # Agent Lifecycle Witnessing
    "AI-JUR.1",       # Cross-Border Inference Routing
    "AI-EMRG.1",      # Emergency Override Lifecycle
    "AI-ASSESS.1",    # Champion-Challenger Assessment
    "AI-COST.1",      # Resource Consumption Witnessing
    "AI-DEL.1",       # Delegation Tree Witnessing
    "AI-DEL.2",       # Delegation Boundary Attestation
    "AI-DEL.3",       # Delegation Chain Integrity
    # ── Lifecycle ──
    "AI-REACH.1",     # Hazard Reachability Attestation
    "AI-DECOM.1",     # Decommissioning Lifecycle Witness
    "AI-RECOMM.1",    # Re-commissioning Validation Witness
    "AI-FREEZE.1",    # Model Parameter Freeze Attestation
    # ── Mobile / Edge ──
    "AI-MOB.1",       # SIM-Bound Attestation
    "AI-MOB.2",       # Roaming Attestation
    "AI-MOB.3",       # Dual-SIM Policy Enforcement
    "AI-MOB.4",       # Peer-to-Peer Trust Mesh
    "AI-MOB.5",       # Bilateral Flush Correlation
    "AI-MOB.6",       # Trajectory Decision Attestation
    "AI-MOB.7",       # VLA Inference Witnessing
    "AI-MOB.8",       # Network Slice Isolation Verification
    # ── MCP ──
    "AI-MCP.1",       # MCP Security Posture Attestation
    "AI-MCP.2",       # Tool Integrity Attestation
    "AI-MCP.3",       # Server Authentication Attestation
    "AI-MCP.4",       # Server Discovery Attestation
    "AI-MCP.5",       # OAuth Token Binding
    "AI-MCP.6",       # MCP Elicitation Consent
    # ── Orchestration ──
    "AI-ORCH.1",      # Orchestration Topology Attestation
    "AI-ORCH.2",      # Agent Handoff Attestation
    "AI-CTX.1",       # Context Window Management Attestation
    "AI-SAND.1",      # Sandbox Enforcement Attestation
    "AI-SAND.2",      # Scope Boundary Attestation
    "AI-GATE.1",      # Eval Gate Decision Attestation
    # ── A2A Protocol ──
    "AI-A2A.1",       # Task Delegation Lifecycle
    "AI-A2A.2",       # Agent Card Discovery
    "AI-A2A.3",       # Context Chain Linking
    # ── Distillation / Containment ──
    "AI-DIST.1",      # Knowledge Distillation Provenance
    "AI-DIST.2",      # Distillation Lineage Attestation
    "AI-SHELL.1",     # Runtime Containment Attestation
    # ── Federated Learning ──
    "AI-FL.1",        # Federated Round Provenance
    "AI-FL.2",        # Federated Session Admission
    # ── Vertical: Non-Human Identity (NHI) ──
    "NHI-AGENT.1",    # Agent-to-Agent Credential Delegation
    "NHI-CYCLE.1",    # Credential Lifecycle Event Witnessing
    "NHI-PRIV.1",     # Privilege Change Witnessing
    "NHI-REVOKE.1",   # Credential Revocation Attestation
    "NHI-ROTATE.1",   # Credential Rotation Attestation
    "NHI-SCOPE.1",    # Credential Scope Attestation
    # ── Vertical: Hardware Bill of Materials (HBOM) ──
    "HBOM-INV.1",     # Hardware Inventory Attestation
    "HBOM-LIFE.1",    # Component Lifecycle Witnessing
    "HBOM-PUE.1",     # Power Usage Effectiveness Attestation
    "HBOM-SUPPLY.1",  # Hardware Supply Chain Provenance
    "HBOM-THERM.1",   # Thermal Profile Attestation
    "HBOM-WATER.1",   # Water Consumption Witnessing
    # ── Vertical: Digital Product Passport (DPP) ──
    "DPP-CHRG.1",     # Charge/Discharge Cycle Witnessing
    "DPP-DEGRAD.1",   # Battery Degradation Event Witnessing
    "DPP-EOL.1",      # End-of-Life / Recycling Handoff Witnessing
    "DPP-SOH.1",      # Battery State of Health Attestation
    # ── Vertical: Automated Demand Response (ADR) ──
    "ADR-BASE.1",     # Baseline Consumption Attestation
    "ADR-CARBON.1",   # Carbon Credit / REC Attestation
    "ADR-CURT.1",     # Curtailment Verification
    "ADR-EVENT.1",    # Demand Response Event Witnessing
    "ADR-GRID.1",     # Grid Signal Correlation Attestation
    "ADR-SETTLE.1",   # Settlement Data Attestation
    "ADR-VOLT.1",     # Autonomous Voltage Regulation Witnessing
    # ── Vertical: Financial Model Risk (FIN) ──
    "FIN-GOV.1",      # Model Governance Committee Approval
    "FIN-MON.1",      # Ongoing Performance Monitoring
    "FIN-MRM.1",      # Model Inventory and Lineage
    "FIN-OUT.1",      # Outcomes Analysis (Back-testing)
    "FIN-VAL.1",      # Independent Model Validation
    # ── Vertical: Construction (CON) ──
    "CON-ENV.1",      # Environmental Monitoring
    "CON-FIN.1",      # Payment Attestation
    "CON-INS.1",      # Inspection Attestation
    "CON-SAF.1",      # Safety Compliance
    "CON-STR.1",      # Structural Verification
    # ── Vertical: Healthcare / Clinical AI (HCF) ──
    "HCF-DX.1",       # Diagnostic Accountability
    "HCF-PRIV.1",     # PHI Access Audit
    "HCF-RX.1",       # Prescription Safety
]

# Revocation reason code mapping
REVOCATION_REASONS: Dict[str, int] = {
    "unspecified": 0,
    "model_recall": 1,
    "policy_violation": 2,
    "data_contamination": 3,
    "consent_withdrawal": 4,
    "regulatory_order": 5,
    "error_correction": 6,
}

# Procedures emitted per inference call (subset of the 17)
PER_INFERENCE_PROCEDURES = [
    "AI-INF.1",  # Provenance — always emitted
    "AI-INF.2",  # Latency — always emitted
    "AI-MDL.1",  # Model integrity — always emitted
    "AI-MDL.2",  # Model version — always emitted
    "AI-GRD.1",  # Guardrail enforcement — emitted when guardrails configured
]


def extract_payloads(
    record: InferenceRecord,
    tenant_id: str,
    clearing_level: int,
    latency_threshold_ms: int = 30000,
    guardrails_required: int = 0,
    procedures: Optional[List[str]] = None,
    agent_id: Optional[str] = None,
    signing_key: Optional[str] = None,
    signing_key_id: Optional[str] = None,
    signing_key_version: Optional[int] = None,
    signing_algorithm: Optional[str] = None,
    cycle_id: Optional[str] = None,
    policy_version_hash: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    legal_basis: Optional[str] = None,
    purpose_class: Optional[str] = None,
    authorization_id: Optional[str] = None,
    authorization_expires: Optional[int] = None,
    authorization_scope: Optional[str] = None,
    references: Optional[List[Dict[str, str]]] = None,
) -> List[WitnessPayload]:
    """Extract witness payloads from an inference record.

    Applies clearing level to each payload before returning.
    Returns one payload per witnessed procedure.
    """
    ts, epoch = timestamp_ms()
    payloads: List[WitnessPayload] = []

    # Build raw factors for each procedure, then clear based on level
    proc_factors: List[Dict[str, Any]] = []

    # Access control records produce only AI-ACC.1 (skip inference procedures)
    if record.access_target:
        proc_factors.append({
            "procedure_id": "AI-ACC.1",
            "factor_a": 1,
            "factor_b": 1 if not record.access_scope or record.access_granted else 0,
            "factor_c": 1 if record.access_granted else 0,
        })

        if procedures:
            proc_factors = [p for p in proc_factors if p["procedure_id"] in procedures]

        for pf in proc_factors:
            proc_id = pf["procedure_id"]
            fa, fb, fc = pf["factor_a"], pf["factor_b"], pf["factor_c"]
            fp = mint_fingerprint(tenant_id, proc_id, fa, fb, fc, ts)

            payload = WitnessPayload(
                procedure_id=proc_id,
                factor_a=fa,
                factor_b=fb,
                factor_c=fc,
                clearing_level=clearing_level,
                anchor_fingerprint=fp,
                anchor_epoch=epoch,
                fingerprint_timestamp_ms=ts,
            )

            if clearing_level <= 2:
                payload.ai_latency_ms = record.latency_ms
            if clearing_level <= 1:
                payload.ai_model_id = record.model_id
                payload.ai_context = {
                    "provider": "access",
                    "access_target": record.access_target,
                }
                if record.access_scope:
                    payload.ai_context["access_scope"] = record.access_scope
                payload.ai_context["access_granted"] = record.access_granted
                if cycle_id:
                    payload.ai_context["cycle_id"] = cycle_id

            _apply_operational_metadata(
                payload, agent_id=agent_id, cycle_id=cycle_id,
                signing_key=signing_key, signing_key_id=signing_key_id,
                signing_key_version=signing_key_version, signing_algorithm=signing_algorithm,
                policy_version_hash=policy_version_hash,
                jurisdiction=jurisdiction, legal_basis=legal_basis, purpose_class=purpose_class,
                authorization_id=authorization_id, references=references,
            )

            payloads.append(payload)

        return payloads

    # Tool call records produce only AI-TOOL.1 (skip inference procedures)
    if record.tool_name:
        proc_factors.append({
            "procedure_id": "AI-TOOL.1",
            "factor_a": 1,
            "factor_b": record.latency_ms,
            "factor_c": 0 if record.has_refusal else 1,  # 1=success, 0=exception
        })

        # Filter to requested procedures
        if procedures:
            proc_factors = [p for p in proc_factors if p["procedure_id"] in procedures]

        # Build tool payloads
        for pf in proc_factors:
            proc_id = pf["procedure_id"]
            fa, fb, fc = pf["factor_a"], pf["factor_b"], pf["factor_c"]
            fp = mint_fingerprint(tenant_id, proc_id, fa, fb, fc, ts)

            payload = WitnessPayload(
                procedure_id=proc_id,
                factor_a=fa,
                factor_b=fb,
                factor_c=fc,
                clearing_level=clearing_level,
                anchor_fingerprint=fp,
                anchor_epoch=epoch,
                fingerprint_timestamp_ms=ts,
            )

            # Tool clearing: include tool context at levels 0-1
            if clearing_level <= 2:
                payload.ai_latency_ms = record.latency_ms
            if clearing_level <= 1:
                payload.ai_model_id = record.model_id
                payload.ai_context = {
                    "provider": "tool",
                    "tool_name": record.tool_name,
                }
                if record.tool_call_id:
                    payload.ai_context["tool_call_id"] = record.tool_call_id
                if cycle_id:
                    payload.ai_context["cycle_id"] = cycle_id

            _apply_operational_metadata(
                payload, agent_id=agent_id, cycle_id=cycle_id,
                signing_key=signing_key, signing_key_id=signing_key_id,
                signing_key_version=signing_key_version, signing_algorithm=signing_algorithm,
                policy_version_hash=policy_version_hash,
                jurisdiction=jurisdiction, legal_basis=legal_basis, purpose_class=purpose_class,
                authorization_id=authorization_id, references=references,
            )

            payloads.append(payload)

        return payloads

    # AI-INF.1: Inference Provenance
    # factor_a = 1 (required), factor_b = 1 if hashes present, factor_c = 0
    proc_factors.append({
        "procedure_id": "AI-INF.1",
        "factor_a": 1,
        "factor_b": 1 if record.prompt_hash and record.response_hash else 0,
        "factor_c": 0,
    })

    # AI-INF.2: Inference Latency
    # factor_a = threshold_ms, factor_b = actual_ms, factor_c = 1 if anomaly
    proc_factors.append({
        "procedure_id": "AI-INF.2",
        "factor_a": latency_threshold_ms,
        "factor_b": record.latency_ms,
        "factor_c": 1 if record.latency_ms > latency_threshold_ms else 0,
    })

    # AI-MDL.1: Model Weight Integrity
    # factor_a = 1 (hash required), factor_b = 1 if model hash present
    proc_factors.append({
        "procedure_id": "AI-MDL.1",
        "factor_a": 1,
        "factor_b": 1 if record.model_hash else 0,
        "factor_c": 0,
    })

    # AI-MDL.2: Model Version Tracking
    # factor_a = 1 (required), factor_b = 1 if model_id recorded
    proc_factors.append({
        "procedure_id": "AI-MDL.2",
        "factor_a": 1,
        "factor_b": 1 if record.model_id else 0,
        "factor_c": 0,
    })

    # AI-GRD.1: Guardrail Enforcement (only if guardrails configured)
    # factor_a = required count, factor_b = active count, factor_c = pass/fail
    grd_required = guardrails_required or record.guardrails_required
    if grd_required > 0:
        proc_factors.append({
            "procedure_id": "AI-GRD.1",
            "factor_a": grd_required,
            "factor_b": record.guardrails_active,
            "factor_c": 1 if record.guardrail_passed else 0,
        })

    # AI-GRD.2: Content Safety Filter
    # factor_a = 1, factor_b = 1 if no refusal/violation, factor_c = has_refusal flag
    proc_factors.append({
        "procedure_id": "AI-GRD.2",
        "factor_a": 1,
        "factor_b": 0 if record.has_refusal else 1,
        "factor_c": 1 if record.has_refusal else 0,
    })

    # AI-ID.1: Agent Identity Attestation (only when agent_id is configured)
    if agent_id:
        proc_factors.append({
            "procedure_id": "AI-ID.1",
            "factor_a": 1,
            "factor_b": 1,
            "factor_c": 0,
        })

    # Filter to requested procedures
    if procedures:
        proc_factors = [p for p in proc_factors if p["procedure_id"] in procedures]

    # Build payloads with clearing applied
    for pf in proc_factors:
        proc_id = pf["procedure_id"]
        fa = pf["factor_a"]
        fb = pf["factor_b"]
        fc = pf["factor_c"]

        fp = mint_fingerprint(tenant_id, proc_id, fa, fb, fc, ts)

        payload = WitnessPayload(
            procedure_id=proc_id,
            factor_a=fa,
            factor_b=fb,
            factor_c=fc,
            clearing_level=clearing_level,
            anchor_fingerprint=fp,
            anchor_epoch=epoch,
            fingerprint_timestamp_ms=ts,
        )

        # Apply clearing level to determine what metadata travels on the wire
        _apply_clearing(payload, record, clearing_level)

        # Operational metadata survives all clearing levels
        _apply_operational_metadata(
            payload, agent_id=agent_id, cycle_id=cycle_id,
            signing_key=signing_key, signing_key_id=signing_key_id,
            signing_key_version=signing_key_version, signing_algorithm=signing_algorithm,
            policy_version_hash=policy_version_hash,
            jurisdiction=jurisdiction, legal_basis=legal_basis, purpose_class=purpose_class,
            authorization_id=authorization_id,
            authorization_expires=authorization_expires, authorization_scope=authorization_scope,
            references=references,
        )

        payloads.append(payload)

    return payloads


def normalize_references(
    refs: Optional[List[Any]],
) -> Optional[List[Dict[str, str]]]:
    """Normalize references input to structured dicts. Accepts strings or dicts."""
    if not refs:
        return None
    result = []
    for ref in refs:
        if isinstance(ref, str):
            result.append({"fingerprint": ref})
        elif isinstance(ref, dict):
            result.append(ref)
    return result if result else None


def _apply_operational_metadata(
    payload: WitnessPayload,
    *,
    agent_id: Optional[str] = None,
    cycle_id: Optional[str] = None,
    signing_key: Optional[str] = None,
    signing_key_id: Optional[str] = None,
    signing_key_version: Optional[int] = None,
    signing_algorithm: Optional[str] = None,
    policy_version_hash: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    legal_basis: Optional[str] = None,
    purpose_class: Optional[str] = None,
    authorization_id: Optional[str] = None,
    authorization_expires: Optional[int] = None,
    authorization_scope: Optional[str] = None,
    references: Optional[List[Dict[str, str]]] = None,
) -> None:
    """Apply operational metadata that survives all clearing levels."""
    if agent_id:
        payload.agent_id = agent_id
    if cycle_id:
        payload.cycle_id = cycle_id
    if policy_version_hash:
        payload.policy_version_hash = policy_version_hash
    if jurisdiction:
        payload.jurisdiction = jurisdiction
    if legal_basis:
        payload.legal_basis = legal_basis
    if purpose_class:
        payload.purpose_class = purpose_class
    if authorization_id:
        payload.authorization_id = authorization_id
    if authorization_expires is not None:
        payload.authorization_expires = authorization_expires
    if authorization_scope:
        payload.authorization_scope = authorization_scope
    if references:
        payload.references = references
    if signing_key:
        from .signing import sign_payload, DEFAULT_SIGNING_ALGORITHM
        algo = signing_algorithm or DEFAULT_SIGNING_ALGORITHM
        payload.payload_signature = sign_payload(
            signing_key, payload.anchor_fingerprint, agent_id, algorithm=algo,
        )
        payload.signing_algorithm = algo
        if signing_key_id:
            payload.signing_key_id = signing_key_id
        if signing_key_version is not None:
            payload.signing_key_version = signing_key_version


def _apply_clearing(
    payload: WitnessPayload,
    record: InferenceRecord,
    level: int,
) -> None:
    """Apply clearing level to a payload — controls what leaves the wire.

    Level 0 — Analytics:   All metadata included
    Level 1 — Standard:    Hashes + model_id + ai_context (no raw text — but raw text
                           was never in the payload; only hashes were derived locally)
    Level 2 — Sensitive:   Hashes + model_id only. ai_context stripped.
    Level 3 — Classified:  Factors only. model_id hashed. No hashes.
    """
    if level <= 2:
        # Levels 0-2: include hashes and model info
        payload.ai_prompt_hash = record.prompt_hash
        payload.ai_response_hash = record.response_hash
        payload.ai_latency_ms = record.latency_ms
        payload.ai_input_tokens = record.input_tokens
        payload.ai_output_tokens = record.output_tokens

    if level <= 1:
        # Levels 0-1: include full ai_context + system prompt hash
        payload.ai_model_id = record.model_id
        payload.ai_context = {
            "provider": record.provider,
        }
        if record.guardrail_names:
            payload.ai_context["guardrails"] = record.guardrail_names
        if record.system_fingerprint:
            payload.ai_context["system_fingerprint"] = record.system_fingerprint
        if payload.cycle_id:
            payload.ai_context["cycle_id"] = payload.cycle_id
        if record.system_prompt_hash:
            payload.ai_system_prompt_hash = record.system_prompt_hash
    elif level == 2:
        # Level 2: model_id in cleartext, but no ai_context
        payload.ai_model_id = record.model_id
        payload.ai_context = None
    else:
        # Level 3: model_id hashed, no hashes, no metadata
        payload.ai_model_id = sha256_truncated(record.model_id) if record.model_id else None
        payload.ai_prompt_hash = None
        payload.ai_response_hash = None
        payload.ai_latency_ms = None
        payload.ai_input_tokens = None
        payload.ai_output_tokens = None
        payload.ai_context = None


def extract_gatekeeper_payload(
    tenant_id: str,
    required: int,
    active: int,
    gate_passed: bool,
    clearing_level: int,
    agent_id: Optional[str] = None,
    signing_key: Optional[str] = None,
    signing_key_id: Optional[str] = None,
    signing_key_version: Optional[int] = None,
    signing_algorithm: Optional[str] = None,
    cycle_id: Optional[str] = None,
    policy_version_hash: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    legal_basis: Optional[str] = None,
    purpose_class: Optional[str] = None,
) -> WitnessPayload:
    """Mint an AI-GRD.3 (Gatekeeper Gate) payload.

    factor_a = required guardrail count
    factor_b = actual guardrail count at call time
    factor_c = 1 if gate passed, 0 if blocked
    Verdict: PASS if b >= a AND c == 1
    """
    ts, epoch = timestamp_ms()
    fa = float(required)
    fb = float(active)
    fc = 1.0 if gate_passed else 0.0
    fp = mint_fingerprint(tenant_id, "AI-GRD.3", fa, fb, fc, ts)

    payload = WitnessPayload(
        procedure_id="AI-GRD.3",
        factor_a=fa,
        factor_b=fb,
        factor_c=fc,
        clearing_level=clearing_level,
        anchor_fingerprint=fp,
        anchor_epoch=epoch,
        fingerprint_timestamp_ms=ts,
    )

    _apply_operational_metadata(
        payload, agent_id=agent_id, cycle_id=cycle_id,
        signing_key=signing_key, signing_key_id=signing_key_id,
        signing_key_version=signing_key_version, signing_algorithm=signing_algorithm,
        policy_version_hash=policy_version_hash,
        jurisdiction=jurisdiction, legal_basis=legal_basis, purpose_class=purpose_class,
    )

    return payload


def extract_revocation_payload(
    tenant_id: str,
    target_fingerprint: str,
    reason: str,
    clearing_level: int,
    agent_id: Optional[str] = None,
    signing_key: Optional[str] = None,
    signing_key_id: Optional[str] = None,
    signing_key_version: Optional[int] = None,
    signing_algorithm: Optional[str] = None,
    cycle_id: Optional[str] = None,
    policy_version_hash: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    legal_basis: Optional[str] = None,
    purpose_class: Optional[str] = None,
) -> WitnessPayload:
    """Mint an AI-REV.1 (Anchor Revocation) payload.

    factor_a = 1 (revocation event occurred)
    factor_b = 1 (target declared valid by caller)
    factor_c = reason code (integer from REVOCATION_REASONS)
    Verdict: always PASS (the revocation itself is valid evidence)

    The revocation_target and revocation_reason fields survive all
    clearing levels as operational metadata.
    """
    ts, epoch = timestamp_ms()
    reason_code = float(REVOCATION_REASONS.get(reason, 0))
    fa = 1.0
    fb = 1.0
    fc = reason_code
    fp = mint_fingerprint(tenant_id, "AI-REV.1", fa, fb, fc, ts)

    payload = WitnessPayload(
        procedure_id="AI-REV.1",
        factor_a=fa,
        factor_b=fb,
        factor_c=fc,
        clearing_level=clearing_level,
        anchor_fingerprint=fp,
        anchor_epoch=epoch,
        fingerprint_timestamp_ms=ts,
        revocation_target=target_fingerprint,
        revocation_reason=reason,
    )

    _apply_operational_metadata(
        payload, agent_id=agent_id, cycle_id=cycle_id,
        signing_key=signing_key, signing_key_id=signing_key_id,
        signing_key_version=signing_key_version, signing_algorithm=signing_algorithm,
        policy_version_hash=policy_version_hash,
        jurisdiction=jurisdiction, legal_basis=legal_basis, purpose_class=purpose_class,
    )

    return payload


def extract_chain_trust_degradation_payload(
    tenant_id: str,
    previous_trust_level: int,
    new_trust_level: int,
    clearing_level: int,
    agent_id: Optional[str] = None,
    signing_key: Optional[str] = None,
    signing_key_id: Optional[str] = None,
    signing_key_version: Optional[int] = None,
    signing_algorithm: Optional[str] = None,
    cycle_id: Optional[str] = None,
    policy_version_hash: Optional[str] = None,
) -> WitnessPayload:
    """Mint an AI-CHAIN.2 (Trust Degradation) payload.

    Minted automatically when the effective trust level drops during
    a multi-agent chain handoff. Provides auditors with a specific,
    searchable anchor for trust boundary crossings.

    factor_a = previous effective trust level
    factor_b = new effective trust level
    factor_c = delta (negative = degradation)
    """
    ts, epoch = timestamp_ms()
    fa = float(previous_trust_level)
    fb = float(new_trust_level)
    fc = float(new_trust_level - previous_trust_level)
    fp = mint_fingerprint(tenant_id, "AI-CHAIN.2", fa, fb, fc, ts)

    payload = WitnessPayload(
        procedure_id="AI-CHAIN.2",
        factor_a=fa,
        factor_b=fb,
        factor_c=fc,
        clearing_level=clearing_level,
        anchor_fingerprint=fp,
        anchor_epoch=epoch,
        fingerprint_timestamp_ms=ts,
    )

    _apply_operational_metadata(
        payload, agent_id=agent_id, cycle_id=cycle_id,
        signing_key=signing_key, signing_key_id=signing_key_id,
        signing_key_version=signing_key_version, signing_algorithm=signing_algorithm,
        policy_version_hash=policy_version_hash,
    )

    return payload
