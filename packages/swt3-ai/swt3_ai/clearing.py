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


# All 17 AI procedures from the SWT3 AI Witnessing Profile
AI_PROCEDURES = [
    "AI-INF.1",  # Inference Provenance
    "AI-INF.2",  # Inference Latency
    "AI-INF.3",  # Inference Volume (not per-inference — tracked separately)
    "AI-MDL.1",  # Model Weight Integrity
    "AI-MDL.2",  # Model Version Tracking
    "AI-GRD.1",  # Guardrail Enforcement
    "AI-GRD.2",  # Content Safety Filter
    "AI-GRD.3",  # Gatekeeper Gate (pre-call enforcement)
    "AI-EXPL.2", # Confidence Scoring (when available)
    "AI-REV.1",  # Anchor Revocation
    "AI-SEC.1",  # Adversarial Detection
    "AI-SEC.2",  # Input Validation
    "AI-RAG.1",  # Context Retrieval Provenance
    "AI-RAG.2",  # Context Relevance
    "AI-MDL.5",  # Weight File Integrity
    "AI-MDL.6",  # Adapter Stack Attestation
    "AI-MDL.7",  # Quantization Attestation
    "AI-SKILL.1",  # Skill Manifest Attestation
    "AI-SKILL.2",  # Memory Context Binding
    "AI-SKILL.3",  # Reward Model Binding
    "AI-MARK.1",   # Content Provenance Marking
    "AI-BASE.1",   # Agent Behavioral Baseline
    "AI-LIC.1",    # License Provenance
    "AI-SBOM.1",      # AI Bill of Materials
    "AI-REDTEAM.1",   # Adversarial Test Campaign
    "AI-CONSENT.1",   # Data Subject Consent
    "AI-MULTI.1",     # Multi-Agent Delegation
    "AI-DRIFT.1",     # Model Drift Detection
    "AI-AUDIT.1",     # Audit Log Integrity
    "AI-INCIDENT.1",  # Incident Reporting
    "AI-PERF.1",      # Performance Metrics
    "AI-ROBUST.1",    # Robustness Testing
    "AI-CYBER.1",     # Cybersecurity Attestation
    "AI-TRANS.1",     # Transparency Disclosure
    "AI-WATERMARK.1", # Watermark Verification
    "AI-DPIA.1",      # Data Protection Impact Assessment
    "AI-AUTO.1",      # Automated Decision Notification
    "AI-AUTO.2",      # Autonomous Generation Depth
    "AI-AUDIT.2",     # External Timestamp Attestation
    "AI-DUALUSE.1",   # Dual-Use Model Classification
    "AI-SUPPLY.1",    # Supply Chain Risk
    "AI-PMM.1",       # Post-Market Monitoring
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
            authorization_id=authorization_id, references=references,
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
