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
    "AI-EXPL.2", # Confidence Scoring (when available)
]

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
) -> List[WitnessPayload]:
    """Extract witness payloads from an inference record.

    Applies clearing level to each payload before returning.
    Returns one payload per witnessed procedure.
    """
    ts, epoch = timestamp_ms()
    payloads: List[WitnessPayload] = []

    # Build raw factors for each procedure, then clear based on level
    proc_factors: List[Dict[str, Any]] = []

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

            # agent_id survives all clearing levels
            if agent_id:
                payload.agent_id = agent_id
            if signing_key:
                from .signing import sign_payload
                payload.payload_signature = sign_payload(signing_key, fp, agent_id)

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

        # agent_id survives all clearing levels (operational metadata)
        if agent_id:
            payload.agent_id = agent_id
        if signing_key:
            from .signing import sign_payload
            payload.payload_signature = sign_payload(signing_key, fp, agent_id)

        payloads.append(payload)

    return payloads


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
        # Levels 0-1: include full ai_context
        payload.ai_model_id = record.model_id
        payload.ai_context = {
            "provider": record.provider,
        }
        if record.guardrail_names:
            payload.ai_context["guardrails"] = record.guardrail_names
        if record.system_fingerprint:
            payload.ai_context["system_fingerprint"] = record.system_fingerprint
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
