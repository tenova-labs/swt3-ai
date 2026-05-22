"""SWT3 AI Witness SDK — Factor Handoff (Local File Export).

Writes factor data to local JSON files before the clearing engine strips
them from the wire payload. This is a custody transfer: once the file is
written, the SDK proceeds with clearing. If the write fails, clearing
does NOT proceed and the payload is NOT transmitted.

The handoff captures the FULL uncleared data (from the InferenceRecord)
combined with the sealed fingerprint (from the WitnessPayload), regardless
of the clearing level selected. This gives the factor holder everything
they need to independently re-verify any anchor.

Spec: SWT3 Factor Handoff Protocol v1.0.0
"""

from __future__ import annotations

import json
import logging
import os
import stat
from datetime import datetime, timezone
from typing import Any, Dict, List

from .types import InferenceRecord, WitnessPayload

logger = logging.getLogger("swt3_ai")

HANDOFF_VERSION = "1.0.0"


def write_handoff_files(
    payloads: List[WitnessPayload],
    inference: InferenceRecord,
    tenant_id: str,
    handoff_path: str,
) -> None:
    """Write one JSON file per payload to the handoff directory.

    Raises on failure — the caller must NOT proceed with clearing
    if this function throws.
    """
    os.makedirs(handoff_path, exist_ok=True)

    for payload in payloads:
        record = _build_handoff_record(payload, inference, tenant_id)
        filename = f"{payload.anchor_fingerprint}.json"
        filepath = os.path.join(handoff_path, filename)

        # Write atomically: write to temp, rename, set permissions
        tmp_path = filepath + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2, ensure_ascii=False)
                f.write("\n")

            # Set restrictive permissions (owner read/write only)
            os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)

            # Atomic rename
            os.replace(tmp_path, filepath)

            logger.debug(
                "Factor handoff: %s -> %s",
                payload.procedure_id, filepath,
            )
        except OSError:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise


def _build_handoff_record(
    payload: WitnessPayload,
    inference: InferenceRecord,
    tenant_id: str,
) -> Dict[str, Any]:
    """Build the full handoff record from the payload and inference data.

    This captures everything needed for independent re-verification,
    regardless of the clearing level selected.
    """
    return {
        "handoff_version": HANDOFF_VERSION,
        "handoff_type": f"clearing_level_{payload.clearing_level}",
        "tenant_id": tenant_id,
        "agent_id": payload.agent_id,
        "timestamp_iso": datetime.fromtimestamp(
            payload.anchor_epoch, tz=timezone.utc
        ).isoformat(),
        # Sealed anchor data
        "anchor_fingerprint": payload.anchor_fingerprint,
        "anchor_epoch": payload.anchor_epoch,
        "fingerprint_timestamp_ms": payload.fingerprint_timestamp_ms,
        "clearing_level": payload.clearing_level,
        # Factors (the proof)
        "factors": {
            "procedure_id": payload.procedure_id,
            "factor_a": payload.factor_a,
            "factor_b": payload.factor_b,
            "factor_c": payload.factor_c,
        },
        # Full metadata (uncleared, from the original inference)
        "metadata": {
            "ai_model_id": inference.model_id,
            "ai_model_hash": inference.model_hash,
            "ai_prompt_hash": inference.prompt_hash,
            "ai_response_hash": inference.response_hash,
            "ai_latency_ms": inference.latency_ms,
            "ai_input_tokens": inference.input_tokens,
            "ai_output_tokens": inference.output_tokens,
            "ai_provider": inference.provider,
            "ai_system_fingerprint": inference.system_fingerprint,
            "ai_guardrail_names": inference.guardrail_names or [],
            "ai_guardrails_active": inference.guardrails_active,
            "ai_guardrails_required": inference.guardrails_required,
            "ai_guardrail_passed": inference.guardrail_passed,
            "ai_tool_name": inference.tool_name,
            "ai_tool_call_id": inference.tool_call_id,
        },
    }
