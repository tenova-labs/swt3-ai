"""SWT3 AI Witness SDK -- NVIDIA SkillSpector Integration.

Converts NVIDIA SkillSpector security scan results into SWT3
witness anchors. Bridges static agent security scanning with
cryptographic compliance evidence.

No runtime dependency on SkillSpector -- parses JSON output only.

Usage:
    import subprocess, json
    from swt3_ai.adapters.skillspector import witness_skill_scan

    result = json.loads(subprocess.check_output(["skillspector", "scan", "."]))
    witness_skill_scan(witness, result)

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ..fingerprint import sha256_truncated
from ..types import InferenceRecord

if TYPE_CHECKING:
    from ..witness import Witness

logger = logging.getLogger("swt3_ai.skillspector")


def witness_skill_scan(
    witness: "Witness",
    scan_result: Dict[str, Any],
    *,
    scan_target: Optional[str] = None,
) -> InferenceRecord:
    """Witness NVIDIA SkillSpector scan results.

    Mints an AI-SEC.1 anchor from SkillSpector's JSON output.
    No runtime dependency on SkillSpector -- parses output only.

    SkillSpector output format:
        {
          "risk_score": 72,
          "severity": "HIGH",
          "findings": [
            {"category": "prompt_injection", "severity": "CRITICAL", ...},
            {"category": "data_exfiltration", "severity": "HIGH", ...}
          ],
          "summary": {"total": 5, "critical": 1, "high": 2, "medium": 1, "low": 1}
        }

    Factor mapping (AI-SEC.1):
        factor_a -> total findings count
        factor_b -> critical findings count
        factor_c -> risk score (0-100)

    Args:
        witness: The Witness instance to record through.
        scan_result: Parsed JSON dict from SkillSpector scan output.
        scan_target: Optional identifier for what was scanned (e.g., agent
            name, path, or repository URL). Included in ai_context.

    Returns:
        The InferenceRecord that was submitted to the witness.

    Raises:
        ValueError: If scan_result is missing required fields.
    """
    # -- Validate input --
    if not isinstance(scan_result, dict):
        raise ValueError("scan_result must be a dict (parsed SkillSpector JSON)")

    risk_score = scan_result.get("risk_score")
    if risk_score is None:
        raise ValueError("scan_result missing 'risk_score' field")

    severity = scan_result.get("severity", "UNKNOWN")
    findings = scan_result.get("findings", [])
    summary = scan_result.get("summary", {})

    # -- Extract counts --
    total_findings = summary.get("total", len(findings))
    critical_count = summary.get("critical", 0)
    high_count = summary.get("high", 0)
    medium_count = summary.get("medium", 0)
    low_count = summary.get("low", 0)

    # If summary is missing but findings exist, count from findings list
    if not summary and findings:
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if _get_severity(f) == "CRITICAL")
        high_count = sum(1 for f in findings if _get_severity(f) == "HIGH")
        medium_count = sum(1 for f in findings if _get_severity(f) == "MEDIUM")
        low_count = sum(1 for f in findings if _get_severity(f) == "LOW")

    # -- Extract finding categories --
    categories: List[str] = []
    for finding in findings:
        cat = finding.get("category", "") if isinstance(finding, dict) else ""
        if cat and cat not in categories:
            categories.append(cat)

    # -- Build ai_context --
    ai_context: Dict[str, Any] = {
        "scanner": "skillspector",
        "severity": severity,
        "risk_score": risk_score,
        "total_findings": total_findings,
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
    }
    if categories:
        ai_context["categories"] = categories
    if scan_target:
        ai_context["scan_target"] = scan_target

    # -- Hash the scan result for integrity --
    # Deterministic hash of the scan output for traceability
    scan_hash = sha256_truncated(
        f"skillspector:{total_findings}:{critical_count}:{risk_score}:{severity}"
    )

    # -- Build InferenceRecord --
    # SkillSpector is not an inference call, so we map fields appropriately:
    #   model_id    -> "skillspector" (scanner identity)
    #   prompt_hash -> hash of scan target or empty
    #   response_hash -> hash of scan result for integrity
    #   latency_ms  -> 0 (not a real-time call)
    target_hash = sha256_truncated(scan_target) if scan_target else sha256_truncated("")

    record = InferenceRecord(
        model_id="skillspector",
        model_hash=sha256_truncated("skillspector"),
        prompt_hash=target_hash,
        response_hash=scan_hash,
        latency_ms=0,
        input_tokens=None,
        output_tokens=None,
        has_refusal=False,
        provider="nvidia-skillspector",
        system_prompt_hash=None,
    )

    # Mint AI-SEC.1 anchor with SkillSpector factors:
    #   factor_a = total findings count
    #   factor_b = critical findings count
    #   factor_c = risk score (0-100)
    payload = witness._mint_and_sign(
        "AI-SEC.1",
        float(total_findings),
        float(critical_count),
        float(risk_score),
    )
    if witness._config.clearing_level <= 1:
        payload.ai_model_id = "skillspector"
        payload.ai_context = ai_context
    witness._buffer.enqueue_many([payload])

    logger.info(
        "SWT3 witnessed SkillSpector scan: %d findings (%d critical), risk_score=%d%s",
        total_findings,
        critical_count,
        risk_score,
        f", target={scan_target}" if scan_target else "",
    )

    return record


def _get_severity(finding: Any) -> str:
    """Safely extract severity from a finding dict."""
    if isinstance(finding, dict):
        return str(finding.get("severity", "")).upper()
    return ""
