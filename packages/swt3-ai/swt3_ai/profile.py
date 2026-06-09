"""SWT3 AI Witness SDK -- Model Trust Profiles.

Portable, cryptographically signed summaries of a model's compliance posture.
Profiles bind a model artifact hash to its attestation coverage and can be
verified offline without network calls.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Dict, List, Optional, Sequence, Union

from .types import AnchorReference, CoverageResult, ModelTrustProfile, ProcedureAttestation

RECOMMENDED_PROCEDURES: Dict[str, List[str]] = {
    "minimal": ["AI-INF.1"],
    "standard": ["AI-INF.1", "AI-INF.2", "AI-MDL.1", "AI-MDL.2", "AI-GRD.1", "AI-GRD.2"],
    "eu-ai-act-high-risk": ["AI-INF.1", "AI-GRD.1", "AI-FAIR.1", "AI-EXPL.1", "AI-DATA.1", "AI-HITL.1"],
    "nist-ai-rmf": ["AI-INF.1", "AI-GRD.1", "AI-MDL.1"],
    "defense-govcon": ["AI-INF.1", "AI-GRD.1", "AI-MDL.1", "AI-ID.1", "AI-SEC.1"],
    "healthcare-clinical": ["AI-INF.1", "AI-GRD.1", "AI-FAIR.1", "AI-DATA.1", "AI-HITL.1", "AI-EXPL.1"],
    "fintech-model-risk": ["AI-INF.1", "AI-GRD.1", "AI-MDL.1", "AI-FAIR.1", "AI-EXPL.1"],
}


def build_profile_message(profile: ModelTrustProfile) -> str:
    """Build a canonical message string for profile signing.

    Format: PROFILE:{model_id}:{model_hash}:{generated_at}:{valid_until}:{sorted_procedures}:{score_3dp}
    """
    procs = ",".join(sorted(a.procedure for a in profile.coverage))
    score_3dp = f"{profile.coverage_score:.3f}"
    return f"PROFILE:{profile.model_id}:{profile.model_hash}:{profile.generated_at}:{profile.valid_until}:{procs}:{score_3dp}"


def sign_profile(profile: ModelTrustProfile, signing_key: str) -> str:
    """Sign a ModelTrustProfile with HMAC-SHA256."""
    message = build_profile_message(profile)
    return hmac.new(signing_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_profile_signature(profile: ModelTrustProfile, signing_key: str) -> bool:
    """Verify a profile signature against a known signing key. Constant-time comparison."""
    if not profile.signature:
        return False
    expected = sign_profile(profile, signing_key)
    return hmac.compare_digest(expected, profile.signature)


def is_profile_valid(profile: ModelTrustProfile, now_ms: Optional[int] = None) -> bool:
    """Check whether a profile is still within its validity window."""
    current = now_ms if now_ms is not None else int(time.time() * 1000)
    return current <= profile.valid_until


def generate_profile(
    *,
    model_id: str,
    model_hash: str,
    attestations: List[ProcedureAttestation],
    upstream_references: Optional[List[AnchorReference]] = None,
    ttl_ms: int = 86_400_000,
    signing_key: Optional[str] = None,
    signing_key_id: Optional[str] = None,
    now_ms: Optional[int] = None,
) -> ModelTrustProfile:
    """Generate a ModelTrustProfile from attestation data."""
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    passing = sum(1 for a in attestations if a.status == "pass")
    score = passing / len(attestations) if attestations else 0.0

    profile = ModelTrustProfile(
        model_id=model_id,
        model_hash=model_hash,
        coverage=list(attestations),
        coverage_score=score,
        upstream_references=list(upstream_references or []),
        generated_at=now,
        valid_until=now + ttl_ms,
        signing_key_id=signing_key_id,
    )

    if signing_key:
        profile.signature = sign_profile(profile, signing_key)

    return profile


def coverage_score(
    attested_procedures: Sequence[str],
    target: Optional[Union[str, List[str]]] = None,
) -> CoverageResult:
    """Calculate coverage against a target procedure set.

    Args:
        attested_procedures: Procedure IDs the model has passing attestations for.
        target: Profile name (key into RECOMMENDED_PROCEDURES) or custom list. Default: "standard".
    """
    if target is None:
        target_set = RECOMMENDED_PROCEDURES["standard"]
    elif isinstance(target, str):
        resolved = RECOMMENDED_PROCEDURES.get(target)
        if resolved is None:
            available = ", ".join(RECOMMENDED_PROCEDURES.keys())
            raise ValueError(f'Unknown profile: "{target}". Available: {available}')
        target_set = resolved
    else:
        target_set = list(target)

    attested_lookup = set(attested_procedures)
    target_lookup = set(target_set)
    covered = [p for p in target_set if p in attested_lookup]
    missing = [p for p in target_set if p not in attested_lookup]
    extra = [p for p in attested_procedures if p not in target_lookup]
    score = len(covered) / len(target_set) if target_set else 0.0

    return CoverageResult(
        score=score,
        covered=covered,
        missing=missing,
        extra=extra,
        target=list(target_set),
    )
