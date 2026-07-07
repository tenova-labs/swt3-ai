"""SWT3 Crosswalk Resolver -- offline regulatory mapping.

Maps SWT3 procedures to framework requirements using the bundled
crosswalks.json. Zero network calls, zero dependencies beyond stdlib.

    from swt3_ai import resolve
    resolve("AI-FAIR.1")
    # {"EU-AI-ACT": "Art.10", "NIST-AI-RMF": "MAP 2.1", ...}
"""

from __future__ import annotations

import json
import os
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_crosswalk_data: Optional[Dict[str, Any]] = None
_STALENESS_DAYS = 90


def _load() -> Dict[str, Any]:
    global _crosswalk_data
    if _crosswalk_data is not None:
        return _crosswalk_data

    path = os.path.join(os.path.dirname(__file__), "data", "crosswalks.json")
    with open(path, "r", encoding="utf-8") as f:
        _crosswalk_data = json.load(f)

    generated_at = _crosswalk_data.get("generated_at", "")
    if generated_at:
        try:
            gen_dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - gen_dt).days
            if age_days > _STALENESS_DAYS:
                warnings.warn(
                    f"Bundled crosswalks.json is {age_days} days old "
                    f"(generated {generated_at}). Update swt3-ai for "
                    f"current regulatory mappings.",
                    stacklevel=2,
                )
        except Exception:
            pass

    return _crosswalk_data


def resolve(procedure_id: str) -> Dict[str, str]:
    """Resolve a procedure to all framework controls it satisfies.

    Returns {framework_id: requirement_ref} or empty dict if unknown.
    """
    proc = _load().get("procedures", {}).get(procedure_id)
    if proc is None:
        return {}
    return dict(proc.get("frameworks", {}))


def resolve_framework(framework_id: str) -> Dict[str, List[str]]:
    """Resolve a framework to all its requirement-to-procedure mappings.

    Returns {requirement_ref: [procedure_ids]} or empty dict if unknown.
    """
    fw = _load().get("by_framework", {}).get(framework_id)
    if fw is None:
        return {}
    return {k: list(v) for k, v in fw.items()}


def frameworks() -> Dict[str, Dict[str, Any]]:
    """Return metadata for all known frameworks."""
    import copy
    return copy.deepcopy(_load().get("frameworks", {}))


def procedures() -> Dict[str, Dict[str, Any]]:
    """Return metadata for all known procedures."""
    import copy
    return copy.deepcopy(_load().get("procedures", {}))


def crosswalk_version() -> str:
    """Return the generated_at timestamp of the bundled crosswalks."""
    return _load().get("generated_at", "unknown")
