"""SWT3 AI Witness SDK — Fingerprint minting and SHA-256 utilities.

The fingerprint formula MUST match the ingestion endpoint's validation:
    SHA256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}").hex()[:12]
"""

from __future__ import annotations

import hashlib
import time
from typing import Tuple


def sha256_hex(data: str, length: int = 64) -> str:
    """SHA-256 hash a string, return first `length` hex characters."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:length]


def sha256_truncated(data: str, length: int = 16) -> str:
    """SHA-256 hash a string, return first 16 hex chars (prompt/response hashing)."""
    return sha256_hex(data, length)


def mint_fingerprint(
    tenant_id: str,
    procedure_id: str,
    factor_a: float,
    factor_b: float,
    factor_c: float,
    timestamp_ms: int,
) -> str:
    """Mint an SWT3 anchor fingerprint.

    This MUST match the endpoint's `validateFingerprint()`:
        SHA256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}").hex()[:12]
    """
    # Factors are transmitted as numbers — ensure consistent string representation
    # The endpoint receives JSON numbers, which JavaScript stringifies without trailing .0
    # Python must match: int-valued floats → "1", true floats → "1.5"
    def _num_str(v: float) -> str:
        if v == int(v):
            return str(int(v))
        return str(v)

    fp_input = (
        f"WITNESS:{tenant_id}:{procedure_id}"
        f":{_num_str(factor_a)}:{_num_str(factor_b)}:{_num_str(factor_c)}"
        f":{timestamp_ms}"
    )
    return hashlib.sha256(fp_input.encode("utf-8")).hexdigest()[:12]


def timestamp_ms() -> Tuple[int, int]:
    """Return (millisecond timestamp, epoch seconds) for anchor minting."""
    ts = int(time.time() * 1000)
    epoch = ts // 1000
    return ts, epoch
