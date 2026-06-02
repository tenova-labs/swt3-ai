"""SWT3 AI Witness SDK - Payload Signing.

Supports HMAC-SHA256 (default) and ML-DSA-65 (FIPS 204, post-quantum).
The signature input is deterministic and must match across Python
and TypeScript for cross-language parity.

ML-DSA-65 requires: pip install cryptography>=43.0 (or pip install swt3-ai[pqc])
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional, Tuple


# ── Algorithm Constants ──────────────────────────────────────────────

SIGNING_ALGORITHM_HMAC = "hmac-sha256"
SIGNING_ALGORITHM_MLDSA = "ml-dsa-65"
VALID_SIGNING_ALGORITHMS = frozenset({SIGNING_ALGORITHM_HMAC, SIGNING_ALGORITHM_MLDSA})
DEFAULT_SIGNING_ALGORITHM = SIGNING_ALGORITHM_HMAC


def _build_message(anchor_fingerprint: str, agent_id: str | None = None) -> str:
    """Build the canonical signing message."""
    return f"{anchor_fingerprint}:{agent_id}" if agent_id else anchor_fingerprint


# ── HMAC-SHA256 ──────────────────────────────────────────────────────

def _sign_hmac(
    signing_key: str,
    message: str,
) -> str:
    """HMAC-SHA256 signature. Returns 64-char hex digest."""
    return hmac.new(
        signing_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ── ML-DSA-65 (FIPS 204) ────────────────────────────────────────────

def _get_mldsa():
    """Lazy import ML-DSA from cryptography>=43.0."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return mldsa
    except ImportError:
        raise ImportError(
            "ML-DSA-65 signing requires cryptography>=43.0. "
            "Install with: pip install 'cryptography>=43.0'  "
            "(or: pip install swt3-ai[pqc])"
        )


def generate_mldsa_keypair() -> Tuple[bytes, bytes]:
    """Generate an ML-DSA-65 key pair.

    Returns:
        (seed_bytes, public_key_bytes) -- seed is 32 bytes, public key is 1952 bytes.
    """
    mldsa = _get_mldsa()
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )
    private_key = mldsa.MLDSA65PrivateKey.generate()
    seed = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, public_bytes


def _sign_mldsa(
    seed_bytes: bytes,
    message: str,
) -> str:
    """ML-DSA-65 signature. Returns hex-encoded signature."""
    mldsa = _get_mldsa()
    private_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed_bytes)
    sig = private_key.sign(message.encode("utf-8"))
    return sig.hex()


def verify_mldsa(
    public_key_bytes: bytes,
    message: str,
    signature_hex: str,
) -> bool:
    """Verify an ML-DSA-65 signature.

    Args:
        public_key_bytes: Raw public key bytes (1952 bytes).
        message: The canonical message that was signed.
        signature_hex: Hex-encoded ML-DSA-65 signature.

    Returns:
        True if valid, False otherwise.
    """
    mldsa = _get_mldsa()
    public_key = mldsa.MLDSA65PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(bytes.fromhex(signature_hex), message.encode("utf-8"))
        return True
    except Exception:
        return False


# ── Public API ───────────────────────────────────────────────────────

def sign_payload(
    signing_key: str,
    anchor_fingerprint: str,
    agent_id: str | None = None,
    *,
    algorithm: str = DEFAULT_SIGNING_ALGORITHM,
) -> str:
    """Sign an anchor fingerprint.

    Args:
        signing_key: For hmac-sha256: shared secret string.
                     For ml-dsa-65: hex-encoded 32-byte seed.
        anchor_fingerprint: The 12-char hex fingerprint to sign.
        agent_id: Optional agent identifier to bind to the signature.
        algorithm: "hmac-sha256" (default) or "ml-dsa-65".

    Returns:
        Hex-encoded signature string.

    The message format is:
        "{fingerprint}:{agent_id}" if agent_id is provided
        "{fingerprint}"            if agent_id is None
    """
    if algorithm not in VALID_SIGNING_ALGORITHMS:
        raise ValueError(
            f"Unknown signing algorithm: '{algorithm}'. "
            f"Valid: {', '.join(sorted(VALID_SIGNING_ALGORITHMS))}"
        )

    message = _build_message(anchor_fingerprint, agent_id)

    if algorithm == SIGNING_ALGORITHM_HMAC:
        return _sign_hmac(signing_key, message)

    # ML-DSA-65: signing_key is hex-encoded 32-byte seed
    seed_bytes = bytes.fromhex(signing_key)
    return _sign_mldsa(seed_bytes, message)
