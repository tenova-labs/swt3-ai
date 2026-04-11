"""SWT3 AI Witness SDK - Payload Signing (HMAC-SHA256).

Signs anchor fingerprints to prove which SDK instance minted them.
The signature input is deterministic and must match across Python
and TypeScript for cross-language parity.
"""

from __future__ import annotations

import hashlib
import hmac


def sign_payload(
    signing_key: str,
    anchor_fingerprint: str,
    agent_id: str | None = None,
) -> str:
    """Sign an anchor fingerprint with HMAC-SHA256.

    Args:
        signing_key: Shared secret between SDK and server.
        anchor_fingerprint: The 12-char hex fingerprint to sign.
        agent_id: Optional agent identifier to bind to the signature.

    Returns:
        64-char hex HMAC-SHA256 digest.

    The message format is:
        "{fingerprint}:{agent_id}" if agent_id is provided
        "{fingerprint}"            if agent_id is None
    """
    message = f"{anchor_fingerprint}:{agent_id}" if agent_id else anchor_fingerprint
    return hmac.new(
        signing_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
