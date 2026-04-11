"""SWT3 AI Witness SDK — Cryptographic attestation for AI inference.

Usage:
    from swt3_ai import Witness
    from openai import OpenAI

    witness = Witness(
        endpoint="https://sovereign.tenova.io",
        api_key="axm_live_...",
        tenant_id="YOUR_TENANT_ID",
    )

    client = witness.wrap(OpenAI())
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )

    # response is untouched — witnessing happens in the background
    print(response.choices[0].message.content)

    # Graceful shutdown (also happens automatically at exit)
    receipts = witness.flush()

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

__version__ = "0.2.6"

from .witness import Witness
from .types import WitnessConfig, WitnessReceipt, WitnessPayload
from .signing import sign_payload

__all__ = [
    "Witness",
    "WitnessConfig",
    "WitnessReceipt",
    "WitnessPayload",
    "sign_payload",
    "__version__",
]
