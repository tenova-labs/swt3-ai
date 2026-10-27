"""SWT3 AI Witness SDK -- Groq Adapter.

Wraps a Groq client with transparent witnessing. Groq exposes an
OpenAI-compatible API (chat.completions.create), so this adapter
delegates to the OpenAI proxy with provider="groq".

Usage:
    from swt3_ai.adapters.groq import wrap_groq

    witness = Witness(endpoint="...", api_key="...", tenant_id="...")
    client = Groq(api_key="...")
    witnessed = wrap_groq(client, witness)

    response = witnessed.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": "Hello"}],
    )

Also auto-detected by witness.wrap() when the client's module
contains "groq".

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .openai import _OpenAIProxy

if TYPE_CHECKING:
    from ..witness import Witness


def wrap_groq(client: Any, witness: "Witness") -> "_OpenAIProxy":
    """Wrap a Groq client with transparent witnessing.

    Identical to the OpenAI adapter but tags all InferenceRecords with
    provider="groq" for accurate lineage tracking.
    """
    return _OpenAIProxy(client, witness, path="", provider="groq")


def groq_client(
    witness: "Witness",
    api_key: str | None = None,
    **kwargs: Any,
) -> "_OpenAIProxy":
    """Create a witnessed Groq client in one call.

    Args:
        witness: Witness instance for anchoring.
        api_key: Groq API key (default: GROQ_API_KEY env var).
        **kwargs: Additional kwargs passed to Groq().

    Returns:
        Witnessed proxy that behaves like a Groq client.
    """
    try:
        from groq import Groq
    except ImportError:
        raise ImportError(
            "groq package required for Groq adapter. "
            "Install: pip install groq"
        )

    client = Groq(api_key=api_key, **kwargs)
    return wrap_groq(client, witness)


def is_groq_client(client: Any) -> bool:
    """Check if a client is a Groq SDK client (by module name)."""
    module = getattr(type(client), "__module__", "")
    return "groq" in module


def is_groq_url(client: Any) -> bool:
    """Check if an OpenAI client is pointed at Groq's API (by base_url)."""
    base_url = _get_base_url(client)
    return "groq.com" in base_url


def _get_base_url(client: Any) -> str:
    """Extract base_url string from a client."""
    base_url = getattr(client, "base_url", None)
    if base_url is None:
        return ""
    return str(base_url)
