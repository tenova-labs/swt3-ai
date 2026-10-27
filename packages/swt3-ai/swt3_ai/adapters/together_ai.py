"""SWT3 AI Witness SDK -- Together AI Adapter.

Wraps a Together AI client with transparent witnessing. Together exposes
an OpenAI-compatible API (chat.completions.create), so this adapter
delegates to the OpenAI proxy with provider="together".

Usage:
    from swt3_ai.adapters.together_ai import wrap_together

    witness = Witness(endpoint="...", api_key="...", tenant_id="...")
    client = Together(api_key="...")
    witnessed = wrap_together(client, witness)

    response = witnessed.chat.completions.create(
        model="meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        messages=[{"role": "user", "content": "Hello"}],
    )

Also auto-detected by witness.wrap() when the client's module
contains "together".

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .openai import _OpenAIProxy

if TYPE_CHECKING:
    from ..witness import Witness


def wrap_together(client: Any, witness: "Witness") -> "_OpenAIProxy":
    """Wrap a Together AI client with transparent witnessing.

    Identical to the OpenAI adapter but tags all InferenceRecords with
    provider="together" for accurate lineage tracking.
    """
    return _OpenAIProxy(client, witness, path="", provider="together")


def together_client(
    witness: "Witness",
    api_key: str | None = None,
    **kwargs: Any,
) -> "_OpenAIProxy":
    """Create a witnessed Together AI client in one call.

    Args:
        witness: Witness instance for anchoring.
        api_key: Together API key (default: TOGETHER_API_KEY env var).
        **kwargs: Additional kwargs passed to Together().

    Returns:
        Witnessed proxy that behaves like a Together client.
    """
    try:
        from together import Together
    except ImportError:
        raise ImportError(
            "together package required for Together AI adapter. "
            "Install: pip install together"
        )

    client = Together(api_key=api_key, **kwargs)
    return wrap_together(client, witness)


def is_together_client(client: Any) -> bool:
    """Check if a client is a Together SDK client (by module name)."""
    module = getattr(type(client), "__module__", "")
    return "together" in module


def is_together_url(client: Any) -> bool:
    """Check if an OpenAI client is pointed at Together's API (by base_url)."""
    base_url = _get_base_url(client)
    return "together.xyz" in base_url


def _get_base_url(client: Any) -> str:
    """Extract base_url string from a client."""
    base_url = getattr(client, "base_url", None)
    if base_url is None:
        return ""
    return str(base_url)
