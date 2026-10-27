"""SWT3 AI Witness SDK -- DeepSeek Adapter.

Wraps an OpenAI client pointed at the DeepSeek API with transparent
witnessing, tagging records with provider="deepseek" for accurate lineage.

DeepSeek does not have its own Python SDK. Users construct an OpenAI
client with base_url="https://api.deepseek.com":

    from openai import OpenAI

    client = OpenAI(
        base_url="https://api.deepseek.com",
        api_key="sk-...",
    )

This adapter is auto-detected by witness.wrap() when the client's
base_url contains "deepseek.com".

DeepSeek R1 reasoning models return thinking tokens (<think>...</think>)
in the response content. These are hashed as part of the response -- the
adapter witnesses what was actually returned, including reasoning traces.

Deployers are responsible for assessing data residency and content policy
requirements when using the DeepSeek API.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .openai import _OpenAIProxy

if TYPE_CHECKING:
    from ..witness import Witness


DEFAULT_DEEPSEEK_BASE_URL = "https://api.deepseek.com"


def wrap_deepseek(client: Any, witness: "Witness") -> "_OpenAIProxy":
    """Wrap an OpenAI client (pointed at DeepSeek) with transparent witnessing.

    Identical to the OpenAI adapter but tags all InferenceRecords with
    provider="deepseek" for accurate lineage tracking.
    """
    return _OpenAIProxy(client, witness, path="", provider="deepseek")


def deepseek_client(
    witness: "Witness",
    api_key: str | None = None,
    base_url: str = DEFAULT_DEEPSEEK_BASE_URL,
    **kwargs: Any,
) -> "_OpenAIProxy":
    """Create a witnessed DeepSeek client in one call.

    Args:
        witness: Witness instance for anchoring.
        api_key: DeepSeek API key.
        base_url: DeepSeek API base URL (default: https://api.deepseek.com).
        **kwargs: Additional kwargs passed to OpenAI().

    Returns:
        Witnessed proxy that behaves like an OpenAI client.
    """
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError(
            "openai package required for DeepSeek adapter. "
            "Install: pip install swt3-ai[openai]"
        )

    client = OpenAI(base_url=base_url, api_key=api_key, **kwargs)
    return wrap_deepseek(client, witness)


def is_deepseek_client(client: Any) -> bool:
    """Check if an OpenAI client is pointed at the DeepSeek API."""
    base_url = _get_base_url(client)
    if not base_url:
        return False
    return "deepseek.com" in base_url


def _get_base_url(client: Any) -> str:
    """Extract base_url string from a client."""
    base_url = getattr(client, "base_url", None)
    if base_url is None:
        return ""
    return str(base_url)
