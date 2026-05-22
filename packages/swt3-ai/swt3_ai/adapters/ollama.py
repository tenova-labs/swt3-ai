"""SWT3 AI Witness SDK -- Ollama Adapter.

Ollama exposes an OpenAI-compatible API at http://localhost:11434/v1.
This adapter wraps an OpenAI client pointed at Ollama with transparent
witnessing, tagging records with provider="ollama" for accurate lineage.

Three usage patterns:

1. Auto-detect (preferred):
    from openai import OpenAI
    client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    witnessed = witness.wrap(client)  # auto-detected by base_url

2. Explicit wrap:
    from swt3_ai.adapters.ollama import wrap_ollama
    witnessed = wrap_ollama(client, witness)

3. Helper constructor:
    from swt3_ai.adapters.ollama import ollama_client
    client = ollama_client(witness, host="http://localhost:11434")
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .openai import _OpenAIProxy

if TYPE_CHECKING:
    from ..witness import Witness


DEFAULT_OLLAMA_HOST = "http://localhost:11434"


def wrap_ollama(client: Any, witness: "Witness") -> "_OpenAIProxy":
    """Wrap an OpenAI client (pointed at Ollama) with transparent witnessing.

    Identical to the OpenAI adapter but tags all InferenceRecords with
    provider="ollama" for accurate lineage tracking.
    """
    return _OpenAIProxy(client, witness, path="", provider="ollama")


def ollama_client(
    witness: "Witness",
    host: str = DEFAULT_OLLAMA_HOST,
    **kwargs: Any,
) -> "_OpenAIProxy":
    """Create a witnessed Ollama client in one call.

    Args:
        witness: Witness instance for anchoring.
        host: Ollama server URL (default: http://localhost:11434).
        **kwargs: Additional kwargs passed to OpenAI().

    Returns:
        Witnessed proxy that behaves like an OpenAI client.
    """
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError(
            "openai package required for Ollama adapter. "
            "Install: pip install swt3-ai[openai]"
        )

    base_url = f"{host.rstrip('/')}/v1"
    client = OpenAI(base_url=base_url, api_key="ollama", **kwargs)
    return wrap_ollama(client, witness)


def is_ollama_client(client: Any) -> bool:
    """Check if an OpenAI client is pointed at an Ollama server."""
    base_url = _get_base_url(client)
    if not base_url:
        return False
    return ":11434" in base_url


def _get_base_url(client: Any) -> str:
    """Extract base_url string from an OpenAI client."""
    base_url = getattr(client, "base_url", None)
    if base_url is None:
        return ""
    return str(base_url)
