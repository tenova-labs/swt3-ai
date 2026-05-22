"""SWT3 AI Witness SDK -- vLLM Adapter.

vLLM's OpenAI-compatible serving (vllm serve) exposes the same API as
OpenAI at a custom base URL. This adapter wraps an OpenAI client pointed
at a vLLM server with transparent witnessing, tagging records with
provider="vllm" for accurate lineage.

Two usage patterns:

1. Explicit wrap:
    from openai import OpenAI
    from swt3_ai.adapters.vllm import wrap_vllm
    client = OpenAI(base_url="http://localhost:8000/v1", api_key="token")
    witnessed = wrap_vllm(client, witness)

2. Helper constructor:
    from swt3_ai.adapters.vllm import vllm_client
    client = vllm_client(witness, base_url="http://localhost:8000/v1")

Note: vLLM is NOT auto-detected by witness.wrap() because port 8000
is too generic. Use wrap_vllm() or vllm_client() explicitly.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .openai import _OpenAIProxy

if TYPE_CHECKING:
    from ..witness import Witness


DEFAULT_VLLM_BASE_URL = "http://localhost:8000/v1"


def wrap_vllm(client: Any, witness: "Witness") -> "_OpenAIProxy":
    """Wrap an OpenAI client (pointed at vLLM) with transparent witnessing.

    Identical to the OpenAI adapter but tags all InferenceRecords with
    provider="vllm" for accurate lineage tracking.
    """
    return _OpenAIProxy(client, witness, path="", provider="vllm")


def vllm_client(
    witness: "Witness",
    base_url: str = DEFAULT_VLLM_BASE_URL,
    api_key: str = "token",
    **kwargs: Any,
) -> "_OpenAIProxy":
    """Create a witnessed vLLM client in one call.

    Args:
        witness: Witness instance for anchoring.
        base_url: vLLM server URL (default: http://localhost:8000/v1).
        api_key: API key (vLLM default: "token").
        **kwargs: Additional kwargs passed to OpenAI().
    """
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError(
            "openai package required for vLLM adapter. "
            "Install: pip install swt3-ai[openai]"
        )

    client = OpenAI(base_url=base_url, api_key=api_key, **kwargs)
    return wrap_vllm(client, witness)
