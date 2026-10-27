"""SWT3 AI Witness SDK -- Azure OpenAI Adapter.

Wraps an Azure OpenAI client with transparent witnessing, tagging records
with provider="azure-openai" for accurate lineage tracking.

Azure OpenAI uses the openai Python SDK with the AzureOpenAI class:

    from openai import AzureOpenAI

    client = AzureOpenAI(
        azure_endpoint="https://your-resource.openai.azure.com",
        api_key="...",
        api_version="2024-02-01",
    )

This adapter is auto-detected by witness.wrap() via class name
("AzureOpenAI" / "AsyncAzureOpenAI") or base_url containing
".openai.azure.com".

The model parameter in Azure OpenAI is the deployment name, not the
model family. The adapter records the deployment name as model_id,
which is correct -- the deployment name is the operationally significant
identifier (it maps 1:1 to a specific model version and configuration).

Azure content filter results (finish_reason="content_filter") are
detected and set has_refusal=True via the standard OpenAI extraction.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .openai import _OpenAIProxy

if TYPE_CHECKING:
    from ..witness import Witness


def wrap_azure_openai(client: Any, witness: "Witness") -> "_OpenAIProxy":
    """Wrap an Azure OpenAI client with transparent witnessing.

    Identical to the OpenAI adapter but tags all InferenceRecords with
    provider="azure-openai" for accurate lineage tracking.
    """
    return _OpenAIProxy(client, witness, path="", provider="azure-openai")


def azure_openai_client(
    witness: "Witness",
    azure_endpoint: str,
    api_key: str | None = None,
    api_version: str = "2024-02-01",
    **kwargs: Any,
) -> "_OpenAIProxy":
    """Create a witnessed Azure OpenAI client in one call.

    Args:
        witness: Witness instance for anchoring.
        azure_endpoint: Azure OpenAI resource URL.
        api_key: Azure OpenAI API key (or use Azure AD token).
        api_version: Azure API version string.
        **kwargs: Additional kwargs passed to AzureOpenAI().

    Returns:
        Witnessed proxy that behaves like an AzureOpenAI client.
    """
    try:
        from openai import AzureOpenAI
    except ImportError:
        raise ImportError(
            "openai package required for Azure OpenAI adapter. "
            "Install: pip install swt3-ai[openai]"
        )

    client = AzureOpenAI(
        azure_endpoint=azure_endpoint,
        api_key=api_key,
        api_version=api_version,
        **kwargs,
    )
    return wrap_azure_openai(client, witness)


def is_azure_openai_client(client: Any) -> bool:
    """Check if a client is an Azure OpenAI client.

    Detects via class name (AzureOpenAI / AsyncAzureOpenAI) or
    base_url containing ".openai.azure.com".
    """
    class_name = type(client).__name__
    if class_name in ("AzureOpenAI", "AsyncAzureOpenAI"):
        return True

    base_url = _get_base_url(client)
    if ".openai.azure.com" in base_url:
        return True

    return False


def _get_base_url(client: Any) -> str:
    """Extract base_url string from a client."""
    base_url = getattr(client, "base_url", None)
    if base_url is None:
        return ""
    return str(base_url)
