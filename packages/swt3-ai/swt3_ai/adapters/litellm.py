"""SWT3 AI Witness SDK -- LiteLLM Adapter.

Wraps litellm.completion() and litellm.acompletion() with transparent
witnessing. One adapter covers 100+ providers through LiteLLM's unified
interface.

Unlike the OpenAI/Anthropic adapters which proxy a client object, this
adapter wraps module-level functions. The developer gets back a namespace
object with .completion and .acompletion that behave identically to the
originals, plus passthrough for all other litellm attributes.

Usage:
    import litellm
    from swt3_ai import Witness

    witness = Witness(...)
    llm = witness.wrap(litellm)
    response = llm.completion(model="gpt-4o", messages=[...])

    # Or directly:
    from swt3_ai.adapters.litellm import wrap_litellm
    llm = wrap_litellm(litellm, witness)
    response = llm.completion(model="gpt-4o", messages=[...])
"""

from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

from ..fingerprint import sha256_truncated
from .openai import _extract_prompt_text, _extract_system_prompt, _extract_record

if TYPE_CHECKING:
    from ..witness import Witness


def wrap_litellm(litellm_module: Any, witness: "Witness") -> "_LiteLLMNamespace":
    """Wrap litellm with transparent witnessing.

    Returns a namespace object with witnessed .completion and .acompletion
    methods. All other litellm attributes pass through unchanged.
    """
    original_completion = getattr(litellm_module, "completion", None)
    original_acompletion = getattr(litellm_module, "acompletion", None)

    if original_completion is None:
        raise ImportError(
            "litellm.completion not found. Install litellm: pip install litellm"
        )

    def witnessed_completion(*args: Any, **kwargs: Any) -> Any:
        """Witnessed wrapper around litellm.completion()."""
        messages = kwargs.get("messages", args[1] if len(args) > 1 else [])
        model = kwargs.get("model", args[0] if args else "unknown")

        prompt_text = _extract_prompt_text(messages)
        prompt_hash = sha256_truncated(prompt_text)

        system_prompt = _extract_system_prompt(messages)
        system_prompt_hash = sha256_truncated(system_prompt) if system_prompt else None

        authorization_id = None
        if witness._strict:
            authorization_id = witness.gate_check(messages, model)

        start = time.monotonic()
        response = original_completion(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        record = _extract_record(response, model, prompt_hash, elapsed_ms, system_prompt_hash)
        record.provider = "litellm"
        witness.record(record, authorization_id=authorization_id)

        return response

    witnessed_completion.__name__ = "completion"
    witnessed_completion.__doc__ = getattr(original_completion, "__doc__", None)

    witnessed_acompletion = None
    if original_acompletion is not None:
        async def _witnessed_acompletion(*args: Any, **kwargs: Any) -> Any:
            """Witnessed wrapper around litellm.acompletion()."""
            messages = kwargs.get("messages", args[1] if len(args) > 1 else [])
            model = kwargs.get("model", args[0] if args else "unknown")

            prompt_text = _extract_prompt_text(messages)
            prompt_hash = sha256_truncated(prompt_text)

            system_prompt = _extract_system_prompt(messages)
            system_prompt_hash = sha256_truncated(system_prompt) if system_prompt else None

            authorization_id = None
            if witness._strict:
                authorization_id = witness.gate_check(messages, model)

            start = time.monotonic()
            response = await original_acompletion(*args, **kwargs)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            record = _extract_record(response, model, prompt_hash, elapsed_ms, system_prompt_hash)
            record.provider = "litellm"
            witness.record(record, authorization_id=authorization_id)

            return response

        _witnessed_acompletion.__name__ = "acompletion"
        _witnessed_acompletion.__doc__ = getattr(original_acompletion, "__doc__", None)
        witnessed_acompletion = _witnessed_acompletion

    return _LiteLLMNamespace(litellm_module, witnessed_completion, witnessed_acompletion)


class _LiteLLMNamespace:
    """Namespace that proxies litellm with witnessed completion methods.

    Behaves like the litellm module: all attributes pass through except
    .completion and .acompletion, which are witnessed.
    """

    def __init__(
        self,
        litellm_module: Any,
        completion: Any,
        acompletion: Any,
    ) -> None:
        object.__setattr__(self, "_module", litellm_module)
        object.__setattr__(self, "completion", completion)
        object.__setattr__(self, "acompletion", acompletion)

    def __getattr__(self, name: str) -> Any:
        module = object.__getattribute__(self, "_module")
        return getattr(module, name)

    def __repr__(self) -> str:
        return "<WitnessProxy(litellm)>"
