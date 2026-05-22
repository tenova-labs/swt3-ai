"""SWT3 AI Witness SDK -- LangChain Callback Handler.

Integrates with LangChain's callback system to transparently witness
every LLM call in a LangChain pipeline. Works with any LangChain LLM
or ChatModel (OpenAI, Anthropic, Ollama, HuggingFace, etc.).

Usage:

1. Global callback (witnesses all LLM calls):
    from swt3_ai.adapters.langchain import SWT3CallbackHandler
    from langchain_openai import ChatOpenAI

    handler = SWT3CallbackHandler(witness)
    llm = ChatOpenAI(model="gpt-4o", callbacks=[handler])
    response = llm.invoke("Hello")

2. Chain-level callback:
    from langchain_core.runnables import RunnableConfig
    chain = prompt | llm | parser
    chain.invoke({"input": "Hello"}, config=RunnableConfig(callbacks=[handler]))

3. Per-call callback:
    llm.invoke("Hello", config={"callbacks": [handler]})

No LangChain import required at module level -- duck-typed against
the BaseCallbackHandler interface.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional, Sequence, TYPE_CHECKING

from ..fingerprint import sha256_truncated
from ..types import InferenceRecord

if TYPE_CHECKING:
    from ..witness import Witness


class SWT3CallbackHandler:
    """LangChain callback handler that witnesses LLM calls.

    Implements the LangChain BaseCallbackHandler interface via duck typing
    (no langchain import required). Captures prompt, response, latency,
    and token usage from every LLM call for compliance anchoring.

    Thread-safe: each run_id gets its own state dict.
    """

    def __init__(self, witness: "Witness") -> None:
        self._witness = witness
        self._runs: Dict[str, Dict[str, Any]] = {}

    # -- LangChain callback interface properties --

    @property
    def raise_on_llm_error(self) -> bool:
        return False

    @property
    def ignore_llm(self) -> bool:
        return False

    @property
    def ignore_chain(self) -> bool:
        return True

    @property
    def ignore_agent(self) -> bool:
        return True

    @property
    def ignore_retriever(self) -> bool:
        return False

    # -- LLM lifecycle callbacks --

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM starts generating (non-chat models)."""
        rid = str(run_id or uuid.uuid4())
        prompt_text = "\n".join(prompts) if prompts else ""
        model_name = _extract_model_name(serialized, kwargs)

        self._runs[rid] = {
            "start": time.monotonic(),
            "prompt_hash": sha256_truncated(prompt_text),
            "system_prompt_hash": None,
            "model": model_name,
            "is_chat": False,
        }

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chat model starts generating."""
        rid = str(run_id or uuid.uuid4())
        model_name = _extract_model_name(serialized, kwargs)

        # Flatten all message lists into one prompt string for hashing
        prompt_text, system_text = _extract_chat_texts(messages)

        self._runs[rid] = {
            "start": time.monotonic(),
            "prompt_hash": sha256_truncated(prompt_text),
            "system_prompt_hash": sha256_truncated(system_text) if system_text else None,
            "model": model_name,
            "is_chat": True,
        }

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM finishes generating."""
        rid = str(run_id or uuid.uuid4())
        state = self._runs.pop(rid, None)
        if state is None:
            return

        elapsed_ms = int((time.monotonic() - state["start"]) * 1000)

        # Extract response text and token usage from LLMResult
        response_text, input_tokens, output_tokens = _extract_llm_result(response)
        response_hash = sha256_truncated(response_text)

        model_id = state["model"]
        model_hash = sha256_truncated(model_id)

        record = InferenceRecord(
            model_id=model_id,
            model_hash=model_hash,
            prompt_hash=state["prompt_hash"],
            response_hash=response_hash,
            latency_ms=elapsed_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            provider="langchain",
            system_prompt_hash=state["system_prompt_hash"],
        )

        self._witness.record(record)

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM errors. Clean up state."""
        rid = str(run_id or uuid.uuid4())
        self._runs.pop(rid, None)

    # -- Retriever lifecycle callbacks (auto-witness RAG context) --

    def on_retriever_start(
        self,
        serialized: Dict[str, Any],
        query: str,
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a retriever starts fetching documents."""
        rid = str(run_id or uuid.uuid4())
        self._runs[rid] = {
            "start": time.monotonic(),
            "query_hash": sha256_truncated(query),
            "is_retriever": True,
        }

    def on_retriever_end(
        self,
        documents: Sequence[Any],
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a retriever finishes. Witnesses the retrieved context."""
        rid = str(run_id or uuid.uuid4())
        state = self._runs.pop(rid, None)
        if state is None or not state.get("is_retriever"):
            return

        elapsed_ms = int((time.monotonic() - state["start"]) * 1000)

        from ..types import RagChunk

        chunks: List[RagChunk] = []
        for doc in documents:
            content = getattr(doc, "page_content", None) or str(doc)
            source_id = None
            score = None
            doc_meta = getattr(doc, "metadata", None)
            if isinstance(doc_meta, dict):
                source_id = doc_meta.get("source") or doc_meta.get("id")
                if source_id is not None:
                    source_id = str(source_id)
                score = doc_meta.get("score") or doc_meta.get("similarity_score")
                if score is not None:
                    try:
                        score = float(score)
                    except (ValueError, TypeError):
                        score = None
            chunks.append(RagChunk(
                content_hash=sha256_truncated(content),
                source_id=source_id,
                similarity_score=score,
            ))

        self._witness.witness_rag_context(
            chunks,
            retrieval_latency_ms=elapsed_ms,
        )

    def on_retriever_error(
        self,
        error: BaseException,
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a retriever errors. Clean up state."""
        rid = str(run_id or uuid.uuid4())
        self._runs.pop(rid, None)

    # -- No-op callbacks for interface completeness --

    def on_llm_new_token(self, token: str, **kwargs: Any) -> None:
        pass

    def on_chain_start(self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs: Any) -> None:
        pass

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        pass

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_text(self, text: str, **kwargs: Any) -> None:
        pass

    def on_retry(self, *args: Any, **kwargs: Any) -> None:
        pass


# -- Extraction helpers --

def _extract_model_name(serialized: Dict[str, Any], kwargs: Dict[str, Any]) -> str:
    """Extract model name from LangChain serialized dict or kwargs."""
    # Try invocation_params first (most reliable)
    invocation = kwargs.get("invocation_params", {})
    if isinstance(invocation, dict):
        model = invocation.get("model_name") or invocation.get("model") or ""
        if model:
            return str(model)

    # Try serialized kwargs
    ser_kwargs = serialized.get("kwargs", {})
    if isinstance(ser_kwargs, dict):
        model = ser_kwargs.get("model_name") or ser_kwargs.get("model") or ""
        if model:
            return str(model)

    # Try serialized id (e.g., ["langchain_openai", "ChatOpenAI"])
    ser_id = serialized.get("id", [])
    if isinstance(ser_id, list) and ser_id:
        return str(ser_id[-1])

    return "unknown"


def _extract_chat_texts(
    message_batches: List[List[Any]],
) -> tuple:
    """Extract (prompt_text, system_text) from LangChain chat message batches.

    LangChain passes messages as List[List[BaseMessage]] where each inner
    list is one batch. Messages have .type and .content attributes.
    """
    prompt_parts: list = []
    system_parts: list = []

    for batch in message_batches:
        if not isinstance(batch, (list, tuple)):
            continue
        for msg in batch:
            content = ""
            msg_type = ""

            if isinstance(msg, dict):
                content = msg.get("content", "")
                msg_type = msg.get("type", "") or msg.get("role", "")
            elif hasattr(msg, "content"):
                content = getattr(msg, "content", "") or ""
                msg_type = getattr(msg, "type", "") or ""

            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                text = " ".join(
                    p.get("text", "") if isinstance(p, dict) else str(p)
                    for p in content
                )
            else:
                text = str(content) if content else ""

            if msg_type == "system":
                system_parts.append(text)
            else:
                prompt_parts.append(text)

    prompt_text = "\n".join(prompt_parts)
    system_text = "\n".join(system_parts) if system_parts else None
    return prompt_text, system_text


def _extract_llm_result(response: Any) -> tuple:
    """Extract (text, input_tokens, output_tokens) from LangChain LLMResult.

    LLMResult has:
        .generations: List[List[Generation]]
        .llm_output: Optional[Dict] with token_usage
    """
    text = ""
    input_tokens = None
    output_tokens = None

    try:
        generations = getattr(response, "generations", [])
        if generations and isinstance(generations, (list, tuple)):
            first_batch = generations[0]
            if first_batch and isinstance(first_batch, (list, tuple)):
                gen = first_batch[0]
                # ChatGeneration has .message.content, Generation has .text
                message = getattr(gen, "message", None)
                if message:
                    text = getattr(message, "content", "") or ""
                else:
                    text = getattr(gen, "text", "") or ""
    except (IndexError, AttributeError):
        pass

    try:
        llm_output = getattr(response, "llm_output", None)
        if isinstance(llm_output, dict):
            usage = llm_output.get("token_usage", {})
            if isinstance(usage, dict):
                input_tokens = usage.get("prompt_tokens")
                output_tokens = usage.get("completion_tokens")
    except (AttributeError, TypeError):
        pass

    return text, input_tokens, output_tokens
