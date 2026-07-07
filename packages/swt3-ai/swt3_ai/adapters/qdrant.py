"""SWT3 AI Witness SDK -- Qdrant Vector Database Adapter.

Wraps the Qdrant Python client to witness vector search operations.
Mints AI-RAG.1 anchors for each retrieval, creating database-level
compliance evidence for RAG pipelines.

Usage:
    from swt3_ai.adapters.qdrant import wrap_qdrant

    witness = Witness(endpoint="...", api_key="...", tenant_id="...")
    client = QdrantClient(url="http://localhost:6333")
    witnessed = wrap_qdrant(client, witness)

    results = witnessed.search(collection_name="docs", query_vector=[...], limit=10)

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..witness import Witness


def wrap_qdrant(client: Any, witness: "Witness") -> "_QdrantProxy":
    """Wrap a QdrantClient with transparent RAG witnessing.

    Intercepts search() and query_points() to mint AI-RAG.1 anchors
    for every vector retrieval operation.

    Args:
        client: A qdrant_client.QdrantClient instance.
        witness: Witness instance for anchoring.

    Returns:
        Proxy that behaves like a QdrantClient but witnesses searches.
    """
    return _QdrantProxy(client, witness)


class _QdrantProxy:
    """Proxy for qdrant_client.QdrantClient.

    Intercepts search() and query_points() to mint AI-RAG.1 anchors.
    All other attributes and methods pass through untouched.
    """

    __slots__ = ("_target", "_witness")

    _INTERCEPTED: frozenset = frozenset({"search", "query_points"})

    def __init__(self, target: Any, witness: "Witness") -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_witness", witness)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        witness = object.__getattribute__(self, "_witness")
        real_attr = getattr(target, name)

        if name in self._INTERCEPTED and callable(real_attr):
            return _make_search_interceptor(real_attr, witness, name)

        return real_attr

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"<WitnessProxy({type(target).__name__})>"


def _make_search_interceptor(
    real_method: Any,
    witness: "Witness",
    method_name: str,
) -> Any:
    """Create an interceptor for search() or query_points()."""

    def interceptor(*args: Any, **kwargs: Any) -> Any:
        # -- Extract parameters before the call --
        collection_name = _extract_collection_name(args, kwargs, method_name)
        limit = kwargs.get("limit", kwargs.get("top", 10))
        score_threshold = kwargs.get("score_threshold")

        # -- Call the real method and measure latency --
        start = time.monotonic()
        result = real_method(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # -- Count results --
        result_count = _count_results(result)

        # -- Mint AI-RAG.1 via witness_rag_context --
        # fa = result count, fb = 1.0 (corpus identified), fc = 0.0 (reserved)
        ai_context: Dict[str, Any] = {
            "provider": "qdrant",
            "collection_name": collection_name,
            "top_k": limit,
            "method": method_name,
        }
        if score_threshold is not None:
            ai_context["score_threshold"] = score_threshold

        model_id = f"qdrant-{collection_name}" if collection_name else "qdrant-unknown"

        # Build chunk list from result IDs (hashed, not raw content)
        chunk_strings = _extract_chunk_ids(result, result_count)

        witness.witness_rag_context(
            chunk_strings if chunk_strings else ["search-result"] * result_count,
            corpus_id=collection_name,
            embedding_model=model_id,
            retrieval_latency_ms=elapsed_ms,
            top_k=limit if isinstance(limit, int) else None,
            similarity_threshold=score_threshold,
        )

        # -- Return UNTOUCHED result --
        return result

    interceptor.__name__ = method_name
    interceptor.__qualname__ = f"QdrantClient.{method_name}"
    interceptor.__doc__ = getattr(real_method, "__doc__", None)
    return interceptor


def _extract_collection_name(
    args: tuple,
    kwargs: Dict[str, Any],
    method_name: str,
) -> str:
    """Extract collection_name from search() or query_points() arguments.

    Both methods accept collection_name as the first positional arg or kwarg.
    """
    if "collection_name" in kwargs:
        return str(kwargs["collection_name"])
    if args:
        return str(args[0])
    return "unknown"


def _count_results(result: Any) -> int:
    """Count the number of results from a Qdrant response.

    Handles both:
        - search() -> list of ScoredPoint
        - query_points() -> QueryResponse with .points list
    """
    if isinstance(result, list):
        return len(result)
    # query_points returns a QueryResponse object with a .points attribute
    points = getattr(result, "points", None)
    if points is not None and isinstance(points, list):
        return len(points)
    return 0


def _extract_chunk_ids(result: Any, count: int) -> list:
    """Extract point IDs from Qdrant results for chunk identification.

    Returns a list of string representations of point IDs.
    """
    points: list = []
    if isinstance(result, list):
        points = result
    else:
        pts = getattr(result, "points", None)
        if pts is not None and isinstance(pts, list):
            points = pts

    ids: list = []
    for point in points:
        point_id = getattr(point, "id", None)
        if point_id is not None:
            ids.append(str(point_id))

    return ids if ids else []
