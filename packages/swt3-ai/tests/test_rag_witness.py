"""RAG context witnessing tests.

Tests for witness_rag_context() -- AI-RAG.1 (Context Retrieval Provenance)
and AI-RAG.2 (Context Relevance).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from swt3_ai import Witness, RagChunk
from swt3_ai.types import WitnessPayload


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_witness(clearing_level=1):
    """Create a Witness with mocked buffer (no network)."""
    w = Witness(
        endpoint="https://test.tenova.io",
        api_key="axm_test_key",
        tenant_id="TEST_TENANT",
        clearing_level=clearing_level,
    )
    w._buffer = MagicMock()
    w._buffer.enqueue_many = MagicMock()
    return w


# ---------------------------------------------------------------------------
# AI-RAG.1: Context Retrieval Provenance
# ---------------------------------------------------------------------------

class TestRagContextStrings:
    """Test witness_rag_context() with raw string chunks (auto-hashing)."""

    def test_basic_string_chunks(self):
        w = _make_witness()
        payloads = w.witness_rag_context(
            ["chunk one", "chunk two", "chunk three"],
            corpus_id="legal-docs-v3",
        )

        assert len(payloads) == 1
        p = payloads[0]
        assert p.procedure_id == "AI-RAG.1"
        assert p.factor_a == 3.0  # 3 chunks
        assert p.factor_b == 1.0  # corpus identified
        assert p.factor_c == 0.0  # reserved
        assert p.anchor_fingerprint  # non-empty
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "rag"
        assert p.ai_context["chunk_count"] == 3
        assert len(p.ai_context["chunk_hashes"]) == 3
        assert p.ai_context["corpus_id"] == "legal-docs-v3"
        w._buffer.enqueue_many.assert_called_once()

    def test_anonymous_retrieval(self):
        w = _make_witness()
        payloads = w.witness_rag_context(["chunk"])

        p = payloads[0]
        assert p.factor_b == 0.0  # no corpus
        assert "corpus_id" not in (p.ai_context or {})

    def test_auto_hash_determinism(self):
        w = _make_witness()
        p1 = w.witness_rag_context(["same text"])[0]
        p2 = w.witness_rag_context(["same text"])[0]

        # Same text should produce same chunk hash
        assert p1.ai_context["chunk_hashes"][0] == p2.ai_context["chunk_hashes"][0]

    def test_different_text_different_hash(self):
        w = _make_witness()
        p1 = w.witness_rag_context(["text A"])[0]
        p2 = w.witness_rag_context(["text B"])[0]

        assert p1.ai_context["chunk_hashes"][0] != p2.ai_context["chunk_hashes"][0]


class TestRagContextChunks:
    """Test witness_rag_context() with RagChunk instances."""

    def test_pre_hashed_chunks(self):
        w = _make_witness()
        chunks = [
            RagChunk(content_hash="abc123def456", source_id="doc-7/p3", similarity_score=0.92),
            RagChunk(content_hash="789012345678", source_id="doc-2/p1", similarity_score=0.78),
        ]
        payloads = w.witness_rag_context(
            chunks,
            corpus_id="legal-docs-v3",
            corpus_hash="fedcba987654",
            embedding_model="text-embedding-3-small",
            retrieval_latency_ms=124,
            top_k=10,
        )

        assert len(payloads) == 1  # no threshold, no AI-RAG.2
        p = payloads[0]
        assert p.factor_a == 2.0
        assert p.ai_context["chunk_hashes"] == ["abc123def456", "789012345678"]
        assert p.ai_context["corpus_hash"] == "fedcba987654"
        assert p.ai_context["embedding_model"] == "text-embedding-3-small"
        assert p.ai_context["retrieval_latency_ms"] == 124
        assert p.ai_context["top_k"] == 10
        assert p.ai_latency_ms == 124


# ---------------------------------------------------------------------------
# AI-RAG.2: Context Relevance (conditional dual-emit)
# ---------------------------------------------------------------------------

class TestRagDualEmit:
    """Test that AI-RAG.2 is emitted when threshold + scores are present."""

    def test_dual_emit_with_threshold_and_scores(self):
        w = _make_witness()
        chunks = [
            RagChunk(content_hash="aaa", similarity_score=0.92),
            RagChunk(content_hash="bbb", similarity_score=0.85),
            RagChunk(content_hash="ccc", similarity_score=0.61),
        ]
        payloads = w.witness_rag_context(
            chunks,
            corpus_id="my-corpus",
            similarity_threshold=0.75,
        )

        assert len(payloads) == 2

        # AI-RAG.1
        p1 = payloads[0]
        assert p1.procedure_id == "AI-RAG.1"
        assert p1.factor_a == 3.0

        # AI-RAG.2
        p2 = payloads[1]
        assert p2.procedure_id == "AI-RAG.2"
        assert p2.factor_a == 750  # threshold * 1000
        avg = (0.92 + 0.85 + 0.61) / 3
        assert p2.factor_b == round(avg * 1000)  # avg * 1000
        assert p2.factor_c == 1.0  # 1 chunk below 0.75
        assert p2.ai_context["similarity_threshold"] == 0.75
        assert p2.ai_context["chunks_below_threshold"] == 1
        assert p2.ai_context["min_similarity"] == 0.61

    def test_no_rag2_without_threshold(self):
        w = _make_witness()
        chunks = [RagChunk(content_hash="aaa", similarity_score=0.92)]
        payloads = w.witness_rag_context(chunks)

        assert len(payloads) == 1
        assert payloads[0].procedure_id == "AI-RAG.1"

    def test_no_rag2_without_scores(self):
        w = _make_witness()
        payloads = w.witness_rag_context(
            ["text without scores"],
            similarity_threshold=0.75,
        )

        assert len(payloads) == 1  # strings have no scores

    def test_all_above_threshold(self):
        w = _make_witness()
        chunks = [
            RagChunk(content_hash="aaa", similarity_score=0.92),
            RagChunk(content_hash="bbb", similarity_score=0.85),
        ]
        payloads = w.witness_rag_context(
            chunks,
            similarity_threshold=0.75,
        )

        assert len(payloads) == 2
        p2 = payloads[1]
        assert p2.factor_c == 0.0  # none below threshold


# ---------------------------------------------------------------------------
# Clearing level behavior
# ---------------------------------------------------------------------------

class TestRagClearingLevels:
    """Test that clearing strips metadata at levels 2-3."""

    def test_level_0_full_metadata(self):
        w = _make_witness(clearing_level=0)
        payloads = w.witness_rag_context(
            ["chunk"],
            corpus_id="corp",
            retrieval_latency_ms=50,
        )
        p = payloads[0]
        assert p.ai_context is not None
        assert p.ai_context["corpus_id"] == "corp"
        assert p.ai_latency_ms == 50

    def test_level_1_full_metadata(self):
        w = _make_witness(clearing_level=1)
        payloads = w.witness_rag_context(["chunk"], corpus_id="corp")
        p = payloads[0]
        assert p.ai_context is not None
        assert p.ai_model_id is not None

    def test_level_2_strips_context(self):
        w = _make_witness(clearing_level=2)
        payloads = w.witness_rag_context(
            ["chunk"],
            corpus_id="corp",
            retrieval_latency_ms=50,
        )
        p = payloads[0]
        assert p.ai_context is None  # stripped at level 2
        assert p.ai_model_id is None  # no model at level 2
        assert p.ai_latency_ms == 50  # latency survives level 2

    def test_level_3_factors_only(self):
        w = _make_witness(clearing_level=3)
        payloads = w.witness_rag_context(
            ["chunk"],
            corpus_id="corp",
            retrieval_latency_ms=50,
        )
        p = payloads[0]
        assert p.ai_context is None
        assert p.ai_model_id is None
        assert p.ai_latency_ms is None  # stripped at level 3
        # Factors always survive
        assert p.factor_a == 1.0
        assert p.factor_b == 1.0
        assert p.factor_c == 0.0

    def test_level_2_strips_rag2_context(self):
        w = _make_witness(clearing_level=2)
        chunks = [RagChunk(content_hash="aaa", similarity_score=0.92)]
        payloads = w.witness_rag_context(
            chunks,
            similarity_threshold=0.75,
        )
        assert len(payloads) == 2
        p2 = payloads[1]
        assert p2.ai_context is None  # stripped
        # Factors survive
        assert p2.factor_a == 750
