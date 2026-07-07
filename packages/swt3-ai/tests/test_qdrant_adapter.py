"""Tests for the Qdrant RAG witness adapter (wrap_qdrant)."""

import unittest
from unittest.mock import MagicMock
from swt3_ai.adapters.qdrant import wrap_qdrant, _QdrantProxy
from swt3_ai.witness import Witness


def _w() -> Witness:
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="TEST", clearing_level=1)
    w._buffer = MagicMock()
    return w


class TestWrapQdrant(unittest.TestCase):
    def test_returns_proxy(self):
        client = MagicMock()
        proxied = wrap_qdrant(client, _w())
        assert isinstance(proxied, _QdrantProxy)

    def test_passthrough_attributes(self):
        client = MagicMock()
        client.collection_name = "docs"
        proxied = wrap_qdrant(client, _w())
        assert proxied.collection_name == "docs"

    def test_search_witnesses_rag(self):
        client = MagicMock()
        client.search = MagicMock(return_value=[
            MagicMock(id=1, score=0.95, payload={"text": "result"}),
        ])
        witness = _w()
        proxied = wrap_qdrant(client, witness)
        results = proxied.search(collection_name="docs", query_vector=[0.1, 0.2], limit=5)
        assert len(results) == 1
        client.search.assert_called_once()

    def test_search_preserves_results(self):
        mock_results = [MagicMock(id=i, score=0.9 - i * 0.1) for i in range(3)]
        client = MagicMock()
        client.search = MagicMock(return_value=mock_results)
        proxied = wrap_qdrant(client, _w())
        results = proxied.search(collection_name="test", query_vector=[0.1], limit=3)
        assert results == mock_results


class TestSkillSpectorAdapter(unittest.TestCase):
    """Test SkillSpector scan result witnessing."""

    def test_basic_scan_witness(self):
        from swt3_ai.adapters.skillspector import witness_skill_scan
        witness = _w()
        scan_result = {
            "findings": [
                {"severity": "high", "type": "permission_misalignment"},
                {"severity": "medium", "type": "excess_scope"},
            ],
            "risk_score": 72,
            "scan_target": "my-agent",
        }
        record = witness_skill_scan(witness, scan_result)
        assert record is not None

    def test_empty_scan(self):
        from swt3_ai.adapters.skillspector import witness_skill_scan
        witness = _w()
        scan_result = {"findings": [], "risk_score": 0}
        record = witness_skill_scan(witness, scan_result)
        assert record is not None


if __name__ == "__main__":
    unittest.main()
