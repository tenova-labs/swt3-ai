"""Tests for LangGraph adapter."""

import pytest
import asyncio
from unittest.mock import MagicMock
from swt3_ai.adapters.langgraph import wrap_langgraph


class MockCompiledGraph:
    """Mock LangGraph CompiledGraph."""

    def __init__(self, name="chatbot-graph"):
        self.name = name
        self._invoke_result = {"messages": [("assistant", "Hello!")]}
        self._stream_chunks = [
            {"messages": [("assistant", "Hel")]},
            {"messages": [("assistant", "Hello!")]},
        ]

    def invoke(self, input_val, *args, **kwargs):
        return self._invoke_result

    def stream(self, input_val, *args, **kwargs):
        yield from self._stream_chunks

    async def ainvoke(self, input_val, *args, **kwargs):
        return self._invoke_result

    async def astream(self, input_val, *args, **kwargs):
        for chunk in self._stream_chunks:
            yield chunk


class TestWrapLangGraph:
    def test_invoke_witnesses(self):
        graph = MockCompiledGraph()
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)

        result = wrapped.invoke({"messages": [("user", "Hi")]})

        assert result == {"messages": [("assistant", "Hello!")]}
        witness.record.assert_called_once()
        record = witness.record.call_args[0][0]
        assert record.provider == "langgraph"
        assert record.model_id == "chatbot-graph"

    def test_invoke_response_untouched(self):
        graph = MockCompiledGraph()
        expected = graph._invoke_result
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)

        result = wrapped.invoke({"messages": []})
        assert result is expected

    def test_stream_witnesses_after_completion(self):
        graph = MockCompiledGraph()
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)

        chunks = list(wrapped.stream({"messages": [("user", "Hi")]}))

        assert len(chunks) == 2
        assert chunks[0] == {"messages": [("assistant", "Hel")]}
        assert chunks[1] == {"messages": [("assistant", "Hello!")]}
        witness.record.assert_called_once()
        record = witness.record.call_args[0][0]
        assert record.provider == "langgraph"

    def test_ainvoke_witnesses(self):
        graph = MockCompiledGraph()
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)

        result = asyncio.run(
            wrapped.ainvoke({"messages": [("user", "Hi")]})
        )

        assert result == {"messages": [("assistant", "Hello!")]}
        witness.record.assert_called_once()
        record = witness.record.call_args[0][0]
        assert record.provider == "langgraph"

    def test_astream_witnesses(self):
        graph = MockCompiledGraph()
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)

        async def collect():
            chunks = []
            async for chunk in wrapped.astream({"messages": [("user", "Hi")]}):
                chunks.append(chunk)
            return chunks

        chunks = asyncio.run(collect())

        assert len(chunks) == 2
        witness.record.assert_called_once()

    def test_model_id_from_name(self):
        graph = MockCompiledGraph(name="rag-pipeline")
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)
        wrapped.invoke({})

        record = witness.record.call_args[0][0]
        assert record.model_id == "rag-pipeline"

    def test_model_id_explicit(self):
        graph = MockCompiledGraph()
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness, model_id="custom-graph")
        wrapped.invoke({})

        record = witness.record.call_args[0][0]
        assert record.model_id == "custom-graph"

    def test_model_id_fallback(self):
        graph = MagicMock(spec=["invoke"])
        graph.invoke.return_value = {}
        del graph.name
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)
        wrapped.invoke({})

        record = witness.record.call_args[0][0]
        assert record.model_id == "langgraph-agent"

    def test_noop_without_witness(self):
        graph = MockCompiledGraph()
        result = wrap_langgraph(graph, witness=None)
        assert result is graph

    def test_passthrough_attributes(self):
        graph = MockCompiledGraph()
        graph.custom = "value"
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)

        assert wrapped.custom == "value"
        assert wrapped.name == "chatbot-graph"

    def test_latency_recorded(self):
        graph = MockCompiledGraph()
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)
        wrapped.invoke({})

        record = witness.record.call_args[0][0]
        assert record.latency_ms >= 0

    def test_ainvoke_missing_raises(self):
        graph = MagicMock(spec=["invoke"])
        graph.invoke.return_value = {}
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)

        with pytest.raises(AttributeError):
            asyncio.run(wrapped.ainvoke({}))

    def test_stream_missing_raises(self):
        graph = MagicMock(spec=["invoke"])
        graph.invoke.return_value = {}
        witness = MagicMock()
        wrapped = wrap_langgraph(graph, witness)

        with pytest.raises(AttributeError):
            list(wrapped.stream({}))
