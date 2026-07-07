"""Tests for the Cohere adapter (wrap_cohere)."""

import unittest
from unittest.mock import MagicMock, patch
from swt3_ai.adapters.cohere import wrap_cohere, _CohereProxy
from swt3_ai.witness import Witness


def _w() -> Witness:
    w = Witness(endpoint="https://test.example.com", api_key="axm_test_key", tenant_id="TEST", clearing_level=1)
    w._buffer = MagicMock()
    return w


def _mock_cohere_response():
    resp = MagicMock()
    resp.message = MagicMock()
    resp.message.content = [MagicMock(text="Hello, world!")]
    resp.model = "command-r-plus"
    resp.usage = MagicMock(tokens=MagicMock(input_tokens=10, output_tokens=5))
    resp.meta = MagicMock(model="command-r-plus-08-2024")
    return resp


class TestWrapCohere(unittest.TestCase):
    def test_returns_proxy(self):
        client = MagicMock()
        witness = _w()
        proxied = wrap_cohere(client, witness)
        assert isinstance(proxied, _CohereProxy)

    def test_passthrough_attributes(self):
        client = MagicMock()
        client.some_attr = "test"
        proxied = wrap_cohere(client, _w())
        assert proxied.some_attr == "test"

    def test_chat_witnesses_inference(self):
        client = MagicMock()
        client.chat = MagicMock(return_value=_mock_cohere_response())
        witness = _w()
        proxied = wrap_cohere(client, witness)
        result = proxied.chat(model="command-r-plus", messages=[{"role": "user", "content": "Hi"}])
        assert result is not None
        client.chat.assert_called_once()

    def test_proxy_preserves_response(self):
        resp = _mock_cohere_response()
        client = MagicMock()
        client.chat = MagicMock(return_value=resp)
        proxied = wrap_cohere(client, _w())
        result = proxied.chat(model="command-r-plus", messages=[])
        assert result == resp


if __name__ == "__main__":
    unittest.main()
