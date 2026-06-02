"""Tests for Cerebras WSE-3 adapter."""

import os
import time
from unittest.mock import MagicMock, patch

import pytest

from swt3_ai.adapters.cerebras import (
    witness_runtime,
    CerebrasWitnessMiddleware,
    _hash_input,
    _hash_output,
    _try_hash,
)
from swt3_ai.witness import Witness


@pytest.fixture
def mock_witness():
    """Create a mock witness that captures records."""
    w = MagicMock(spec=Witness)
    w.config = MagicMock()
    w.config.clearing_level = 1
    return w


# -- _try_hash tests --


class TestTryHash:
    def test_none_returns_none(self):
        assert _try_hash(None) is None

    def test_bytes(self):
        h = _try_hash(b"hello")
        assert h is not None
        assert len(h) == 16

    def test_string(self):
        h = _try_hash("hello")
        assert h is not None
        assert len(h) == 16  # sha256_truncated returns 16 chars

    def test_numpy_array(self):
        """Test with a mock numpy array that has tobytes()."""
        arr = MagicMock()
        arr.tobytes.return_value = b"\x01\x02\x03\x04"
        h = _try_hash(arr)
        assert h is not None
        assert len(h) == 16  # goes through hashlib bytes path

    def test_fallback_to_str(self):
        h = _try_hash(42)
        assert h is not None
        assert len(h) == 16  # str(42) goes through sha256_truncated


class TestHashInput:
    def test_empty_args(self):
        h = _hash_input((), {})
        # Falls through to sha256_truncated("")
        assert h is not None and len(h) == 16

    def test_bytes_arg(self):
        h = _hash_input((b"input_data",), {})
        assert len(h) == 16  # bytes path

    def test_kwarg(self):
        h = _hash_input((), {"data": b"input_data"})
        assert len(h) == 16  # bytes path


class TestHashOutput:
    def test_none_output(self):
        h = _hash_output(None)
        # None -> sha256_truncated("") fallback
        assert len(h) == 16

    def test_bytes_output(self):
        h = _hash_output(b"\x00\x01\x02")
        assert len(h) == 16


# -- witness_runtime decorator tests --


class TestWitnessRuntime:
    def test_no_op_without_config(self):
        """Without env vars or witness, decorator is transparent."""
        with patch.dict(os.environ, {}, clear=True):
            env = {k: v for k, v in os.environ.items() if not k.startswith("SWT3_")}
            with patch.dict(os.environ, env, clear=True):
                @witness_runtime()
                def my_fn(x):
                    return x * 2

                assert my_fn(5) == 10

    def test_witnesses_with_explicit_witness(self, mock_witness):
        @witness_runtime(witness=mock_witness, model_id="test-model")
        def my_fn(x):
            return x + 1

        result = my_fn(10)
        assert result == 11
        mock_witness.record.assert_called_once()

        record = mock_witness.record.call_args[0][0]
        assert record.model_id == "test-model"
        assert record.provider == "cerebras-wse3"
        assert record.latency_ms >= 0

    def test_preserves_return_value(self, mock_witness):
        @witness_runtime(witness=mock_witness)
        def compute():
            return {"result": [1, 2, 3]}

        assert compute() == {"result": [1, 2, 3]}

    def test_model_id_from_env(self, mock_witness):
        with patch.dict(os.environ, {"SWT3_MODEL_ID": "my-csl-model"}):
            @witness_runtime(witness=mock_witness)
            def fn():
                return 42

            fn()
            record = mock_witness.record.call_args[0][0]
            assert record.model_id == "my-csl-model"

    def test_default_model_id(self, mock_witness):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SWT3_MODEL_ID", None)
            os.environ.pop("CEREBRAS_MODEL_NAME", None)

            @witness_runtime(witness=mock_witness)
            def fn():
                return 1

            fn()
            record = mock_witness.record.call_args[0][0]
            assert record.model_id == "cerebras-wse3"

    def test_hashes_input_args(self, mock_witness):
        @witness_runtime(witness=mock_witness)
        def fn(data):
            return data

        fn(b"input_bytes")
        record = mock_witness.record.call_args[0][0]
        assert record.prompt_hash != ""
        assert len(record.prompt_hash) == 16


# -- CerebrasWitnessMiddleware tests --


class TestCerebrasMiddleware:
    def _make_runtime(self):
        """Create a mock SdkRuntime."""
        runtime = MagicMock()
        runtime.launch = MagicMock()
        runtime.memcpy_d2h = MagicMock(return_value=b"\x00\x01\x02\x03")
        runtime.memcpy_h2d = MagicMock()
        return runtime

    def test_patch_adds_witnessing(self, mock_witness):
        runtime = self._make_runtime()
        mw = CerebrasWitnessMiddleware(witness=mock_witness)
        mw.patch(runtime)

        assert mw.is_patched
        runtime.launch("my_kernel", nonblock=False)
        runtime.memcpy_d2h("output_sym", (10,))

        mock_witness.record.assert_called_once()
        record = mock_witness.record.call_args[0][0]
        assert record.provider == "cerebras-wse3"

    def test_launch_count_tracks(self, mock_witness):
        runtime = self._make_runtime()
        mw = CerebrasWitnessMiddleware(witness=mock_witness)
        mw.patch(runtime)

        runtime.launch("k1", nonblock=False)
        runtime.launch("k2", nonblock=False)
        runtime.launch("k3", nonblock=False)

        assert mw.launch_count == 3

    def test_kernel_name_in_anchor(self, mock_witness):
        runtime = self._make_runtime()
        mw = CerebrasWitnessMiddleware(witness=mock_witness, model_id="wse3-llm")
        mw.patch(runtime)

        runtime.launch("attention_kernel", nonblock=False)
        runtime.memcpy_d2h("out", (1,))

        record = mock_witness.record.call_args[0][0]
        assert record.model_id == "wse3-llm"
        # prompt_hash is sha256_truncated(kernel_name) = 16 chars
        assert len(record.prompt_hash) == 16

    def test_double_patch_skips(self, mock_witness):
        runtime = self._make_runtime()
        mw = CerebrasWitnessMiddleware(witness=mock_witness)
        mw.patch(runtime)
        mw.patch(runtime)  # should warn and skip
        assert mw.is_patched

    def test_no_launch_raises_on_bad_object(self, mock_witness):
        bad_runtime = object()
        mw = CerebrasWitnessMiddleware(witness=mock_witness)
        with pytest.raises(AttributeError, match="launch"):
            mw.patch(bad_runtime)

    def test_latency_measured(self, mock_witness):
        runtime = self._make_runtime()

        # Make launch take some time
        original_launch = runtime.launch
        def slow_launch(*a, **kw):
            time.sleep(0.01)
            return original_launch(*a, **kw)
        runtime.launch = slow_launch

        mw = CerebrasWitnessMiddleware(witness=mock_witness)
        mw.patch(runtime)

        runtime.launch("kernel", nonblock=False)
        runtime.memcpy_d2h("out", (1,))

        record = mock_witness.record.call_args[0][0]
        assert record.latency_ms >= 10

    def test_no_op_without_witness(self):
        """Without config, middleware patches but doesn't mint."""
        runtime = self._make_runtime()
        with patch.dict(os.environ, {}, clear=True):
            env = {k: v for k, v in os.environ.items() if not k.startswith("SWT3_")}
            with patch.dict(os.environ, env, clear=True):
                mw = CerebrasWitnessMiddleware()
                mw.patch(runtime)
                runtime.launch("k1")
                runtime.memcpy_d2h("out", (1,))
                # No crash, just no-op

    def test_memcpy_returns_original_data(self, mock_witness):
        runtime = self._make_runtime()
        expected = b"\xDE\xAD\xBE\xEF"
        runtime.memcpy_d2h = MagicMock(return_value=expected)

        mw = CerebrasWitnessMiddleware(witness=mock_witness)
        mw.patch(runtime)

        runtime.launch("k1")
        result = runtime.memcpy_d2h("out", (4,))
        assert result == expected


# -- Schema validation: cerebras_wse3 in allowed_methods --


class TestSchemaWse3:
    def test_cerebras_wse3_valid_method(self):
        from swt3_ai.schema import _VALID_ATTESTATION_METHODS
        assert "cerebras_wse3" in _VALID_ATTESTATION_METHODS

    def test_validate_schema_with_cerebras(self):
        from swt3_ai.schema import validate_schema
        raw = {
            "hardware": {
                "require_attestation": True,
                "allowed_methods": ["cerebras_wse3", "tpm_2.0"],
            }
        }
        result = validate_schema(raw)
        method_errors = [e for e in result.errors if "cerebras_wse3" in str(e)]
        assert len(method_errors) == 0
