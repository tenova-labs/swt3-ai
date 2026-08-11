"""Tests for AI-MOB.6 (witness_trajectory) and AI-MOB.7 (wrap_vla)."""

import asyncio
import pytest

from swt3_ai import Witness, SAFETY_CLASSIFICATION_CODES


def _make_witness(**kwargs):
    defaults = {
        "endpoint": "https://example.com",
        "api_key": "axm_test_key",
        "tenant_id": "TEST_TENANT",
        "clearing_level": 1,
    }
    defaults.update(kwargs)
    return Witness(**defaults)


# ── AI-MOB.6: witness_trajectory ──────────────────────────────────


class TestWitnessTrajectoryBasic:
    def test_pass_nominal(self):
        w = _make_witness()
        p = w.witness_trajectory(safety_validated=True)
        assert p.procedure_id == "AI-MOB.6"
        assert p.factor_a == 1.0
        assert p.factor_b == 1.0
        assert p.factor_c == 1.0  # nominal
        assert p.anchor_fingerprint

    def test_fail(self):
        w = _make_witness()
        p = w.witness_trajectory(safety_validated=False)
        assert p.factor_b == 0.0

    def test_safety_classification_emergency(self):
        w = _make_witness()
        p = w.witness_trajectory(
            safety_validated=True, safety_classification="emergency",
        )
        assert p.factor_c == 4.0

    def test_safety_classification_abort(self):
        w = _make_witness()
        p = w.witness_trajectory(
            safety_validated=False, safety_classification="abort",
        )
        assert p.factor_c == 5.0

    def test_safety_classification_degraded(self):
        w = _make_witness()
        p = w.witness_trajectory(
            safety_validated=True, safety_classification="degraded",
        )
        assert p.factor_c == 3.0

    def test_unknown_classification_defaults_zero(self):
        w = _make_witness()
        p = w.witness_trajectory(
            safety_validated=True, safety_classification="unknown_value",
        )
        assert p.factor_c == 0.0


class TestWitnessTrajectoryContext:
    def test_context_at_cl1(self):
        w = _make_witness(clearing_level=1)
        p = w.witness_trajectory(
            safety_validated=True,
            waypoint_count=47,
            trajectory_hash="abc123",
            coc_trace_hash="def456",
            coc_node_count=12,
            action_class="navigate",
            sensor_sources=["camera_front", "lidar_top", "radar"],
            model_id="alpamayo-2-super",
        )
        assert p.ai_model_id == "alpamayo-2-super"
        ctx = p.ai_context
        assert ctx["provider"] == "trajectory"
        assert ctx["safety_validated"] is True
        assert ctx["waypoint_count"] == 47
        assert ctx["trajectory_hash"] == "abc123"
        assert ctx["coc_trace_hash"] == "def456"
        assert ctx["coc_node_count"] == 12
        assert ctx["action_class"] == "navigate"
        assert ctx["sensor_count"] == 3
        assert ctx["sensor_sources"] == ["camera_front", "lidar_top", "radar"]

    def test_context_stripped_at_cl2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_trajectory(
            safety_validated=True,
            sensor_sources=["camera_front", "lidar"],
            model_id="test-model",
        )
        assert p.ai_model_id == "test-model"
        ctx = p.ai_context
        assert ctx["provider_category"] == "trajectory"
        assert ctx["sensor_count"] == 2
        assert "sensor_sources" not in ctx
        assert "safety_validated" not in ctx

    def test_model_id_hashed_at_cl3(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_trajectory(
            safety_validated=True, model_id="secret-model",
        )
        assert p.ai_model_id != "secret-model"
        assert len(p.ai_model_id) <= 16  # sha256 truncated
        assert p.ai_context is None

    def test_default_model_id(self):
        w = _make_witness()
        p = w.witness_trajectory(safety_validated=True)
        assert p.ai_model_id == "trajectory-planner"

    def test_coc_hash_stored_not_raw(self):
        w = _make_witness()
        p = w.witness_trajectory(
            safety_validated=True,
            coc_trace_hash="sha256abcdef",
        )
        ctx = p.ai_context
        assert ctx["coc_trace_hash"] == "sha256abcdef"
        assert "coc_trace" not in ctx  # never raw traces


class TestSafetyClassificationCodes:
    def test_all_codes_present(self):
        assert SAFETY_CLASSIFICATION_CODES["reserved"] == 0
        assert SAFETY_CLASSIFICATION_CODES["nominal"] == 1
        assert SAFETY_CLASSIFICATION_CODES["cautionary"] == 2
        assert SAFETY_CLASSIFICATION_CODES["degraded"] == 3
        assert SAFETY_CLASSIFICATION_CODES["emergency"] == 4
        assert SAFETY_CLASSIFICATION_CODES["abort"] == 5


# ── AI-MOB.7: wrap_vla ────────────────────────────────────────────


class TestWrapVlaSync:
    def test_basic_sync_wrap(self):
        w = _make_witness()

        def predict(frames):
            return {"trajectory": [1, 2, 3]}

        wrapped = w.wrap_vla(predict, model_id="test-vla")
        result = wrapped([b"frame1", b"frame2"])
        assert result == {"trajectory": [1, 2, 3]}

    def test_exception_propagated(self):
        w = _make_witness()

        def bad_predict(frames):
            raise ValueError("inference failed")

        wrapped = w.wrap_vla(bad_predict, model_id="test-vla")
        with pytest.raises(ValueError, match="inference failed"):
            wrapped([b"frame1"])

    def test_decorator_syntax(self):
        w = _make_witness()

        @w.wrap_vla(model_id="decorator-vla")
        def predict(frames):
            return [0.1, 0.2]

        result = predict([b"f1"])
        assert result == [0.1, 0.2]

    def test_with_frame_hashes(self):
        w = _make_witness()

        def predict(frames):
            return "trajectory"

        wrapped = w.wrap_vla(
            predict,
            model_id="test-vla",
            input_frame_hashes=["hash1", "hash2"],
        )
        result = wrapped([b"f1", b"f2"])
        assert result == "trajectory"


class TestWrapVlaAsync:
    def test_async_wrap(self):
        w = _make_witness()

        async def async_predict(frames):
            return {"path": [1, 2]}

        wrapped = w.wrap_vla(async_predict, model_id="async-vla")
        result = asyncio.run(wrapped([b"frame1"]))
        assert result == {"path": [1, 2]}

    def test_async_exception(self):
        w = _make_witness()

        async def bad_async(frames):
            raise RuntimeError("timeout")

        wrapped = w.wrap_vla(bad_async, model_id="bad-vla")
        with pytest.raises(RuntimeError, match="timeout"):
            asyncio.run(wrapped([]))
