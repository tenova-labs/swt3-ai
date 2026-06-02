"""Model weights + procedural knowledge witnessing tests.

Tests for AI-MDL.5/6/7 (model weights, adapters, quantization) and
AI-SKILL.1/2/3 (skills, memory, reward model).
"""

from __future__ import annotations

import os
import tempfile
from unittest.mock import MagicMock

import pytest

from swt3_ai import Witness, ModelWeightInfo, AdapterInfo, SkillInfo, MemorySource


def _make_witness(clearing_level=1):
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
# AI-MDL.5: Weight File Integrity
# ---------------------------------------------------------------------------

class TestModelWeights:
    def test_model_weight_info(self):
        w = _make_witness()
        info = ModelWeightInfo(file_hash="abc123def456", format="safetensors")
        p = w.witness_model_weights(info)
        assert p.procedure_id == "AI-MDL.5"
        assert p.factor_a == 1.0
        assert p.factor_b == 1.0  # no expected hash = attested
        assert p.ai_context["file_hash"] == "abc123def456"

    def test_file_path_auto_hash(self):
        w = _make_witness()
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(b"fake model weights data")
            path = f.name
        try:
            p = w.witness_model_weights(path)
            assert p.procedure_id == "AI-MDL.5"
            assert p.factor_b == 1.0
            assert p.ai_context["file_hash"]  # non-empty hash
            assert p.ai_context["file_path"] == path
            assert p.ai_context["file_size_bytes"] > 0
            assert p.ai_context["format"] == "safetensors"
        finally:
            os.unlink(path)

    def test_hash_mismatch(self):
        w = _make_witness()
        info = ModelWeightInfo(file_hash="actual_hash_123")
        p = w.witness_model_weights(info, expected_hash="different_hash")
        assert p.factor_b == 0.0  # FAIL

    def test_hash_match(self):
        w = _make_witness()
        info = ModelWeightInfo(file_hash="matching_hash")
        p = w.witness_model_weights(info, expected_hash="matching_hash")
        assert p.factor_b == 1.0  # PASS

    def test_clearing_level_3(self):
        w = _make_witness(clearing_level=3)
        info = ModelWeightInfo(file_hash="abc123")
        p = w.witness_model_weights(info)
        assert p.ai_context is None
        assert p.factor_a == 1.0


# ---------------------------------------------------------------------------
# AI-MDL.6: Adapter Stack
# ---------------------------------------------------------------------------

class TestAdapterStack:
    def test_multiple_adapters(self):
        w = _make_witness()
        adapters = [
            AdapterInfo(name="lora-legal", adapter_hash="aaa111"),
            AdapterInfo(name="lora-medical", adapter_hash="bbb222"),
        ]
        p = w.witness_adapter_stack(adapters, base_model_id="llama-3.1-70b")
        assert p.procedure_id == "AI-MDL.6"
        assert p.factor_a == 2.0
        assert p.factor_b == 1.0  # all verified
        assert p.ai_context["base_model_id"] == "llama-3.1-70b"
        assert len(p.ai_context["adapters"]) == 2

    def test_empty_stack(self):
        w = _make_witness()
        p = w.witness_adapter_stack([])
        assert p.factor_a == 0.0
        assert p.factor_b == 1.0  # empty = verified

    def test_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        adapters = [AdapterInfo(name="lora-1", adapter_hash="aaa")]
        p = w.witness_adapter_stack(adapters, base_model_id="llama")
        assert p.ai_context is None


# ---------------------------------------------------------------------------
# AI-MDL.7: Quantization
# ---------------------------------------------------------------------------

class TestQuantization:
    def test_gptq(self):
        w = _make_witness()
        p = w.witness_quantization("gptq", bits=4, group_size=128)
        assert p.procedure_id == "AI-MDL.7"
        assert p.factor_c == 5.0  # GPTQ code
        assert p.ai_context["method"] == "gptq"
        assert p.ai_context["bits"] == 4
        assert p.ai_context["group_size"] == 128

    def test_fp16(self):
        w = _make_witness()
        p = w.witness_quantization("FP16")
        assert p.factor_c == 1.0  # FP16 code
        assert p.ai_context["method"] == "fp16"

    def test_unknown_method(self):
        w = _make_witness()
        p = w.witness_quantization("custom_quant")
        assert p.factor_c == 0.0  # unknown defaults to 0


# ---------------------------------------------------------------------------
# AI-SKILL.1: Skill Manifest
# ---------------------------------------------------------------------------

class TestSkillManifest:
    def test_string_skills(self):
        w = _make_witness()
        p = w.witness_skill_manifest(["code_exec", "web_search", "file_read"])
        assert p.procedure_id == "AI-SKILL.1"
        assert p.factor_a == 3.0
        assert p.factor_b == 1.0
        assert len(p.ai_context["skills"]) == 3
        assert p.ai_context["manifest_hash"]  # non-empty

    def test_skill_info_objects(self):
        w = _make_witness()
        skills = [
            SkillInfo(name="search", version="1.2.0", skill_hash="abc123"),
            SkillInfo(name="calc", version="2.0.0", skill_hash="def456"),
        ]
        p = w.witness_skill_manifest(skills)
        assert p.factor_a == 2.0
        assert p.ai_context["skills"][0]["version"] == "1.2.0"

    def test_manifest_hash_mismatch(self):
        w = _make_witness()
        p = w.witness_skill_manifest(["a", "b"], expected_manifest_hash="wrong_hash")
        assert p.factor_b == 0.0  # FAIL

    def test_clearing_level_3(self):
        w = _make_witness(clearing_level=3)
        p = w.witness_skill_manifest(["skill_a"])
        assert p.ai_context is None
        assert p.factor_a == 1.0


# ---------------------------------------------------------------------------
# AI-SKILL.2: Memory Context
# ---------------------------------------------------------------------------

class TestMemoryContext:
    def test_multiple_sources(self):
        w = _make_witness()
        sources = [
            MemorySource(source_type="vector_store", source_id="pinecone-prod", content_hash="aaa"),
            MemorySource(source_type="conversation", source_id="session-123"),
        ]
        p = w.witness_memory_context(sources)
        assert p.procedure_id == "AI-SKILL.2"
        assert p.factor_a == 2.0
        assert p.factor_b == 1.0  # all identified
        assert len(p.ai_context["sources"]) == 2

    def test_anonymous_source(self):
        w = _make_witness()
        sources = [MemorySource(source_type="scratchpad")]  # no id, no hash
        p = w.witness_memory_context(sources)
        assert p.factor_b == 0.0  # not all identified

    def test_empty_sources(self):
        w = _make_witness()
        p = w.witness_memory_context([])
        assert p.factor_a == 0.0
        assert p.factor_b == 0.0  # empty = not identified


# ---------------------------------------------------------------------------
# AI-SKILL.3: Reward Model
# ---------------------------------------------------------------------------

class TestRewardModel:
    def test_identified(self):
        w = _make_witness()
        p = w.witness_reward_model("rm-v3-legal", model_hash="abc123", method="dpo")
        assert p.procedure_id == "AI-SKILL.3"
        assert p.factor_b == 1.0
        assert p.ai_context["model_id"] == "rm-v3-legal"
        assert p.ai_context["method"] == "dpo"

    def test_empty_model_id(self):
        w = _make_witness()
        p = w.witness_reward_model("", method="rlhf")
        assert p.factor_b == 0.0  # not identified

    def test_clearing_level_2(self):
        w = _make_witness(clearing_level=2)
        p = w.witness_reward_model("rm-v3")
        assert p.ai_context is None
