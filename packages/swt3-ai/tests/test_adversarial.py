"""SWT3 AI Witness SDK -- Adversarial Tests.

Tests SDK resilience against malformed inputs, injection attempts,
boundary conditions, and fail-safe behavior.
"""

import json
import math
import re

import pytest

from swt3_ai import Witness, GatekeeperError
from swt3_ai.fingerprint import mint_fingerprint, sha256_truncated, sha256_hex
from swt3_ai.signing import sign_payload
from swt3_ai.clearing import (
    extract_payloads,
    extract_revocation_payload,
    REVOCATION_REASONS,
)
from swt3_ai.types import (
    InferenceRecord, AdapterInfo, ModelWeightInfo, RagChunk,
)


def mk_witness(**overrides):
    defaults = dict(
        endpoint="https://test.example.com",
        api_key="axm_test_key",
        tenant_id="test_tenant",
        flush_interval=999999,
    )
    defaults.update(overrides)
    return Witness(**defaults)


def mk_record(**overrides):
    defaults = dict(
        model_id="gpt-4o",
        model_hash="abc123",
        prompt_hash="prompt_hash_val",
        response_hash="response_hash_val",
        latency_ms=500,
        guardrails_active=1,
        guardrails_required=1,
        guardrail_passed=True,
        has_refusal=False,
        provider="openai",
        guardrail_names=["content-filter"],
    )
    defaults.update(overrides)
    return InferenceRecord(**defaults)


# ----------------------------------------------------------------
# 1. Constructor validation bypass
# ----------------------------------------------------------------
class TestConstructorValidation:
    def test_rejects_empty_endpoint(self):
        with pytest.raises(ValueError, match="endpoint is required"):
            Witness(endpoint="", api_key="axm_x", tenant_id="t")

    def test_rejects_missing_api_key(self):
        with pytest.raises(ValueError, match="api_key is required"):
            Witness(endpoint="https://x.com", api_key="", tenant_id="t")

    def test_rejects_invalid_factor_handoff(self):
        with pytest.raises(ValueError, match="factor_handoff must be 'file'"):
            mk_witness(factor_handoff="s3")

    def test_rejects_factor_handoff_without_path(self):
        with pytest.raises(ValueError, match="factor_handoff_path is required"):
            mk_witness(factor_handoff="file")

    def test_gateway_mode_skips_validation(self):
        w = Witness(gateway_mode=True, flush_interval=999999)
        assert w.gateway_mode is True


# ----------------------------------------------------------------
# 2. Fingerprint integrity under malicious inputs
# ----------------------------------------------------------------
class TestFingerprintIntegrity:
    def test_colon_injection_in_tenant_id(self):
        legit = mint_fingerprint("tenant_a", "AI-INF.1", 1, 1, 0, 1000)
        injected = mint_fingerprint("tenant_a:AI-INF.1:1", "", 0, 0, 0, 1000)
        assert legit != injected

    def test_colon_injection_in_procedure_id(self):
        legit = mint_fingerprint("t", "AI-INF.1", 1, 0, 0, 1000)
        injected = mint_fingerprint("t", "AI-INF.1:1:0:0:1000", 0, 0, 0, 999)
        assert legit != injected

    def test_negative_factors(self):
        pos = mint_fingerprint("t", "AI-INF.1", 1, 1, 0, 1000)
        neg = mint_fingerprint("t", "AI-INF.1", -1, -1, 0, 1000)
        assert pos != neg

    def test_nan_factors_raise_or_produce_valid(self):
        # Python int(nan) raises ValueError -- this is correct fail-safe behavior
        with pytest.raises((ValueError, OverflowError)):
            mint_fingerprint("t", "P", float("nan"), 0, 0, 1000)

    def test_infinity_factors_raise_or_produce_valid(self):
        # Python int(inf) raises OverflowError -- this is correct fail-safe behavior
        with pytest.raises((ValueError, OverflowError)):
            mint_fingerprint("t", "P", float("inf"), 0, 0, 1000)

    def test_very_large_factors(self):
        fp = mint_fingerprint("t", "P", 2**53, 0, 0, 1000)
        assert len(fp) == 12
        assert re.match(r"^[0-9a-f]{12}$", fp)

    def test_float_factors_consistent(self):
        fp1 = mint_fingerprint("t", "P", 1.5, 2.7, 0.001, 1000)
        fp2 = mint_fingerprint("t", "P", 1.5, 2.7, 0.001, 1000)
        assert fp1 == fp2

    def test_unicode_tenant_id(self):
        fp = mint_fingerprint("tenant_\U0001F600\U0001F4A9", "P", 1, 0, 0, 1000)
        assert len(fp) == 12

    def test_empty_tenant_id(self):
        fp = mint_fingerprint("", "P", 1, 0, 0, 1000)
        assert len(fp) == 12

    def test_very_long_tenant_id(self):
        fp = mint_fingerprint("a" * 100_000, "P", 1, 0, 0, 1000)
        assert len(fp) == 12


# ----------------------------------------------------------------
# 3. Clearing level enforcement
# ----------------------------------------------------------------
class TestClearingEnforcement:
    def test_level_3_no_model_id_cleartext(self):
        record = mk_record()
        payloads = extract_payloads(record, "t", 3)
        for p in payloads:
            if p.ai_model_id:
                assert p.ai_model_id != "gpt-4o"
                assert re.match(r"^[0-9a-f]+$", p.ai_model_id)

    def test_level_3_strips_all_hashes(self):
        record = mk_record()
        payloads = extract_payloads(record, "t", 3)
        for p in payloads:
            assert p.ai_prompt_hash is None
            assert p.ai_response_hash is None
            assert p.ai_latency_ms is None
            assert p.ai_input_tokens is None
            assert p.ai_output_tokens is None
            assert p.ai_context is None
            assert p.ai_system_prompt_hash is None

    def test_level_2_strips_ai_context(self):
        record = mk_record()
        payloads = extract_payloads(record, "t", 2)
        for p in payloads:
            assert p.ai_context is None

    def test_level_3_json_does_not_leak(self):
        record = mk_record(system_prompt_hash="sys_hash_val", system_fingerprint="fp_abc")
        payloads = extract_payloads(record, "t", 3)
        # Serialize via dataclass __dict__
        blob = json.dumps([vars(p) for p in payloads])
        assert "gpt-4o" not in blob
        assert "prompt_hash_val" not in blob
        assert "response_hash_val" not in blob
        assert "sys_hash_val" not in blob
        assert "content-filter" not in blob

    def test_cjt_fields_survive_all_levels(self):
        record = mk_record()
        for level in (0, 1, 2, 3):
            payloads = extract_payloads(
                record, "t", level,
                jurisdiction="DE", legal_basis="GDPR-6.1.a", purpose_class="analytics",
            )
            for p in payloads:
                assert p.jurisdiction == "DE"
                assert p.legal_basis == "GDPR-6.1.a"
                assert p.purpose_class == "analytics"

    def test_agent_id_survives_all_levels(self):
        record = mk_record()
        for level in (0, 1, 2, 3):
            payloads = extract_payloads(record, "t", level, agent_id="agent-007")
            for p in payloads:
                assert p.agent_id == "agent-007"


# ----------------------------------------------------------------
# 4. Injection via payload fields
# ----------------------------------------------------------------
class TestInjectionResistance:
    def test_sql_injection_in_tenant_id(self):
        w = mk_witness(tenant_id="'; DROP TABLE ledger; --")
        w.witness_security_scan(100)
        assert w.pending > 0

    def test_html_xss_in_model_id(self):
        record = mk_record(model_id='<script>alert("xss")</script>')
        payloads = extract_payloads(record, "t", 1)
        assert len(payloads) > 0
        for p in payloads:
            assert re.match(r"^[0-9a-f]{12}$", p.anchor_fingerprint)

    def test_null_bytes_in_hashing(self):
        fp = sha256_truncated("test\x00injection\x00payload")
        assert len(fp) == 16

    def test_control_chars_in_agent_id(self):
        w = mk_witness(agent_id="agent\n\r\t\x00\x1b[31m")
        w.witness_security_scan(100)
        assert w.pending > 0


# ----------------------------------------------------------------
# 5. Revocation abuse
# ----------------------------------------------------------------
class TestRevocationAbuse:
    def test_rejects_empty_fingerprint(self):
        w = mk_witness()
        with pytest.raises(ValueError, match="fingerprint is required"):
            w.revoke("", "model_recall")

    def test_rejects_whitespace_fingerprint(self):
        w = mk_witness()
        with pytest.raises(ValueError, match="fingerprint is required"):
            w.revoke("   \t\n  ", "model_recall")

    def test_rejects_unknown_reason(self):
        w = mk_witness()
        with pytest.raises(ValueError, match="Unknown revocation reason"):
            w.revoke("abc123def456", "because_i_said_so")

    def test_accepts_all_7_valid_reasons(self):
        w = mk_witness()
        for reason in REVOCATION_REASONS:
            fp = w.revoke("abc123def456", reason)
            assert len(fp) == 12
        assert w.pending == 7

    def test_rejects_dunder_keys(self):
        w = mk_witness()
        with pytest.raises(ValueError, match="Unknown revocation reason"):
            w.revoke("abc123def456", "__class__")
        with pytest.raises(ValueError, match="Unknown revocation reason"):
            w.revoke("abc123def456", "__init__")

    def test_double_revocation_produces_anchors(self):
        w = mk_witness()
        fp1 = w.revoke("abc123def456", "model_recall")
        fp2 = w.revoke("abc123def456", "model_recall")
        assert len(fp1) == 12
        assert len(fp2) == 12


# ----------------------------------------------------------------
# 6. Buffer resilience
# ----------------------------------------------------------------
class TestBufferResilience:
    def test_enqueue_after_flush_no_crash(self):
        w = mk_witness()
        w.flush()
        w.witness_security_scan(100)
        assert w.pending > 0

    def test_flush_empty_buffer(self):
        w = mk_witness()
        result = w.flush()
        assert result == []

    def test_gateway_mode_drops_records(self):
        w = Witness(gateway_mode=True, flush_interval=999999)
        w.record(mk_record())
        assert w.pending == 0


# ----------------------------------------------------------------
# 7. Signing edge cases
# ----------------------------------------------------------------
class TestSigningEdgeCases:
    def test_signing_deterministic(self):
        s1 = sign_payload("key", "fp123", "agent")
        s2 = sign_payload("key", "fp123", "agent")
        assert s1 == s2

    def test_signing_with_without_agent_id_differs(self):
        s1 = sign_payload("secret", "abc123def456")
        s2 = sign_payload("secret", "abc123def456", "agent-1")
        assert s1 != s2

    def test_unicode_signing_key(self):
        sig = sign_payload("\U0001F600\U0001F4A9", "abc123def456")
        assert len(sig) == 64

    def test_long_signing_key(self):
        sig = sign_payload("k" * 100_000, "abc123def456")
        assert len(sig) == 64

    def test_empty_signing_key(self):
        sig = sign_payload("", "abc123def456")
        assert len(sig) == 64
        assert re.match(r"^[0-9a-f]{64}$", sig)

    def test_null_bytes_in_key(self):
        sig = sign_payload("key\x00with\x00nulls", "abc123def456")
        assert len(sig) == 64


# ----------------------------------------------------------------
# 8. Decorator/wrapper abuse
# ----------------------------------------------------------------
class TestDecoratorAbuse:
    def test_wrap_tool_records_exception(self):
        w = mk_witness()

        @w.wrap_tool
        def boom():
            raise RuntimeError("kaboom")

        with pytest.raises(RuntimeError, match="kaboom"):
            boom()
        assert w.pending > 0

    def test_wrap_tool_preserves_return_value(self):
        w = mk_witness()
        obj = {"nested": [1, 2, 3]}

        @w.wrap_tool
        def identity():
            return obj

        result = identity()
        assert result is obj

    def test_wrap_access_records_denied(self):
        w = mk_witness()

        def restricted():
            raise PermissionError("403")

        wrapped = w.wrap_access(restricted, resource_name="secret-db", scope="read")
        with pytest.raises(PermissionError):
            wrapped()
        assert w.pending > 0


# ----------------------------------------------------------------
# 9. RAG/skill/model weight boundary inputs
# ----------------------------------------------------------------
class TestBoundaryInputs:
    def test_rag_empty_chunks(self):
        w = mk_witness()
        payloads = w.witness_rag_context(chunks=[])
        assert len(payloads) == 1
        assert payloads[0].factor_a == 0

    def test_rag_10k_chunks(self):
        w = mk_witness()
        chunks = [f"chunk {i}" for i in range(10_000)]
        payloads = w.witness_rag_context(chunks=chunks)
        assert payloads[0].factor_a == 10_000

    def test_rag_negative_similarity(self):
        w = mk_witness()
        payloads = w.witness_rag_context(
            chunks=[
                RagChunk(content_hash="a", similarity_score=-0.5),
                RagChunk(content_hash="b", similarity_score=-1.0),
            ],
            similarity_threshold=0.0,
        )
        rag2 = [p for p in payloads if p.procedure_id == "AI-RAG.2"]
        assert len(rag2) == 1
        assert rag2[0].factor_c == 2

    def test_skill_manifest_empty(self):
        w = mk_witness()
        p = w.witness_skill_manifest([])
        assert p.factor_a == 0

    def test_skill_manifest_duplicates(self):
        w = mk_witness()
        p = w.witness_skill_manifest(["search", "search", "search"])
        assert p.factor_a == 3

    def test_memory_context_empty(self):
        w = mk_witness()
        p = w.witness_memory_context([])
        assert p.factor_a == 0
        assert p.factor_b == 0

    def test_reward_model_empty_string(self):
        w = mk_witness()
        p = w.witness_reward_model("")
        assert p.factor_b == 0

    def test_reward_model_whitespace(self):
        w = mk_witness()
        p = w.witness_reward_model("   ")
        assert p.factor_b == 0

    def test_quantization_unknown_method(self):
        w = mk_witness()
        p = w.witness_quantization("totally_fake")
        assert p.factor_c == 0

    def test_adapter_stack_missing_hash(self):
        w = mk_witness()
        p = w.witness_adapter_stack(
            [AdapterInfo(name="lora-1", adapter_hash="aaa"),
             AdapterInfo(name="lora-2", adapter_hash="")],
        )
        assert p.factor_b == 0

    def test_model_weights_hash_mismatch(self):
        w = mk_witness()
        p = w.witness_model_weights(
            ModelWeightInfo(file_hash="actual_abc"),
            expected_hash="expected_xyz",
        )
        assert p.factor_b == 0


# ----------------------------------------------------------------
# 10. Gatekeeper bypass
# ----------------------------------------------------------------
class TestGatekeeperBypass:
    def test_blocks_insufficient_guardrails(self):
        w = mk_witness(guardrails_required=3, guardrail_names=["one", "two"])
        with pytest.raises(GatekeeperError):
            w.gate_check()
        assert w.pending > 0

    def test_passes_sufficient_guardrails(self):
        w = mk_witness(guardrails_required=2, guardrail_names=["one", "two"])
        fp = w.gate_check()
        assert len(fp) == 12

    def test_zero_required_always_passes(self):
        w = mk_witness(guardrails_required=0)
        fp = w.gate_check()
        assert len(fp) == 12

    def test_error_exposes_counts(self):
        w = mk_witness(guardrails_required=5, guardrail_names=["a"])
        with pytest.raises(GatekeeperError) as exc_info:
            w.gate_check()
        assert exc_info.value.required == 5
        assert exc_info.value.active == 1

    def test_error_does_not_leak_secrets(self):
        w = mk_witness(
            strict=True,
            guardrails_required=3,
            guardrail_names=["a"],
            signing_key="super_secret_key_do_not_leak",
        )
        with pytest.raises(GatekeeperError) as exc_info:
            w.gate_check()
        msg = str(exc_info.value)
        assert "super_secret" not in msg
        assert "axm_test_key" not in msg


# ----------------------------------------------------------------
# 11. Security scan edge cases
# ----------------------------------------------------------------
class TestSecurityScanEdgeCases:
    def test_negative_threat_score(self):
        w = mk_witness()
        w.witness_security_scan(-100)
        assert w.pending > 0

    def test_zero_threshold(self):
        w = mk_witness()
        w.witness_security_scan(1, threshold=0)
        assert w.pending > 0

    def test_unknown_threat_type(self):
        w = mk_witness()
        w.witness_security_scan(500, threat_type="cosmic_ray")
        assert w.pending > 0

    def test_input_validation_all_factor_c(self):
        w = mk_witness()
        w.witness_input_validation(True, sanitized=False)
        w.witness_input_validation(True, sanitized=True)
        w.witness_input_validation(False)
        assert w.pending == 3


# ----------------------------------------------------------------
# 12. SHA-256 utility edge cases
# ----------------------------------------------------------------
class TestSha256EdgeCases:
    def test_length_zero(self):
        assert sha256_hex("test", 0) == ""

    def test_length_over_64(self):
        assert len(sha256_hex("test", 128)) == 64

    def test_truncated_default_16(self):
        assert len(sha256_truncated("test")) == 16

    def test_empty_string_known_hash(self):
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_hex("") == expected


# ----------------------------------------------------------------
# 13. Procedure filtering
# ----------------------------------------------------------------
class TestProcedureFiltering:
    def test_empty_procedures_means_no_filter(self):
        # In Python, empty list is falsy so all procedures pass through
        record = mk_record()
        payloads = extract_payloads(record, "t", 1, procedures=[])
        assert len(payloads) > 0

    def test_nonexistent_procedure_no_payloads(self):
        record = mk_record()
        payloads = extract_payloads(record, "t", 1, procedures=["AI-FAKE.99"])
        assert len(payloads) == 0

    def test_single_procedure_returns_one(self):
        record = mk_record()
        payloads = extract_payloads(record, "t", 1, procedures=["AI-INF.1"])
        assert len(payloads) == 1
        assert payloads[0].procedure_id == "AI-INF.1"
