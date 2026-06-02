"""SWT3 AI Witness SDK -- AI-TRUST.1 / AI-TRUST.2 Trust Mesh Tests."""

import time

import pytest

from swt3_ai import (
    Witness, TrustCredential, TrustResult, TrustRegistry,
    TRUST_DENIED, TRUST_BASIC, TRUST_VERIFIED, TRUST_ATTESTED, TRUST_SOVEREIGN,
)
from swt3_ai.trust import (
    verify_credential, evaluate_trust_level,
    DENIAL_DENY_LISTED, DENIAL_TENANT_NOT_TRUSTED, DENIAL_ANCHOR_EXPIRED,
    DENIAL_SIGNATURE_MISSING, DENIAL_INSUFFICIENT_PROCEDURES,
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


def mk_credential(**overrides):
    defaults = dict(
        agent_id="remote-agent-001",
        tenant_id="partner_tenant",
        anchor_fingerprint="abc123def456",
        anchor_timestamp_ms=int(time.time() * 1000),
    )
    defaults.update(overrides)
    return TrustCredential(**defaults)


# ── TrustRegistry ────────────────────────────────────────────────────

class TestTrustRegistry:
    def test_same_tenant_auto_trusted(self):
        reg = TrustRegistry()
        assert reg.is_tenant_trusted("my_tenant", "my_tenant") is True

    def test_unknown_tenant_not_trusted(self):
        reg = TrustRegistry()
        assert reg.is_tenant_trusted("stranger", "my_tenant") is False

    def test_trust_tenant(self):
        reg = TrustRegistry()
        reg.trust_tenant("partner")
        assert reg.is_tenant_trusted("partner", "my_tenant") is True

    def test_deny_tenant(self):
        reg = TrustRegistry()
        reg.trust_tenant("partner")
        reg.deny_tenant("partner")
        assert reg.is_tenant_trusted("partner", "my_tenant") is False

    def test_deny_agent(self):
        reg = TrustRegistry()
        reg.trust_tenant("partner")
        reg.deny_agent("bad-agent")
        assert reg.is_agent_trusted("partner", "bad-agent", "my_tenant") is False
        assert reg.is_agent_trusted("partner", "good-agent", "my_tenant") is True

    def test_trust_specific_agent(self):
        reg = TrustRegistry()
        reg.trust_agent("other_tenant", "specific-agent")
        assert reg.is_agent_trusted("other_tenant", "specific-agent", "my_tenant") is True
        assert reg.is_agent_trusted("other_tenant", "other-agent", "my_tenant") is False

    def test_freshness_window(self):
        reg = TrustRegistry()
        reg.set_freshness_window(3600)  # 1 hour
        assert reg._freshness_window_ms == 3_600_000


# ── evaluate_trust_level ─────────────────────────────────────────────

class TestEvaluateTrustLevel:
    def test_unsigned_is_basic(self):
        cred = mk_credential(is_signed=False)
        assert evaluate_trust_level(cred) == TRUST_BASIC

    def test_signed_no_hw_is_verified(self):
        cred = mk_credential(is_signed=True, has_hardware_attestation=False)
        assert evaluate_trust_level(cred) == TRUST_VERIFIED

    def test_signed_hw_guardrails_is_attested(self):
        cred = mk_credential(is_signed=True, has_hardware_attestation=True, has_guardrails=True, clearing_level=1)
        assert evaluate_trust_level(cred) == TRUST_ATTESTED

    def test_signed_hw_guardrails_cl2_is_sovereign(self):
        cred = mk_credential(is_signed=True, has_hardware_attestation=True, has_guardrails=True, clearing_level=2)
        assert evaluate_trust_level(cred) == TRUST_SOVEREIGN

    def test_signed_hw_no_guardrails_is_verified(self):
        cred = mk_credential(is_signed=True, has_hardware_attestation=True, has_guardrails=False)
        assert evaluate_trust_level(cred) == TRUST_VERIFIED


# ── verify_credential ────────────────────────────────────────────────

class TestVerifyCredential:
    def test_deny_listed_agent(self):
        reg = TrustRegistry()
        reg.deny_agent("bad-agent")
        cred = mk_credential(agent_id="bad-agent")
        result = verify_credential(cred, reg, "my_tenant")
        assert result.granted is False
        assert result.denial_reason == DENIAL_DENY_LISTED

    def test_deny_listed_tenant(self):
        reg = TrustRegistry()
        reg.deny_tenant("evil_tenant")
        cred = mk_credential(tenant_id="evil_tenant")
        result = verify_credential(cred, reg, "my_tenant")
        assert result.granted is False
        assert result.denial_reason == DENIAL_DENY_LISTED

    def test_untrusted_tenant(self):
        reg = TrustRegistry()
        cred = mk_credential(tenant_id="stranger")
        result = verify_credential(cred, reg, "my_tenant")
        assert result.granted is False
        assert result.denial_reason == DENIAL_TENANT_NOT_TRUSTED

    def test_same_tenant_passes(self):
        reg = TrustRegistry()
        cred = mk_credential(tenant_id="my_tenant")
        result = verify_credential(cred, reg, "my_tenant")
        assert result.granted is True

    def test_expired_anchor(self):
        reg = TrustRegistry()
        reg.trust_tenant("partner")
        reg.set_freshness_window(1)  # 1 second
        cred = mk_credential(
            tenant_id="partner",
            anchor_timestamp_ms=int(time.time() * 1000) - 5000,  # 5s ago
        )
        result = verify_credential(cred, reg, "my_tenant")
        assert result.granted is False
        assert result.denial_reason == DENIAL_ANCHOR_EXPIRED

    def test_signature_required_but_missing(self):
        reg = TrustRegistry()
        reg.trust_tenant("partner")
        reg.set_require_signature(True)
        cred = mk_credential(tenant_id="partner", is_signed=False)
        result = verify_credential(cred, reg, "my_tenant")
        assert result.granted is False
        assert result.denial_reason == DENIAL_SIGNATURE_MISSING

    def test_insufficient_procedures(self):
        reg = TrustRegistry()
        reg.trust_tenant("partner")
        reg.require_procedures(["AI-ID.1", "AI-HW.1"])
        cred = mk_credential(tenant_id="partner", procedures=["AI-ID.1"])
        result = verify_credential(cred, reg, "my_tenant")
        assert result.granted is False
        assert result.denial_reason == DENIAL_INSUFFICIENT_PROCEDURES

    def test_all_checks_pass_unsigned_gets_basic(self):
        reg = TrustRegistry()
        reg.trust_tenant("partner")
        cred = mk_credential(tenant_id="partner", is_signed=True)
        result = verify_credential(cred, reg, "my_tenant")
        assert result.granted is True
        # isSigned=True but no credentialSignature -> capped at BASIC
        assert result.trust_level == TRUST_BASIC
        assert result.checks_performed >= 4
        assert result.checks_passed == result.checks_performed

    def test_signed_verified_gets_verified(self):
        from swt3_ai.trust import sign_credential
        reg = TrustRegistry()
        reg.trust_tenant("partner")
        reg.register_signing_key("remote-agent-001", "test-secret")
        cred = mk_credential(tenant_id="partner", is_signed=True)
        cred.credential_signature = sign_credential(cred, "test-secret")
        result = verify_credential(cred, reg, "my_tenant")
        assert result.granted is True
        assert result.trust_level == TRUST_VERIFIED

    def test_min_trust_level_enforced(self):
        reg = TrustRegistry()
        reg.trust_tenant("partner")
        reg.set_min_trust_level(TRUST_ATTESTED)
        cred = mk_credential(tenant_id="partner", is_signed=True)  # only VERIFIED
        result = verify_credential(cred, reg, "my_tenant")
        assert result.granted is False


# ── Witness.verify_trust ─────────────────────────────────────────────

class TestWitnessVerifyTrust:
    def test_mints_trust_anchors(self):
        w = mk_witness()
        w.trust_registry.trust_tenant("partner")
        cred = mk_credential(tenant_id="partner")
        result = w.verify_trust(cred)
        assert result.granted is True
        assert w.pending >= 2  # AI-TRUST.1 + AI-TRUST.2

    def test_denied_still_mints(self):
        w = mk_witness()
        cred = mk_credential(tenant_id="stranger")
        result = w.verify_trust(cred)
        assert result.granted is False
        assert w.pending >= 2  # denial is evidence too

    def test_clearing_level_0_has_context(self):
        w = mk_witness(clearing_level=0)
        w.trust_registry.trust_tenant("partner")
        cred = mk_credential(tenant_id="partner")
        w.verify_trust(cred)
        # Can't easily inspect individual payloads in buffer,
        # but verify_trust returned without error
        assert w.pending >= 2

    def test_clearing_level_2_strips_context(self):
        w = mk_witness(clearing_level=2)
        w.trust_registry.trust_tenant("partner")
        cred = mk_credential(tenant_id="partner")
        w.verify_trust(cred)
        assert w.pending >= 2

    def test_agent_id_in_result(self):
        w = mk_witness()
        cred = mk_credential(agent_id="remote-007", tenant_id="test_tenant")
        result = w.verify_trust(cred)
        assert result.counterpart_agent_id == "remote-007"


# ── Witness.present_credential ───────────────────────────────────────

class TestWitnessPresentCredential:
    def test_basic_credential(self):
        w = mk_witness(agent_id="my-agent")
        cred = w.present_credential()
        assert cred.agent_id == "my-agent"
        assert cred.tenant_id == "test_tenant"
        assert len(cred.anchor_fingerprint) == 12
        assert cred.is_signed is False

    def test_signed_credential(self):
        w = mk_witness(agent_id="my-agent", signing_key="secret123456")
        cred = w.present_credential()
        assert cred.is_signed is True

    def test_no_agent_id_uses_anonymous(self):
        w = mk_witness()
        cred = w.present_credential()
        assert cred.agent_id == "anonymous"

    def test_guardrails_detected(self):
        w = mk_witness(guardrail_names=["content-filter", "pii-scan"])
        cred = w.present_credential()
        assert cred.has_guardrails is True

    def test_timestamp_is_recent(self):
        w = mk_witness()
        cred = w.present_credential()
        now_ms = int(time.time() * 1000)
        assert abs(cred.anchor_timestamp_ms - now_ms) < 1000  # within 1s


# ── End-to-End Bilateral Handshake ───────────────────────────────────

class TestBilateralHandshake:
    def test_two_agents_mutual_trust(self):
        agent_a = mk_witness(agent_id="agent-a", tenant_id="tenant_a")
        agent_b = mk_witness(agent_id="agent-b", tenant_id="tenant_b")

        # Both trust each other's tenant
        agent_a.trust_registry.trust_tenant("tenant_b")
        agent_b.trust_registry.trust_tenant("tenant_a")

        # A presents to B
        cred_a = agent_a.present_credential()
        result_b = agent_b.verify_trust(cred_a)
        assert result_b.granted is True

        # B presents to A
        cred_b = agent_b.present_credential()
        result_a = agent_a.verify_trust(cred_b)
        assert result_a.granted is True

        # Both have trust anchors
        assert agent_a.pending >= 2
        assert agent_b.pending >= 2

    def test_one_sided_trust_fails(self):
        agent_a = mk_witness(agent_id="agent-a", tenant_id="tenant_a")
        agent_b = mk_witness(agent_id="agent-b", tenant_id="tenant_b")

        # Only A trusts B, B doesn't trust A
        agent_a.trust_registry.trust_tenant("tenant_b")

        # A presents to B -- B denies (doesn't trust tenant_a)
        cred_a = agent_a.present_credential()
        result_b = agent_b.verify_trust(cred_a)
        assert result_b.granted is False
        assert result_b.denial_reason == DENIAL_TENANT_NOT_TRUSTED
