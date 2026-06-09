"""SWT3 AI Witness SDK -- Agent Trust Mesh (AI-TRUST.1 / AI-TRUST.2).

Mutual compliance trust verification between AI agents. Before two agents
exchange data, invoke tools, or share context, each verifies the other's
SWT3 compliance anchor. No anchor, no handshake.

Architecture:
    - Out-of-band: trust verification does not sit in the inference path
    - Bilateral: both agents verify each other (mutual)
    - Evidence-producing: every handshake (pass or fail) mints anchors
    - Zero new dependencies: uses existing ledger verify endpoint

Trust levels (factor_c on AI-TRUST.1):
    0 = denied (verification failed)
    1 = basic (valid AI-ID.1, unsigned)
    2 = verified (valid AI-ID.1, signed)
    3 = attested (AI-ID.1 + AI-HW.1 + AI-GRD.1, signed)
    4 = sovereign (attested + clearing_level >= 2)

Denial reasons:
    anchor_not_found, anchor_expired, anchor_revoked,
    signature_missing, tenant_not_trusted, deny_listed
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .fingerprint import sha256_truncated

logger = logging.getLogger("swt3_ai.trust")


@dataclass
class DenyEvent:
    """Event emitted when an agent or tenant is denied."""

    type: str  # "agent" or "tenant"
    target: str
    reason: str
    timestamp: int


class _RateLimiter:
    """Sliding-window rate limiter for verification attempts."""

    def __init__(self, max_failures: int, window_ms: int) -> None:
        self._max_failures = max_failures
        self._window_ms = window_ms
        self._attempts: Dict[str, List[int]] = {}

    def is_exceeded(self, source: str) -> bool:
        now = int(time.time() * 1000)
        history = self._attempts.get(source)
        if not history:
            return False
        recent = [t for t in history if now - t < self._window_ms]
        self._attempts[source] = recent
        return len(recent) >= self._max_failures

    def record_failure(self, source: str) -> None:
        history = self._attempts.get(source, [])
        history.append(int(time.time() * 1000))
        self._attempts[source] = history

# Trust level constants
TRUST_DENIED = 0
TRUST_BASIC = 1
TRUST_VERIFIED = 2
TRUST_ATTESTED = 3
TRUST_SOVEREIGN = 4

TRUST_LEVEL_NAMES = {
    0: "denied",
    1: "basic",
    2: "verified",
    3: "attested",
    4: "sovereign",
}

# Denial reason codes
DENIAL_ANCHOR_NOT_FOUND = "anchor_not_found"
DENIAL_ANCHOR_EXPIRED = "anchor_expired"
DENIAL_ANCHOR_REVOKED = "anchor_revoked"
DENIAL_SIGNATURE_MISSING = "signature_missing"
DENIAL_TENANT_NOT_TRUSTED = "tenant_not_trusted"
DENIAL_DENY_LISTED = "deny_listed"
DENIAL_INSUFFICIENT_PROCEDURES = "insufficient_procedures"
DENIAL_SIGNATURE_INVALID = "signature_invalid"
DENIAL_SIGNATURE_UNVERIFIABLE = "signature_unverifiable"
DENIAL_INSUFFICIENT_TRUST_LEVEL = "insufficient_trust_level"
DENIAL_TIMESTAMP_FUTURE = "timestamp_future"
DENIAL_RATE_LIMITED = "rate_limited"


@dataclass
class TrustCredential:
    """Credential presented by an agent seeking trust verification."""

    agent_id: str
    tenant_id: str
    anchor_fingerprint: str
    anchor_timestamp_ms: int
    is_signed: bool = False
    procedures: List[str] = field(default_factory=list)
    clearing_level: int = 1
    has_hardware_attestation: bool = False
    has_guardrails: bool = False
    credential_signature: Optional[str] = None


@dataclass
class TrustResult:
    """Result of a trust verification attempt."""

    granted: bool
    trust_level: int  # 0-4
    denial_reason: Optional[str] = None
    checks_performed: int = 0
    checks_passed: int = 0
    counterpart_agent_id: str = ""
    counterpart_tenant_id: str = ""


class TrustRegistry:
    """Tenant-scoped registry of trusted agents and tenants.

    Maintains lists of trusted agent_ids, trusted tenants, and
    deny-listed agents. Queries are local (no network).

    Usage:
        registry = TrustRegistry()
        registry.trust_tenant("partner_tenant_id")
        registry.deny_agent("malicious_agent_id")
    """

    def __init__(self) -> None:
        self._trusted_tenants: Set[str] = set()
        self._trusted_agents: Set[str] = set()  # "tenant:agent_id" format
        self._denied_agents: Set[str] = set()
        self._denied_tenants: Set[str] = set()
        self._signing_keys: Dict[str, str] = {}
        self._required_procedures: List[str] = []
        self._freshness_window_ms: int = 24 * 60 * 60 * 1000  # 24 hours default
        self._require_signature: bool = False
        self._min_trust_level: int = TRUST_BASIC
        self._require_intra_tenant_signing: bool = False
        self._rate_limiter: Optional[_RateLimiter] = None
        self._per_level_freshness_ms: Optional[Dict[int, int]] = None
        self._verify_boolean_claims: bool = False
        self._deny_event_listeners: List[Any] = []

    def trust_tenant(self, tenant_id: str) -> None:
        """Trust all agents from a tenant."""
        self._trusted_tenants.add(tenant_id)
        self._denied_tenants.discard(tenant_id)

    def trust_agent(self, tenant_id: str, agent_id: str) -> None:
        """Trust a specific agent from a specific tenant."""
        self._trusted_agents.add(f"{tenant_id}:{agent_id}")

    def deny_agent(self, agent_id: str, reason: str = "manual") -> None:
        """Deny a specific agent regardless of tenant."""
        self._denied_agents.add(agent_id)
        self._emit_deny_event(DenyEvent(type="agent", target=agent_id, reason=reason, timestamp=int(time.time() * 1000)))

    def deny_tenant(self, tenant_id: str, reason: str = "manual") -> None:
        """Deny all agents from a tenant."""
        self._denied_tenants.add(tenant_id)
        self._trusted_tenants.discard(tenant_id)
        self._emit_deny_event(DenyEvent(type="tenant", target=tenant_id, reason=reason, timestamp=int(time.time() * 1000)))

    def register_signing_key(self, agent_id: str, key: str) -> None:
        """Register a counterpart agent's signing key for credential verification."""
        self._signing_keys[agent_id] = key

    def get_signing_key(self, agent_id: str) -> Optional[str]:
        """Get the registered signing key for an agent."""
        return self._signing_keys.get(agent_id)

    def require_procedures(self, procedures: List[str]) -> None:
        """Require counterpart to have specific procedure anchors."""
        self._required_procedures = procedures

    def set_freshness_window(self, seconds: int) -> None:
        """Set how recent a counterpart's anchor must be."""
        self._freshness_window_ms = seconds * 1000

    def set_require_signature(self, require: bool) -> None:
        """Require counterpart anchors to be signed."""
        self._require_signature = require

    def set_min_trust_level(self, level: int) -> None:
        """Set minimum trust level for access (0-4)."""
        self._min_trust_level = max(0, min(4, level))

    def set_require_intra_tenant_signing(self, require: bool) -> None:
        """When True, same-tenant agents must pass full verification (no auto-trust)."""
        self._require_intra_tenant_signing = require

    def set_rate_limit(self, max_failures: int, window_seconds: int) -> None:
        """Set per-agent failure rate limit."""
        self._rate_limiter = _RateLimiter(max_failures, window_seconds * 1000)

    def set_per_level_freshness(self, windows: Dict[int, int]) -> None:
        """Set per-trust-level freshness windows (seconds per level)."""
        self._per_level_freshness_ms = {level: secs * 1000 for level, secs in windows.items()}

    def set_verify_boolean_claims(self, verify: bool) -> None:
        """When True, boolean claims must be backed by matching procedures."""
        self._verify_boolean_claims = verify

    def on_deny_event(self, listener: Any) -> None:
        """Register a listener for deny events (sentinel integration point)."""
        self._deny_event_listeners.append(listener)

    def apply_revocation_event(self, event: Dict[str, Any]) -> None:
        """Apply an external revocation (e.g., from sentinel daemon)."""
        reason = event.get("reason", "revocation")
        if event.get("agent_id"):
            self._denied_agents.add(event["agent_id"])
            self._emit_deny_event(DenyEvent(type="agent", target=event["agent_id"], reason=reason, timestamp=int(time.time() * 1000)))
        if event.get("tenant_id"):
            self._denied_tenants.add(event["tenant_id"])
            self._trusted_tenants.discard(event["tenant_id"])
            self._emit_deny_event(DenyEvent(type="tenant", target=event["tenant_id"], reason=reason, timestamp=int(time.time() * 1000)))

    def is_agent_denied(self, agent_id: str) -> bool:
        return agent_id in self._denied_agents

    def is_tenant_denied(self, tenant_id: str) -> bool:
        return tenant_id in self._denied_tenants

    def is_tenant_trusted(self, tenant_id: str, own_tenant_id: str) -> bool:
        """Check if a tenant is trusted."""
        if tenant_id == own_tenant_id and not self._require_intra_tenant_signing:
            return True
        return tenant_id in self._trusted_tenants

    def is_agent_trusted(self, tenant_id: str, agent_id: str, own_tenant_id: str) -> bool:
        """Check if a specific agent is trusted."""
        if self.is_agent_denied(agent_id):
            return False
        if self.is_tenant_denied(tenant_id):
            return False
        if self.is_tenant_trusted(tenant_id, own_tenant_id):
            return True
        return f"{tenant_id}:{agent_id}" in self._trusted_agents

    def _emit_deny_event(self, event: DenyEvent) -> None:
        for listener in self._deny_event_listeners:
            listener(event)


def build_credential_message(credential: TrustCredential) -> str:
    """Build the deterministic message used for credential signing/verification.
    Formula is LOCKED for cross-language parity."""
    procs = ",".join(sorted(credential.procedures))
    is_signed = 1 if credential.is_signed else 0
    has_hw = 1 if credential.has_hardware_attestation else 0
    has_gr = 1 if credential.has_guardrails else 0
    cl = credential.clearing_level or 0
    return f"{credential.agent_id}:{credential.tenant_id}:{credential.anchor_fingerprint}:{credential.anchor_timestamp_ms}:{is_signed}:{has_hw}:{has_gr}:{cl}:{procs}"


def sign_credential(credential: TrustCredential, signing_key: str) -> str:
    """Sign a credential with HMAC-SHA256."""
    message = build_credential_message(credential)
    return hmac.new(
        signing_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_credential_signature(credential: TrustCredential, signing_key: str) -> bool:
    """Verify a credential signature against a known signing key."""
    if not credential.credential_signature:
        return False
    expected = sign_credential(credential, signing_key)
    return hmac.compare_digest(expected, credential.credential_signature)


def evaluate_trust_level(credential: TrustCredential) -> int:
    """Compute the trust level from a credential's metadata.

    Level 0: Denied (should not reach here -- caller handles denial)
    Level 1: Basic -- valid anchor, no signature
    Level 2: Verified -- valid anchor with signature
    Level 3: Attested -- signed + hardware + guardrails
    Level 4: Sovereign -- attested + clearing_level >= 2
    """
    if not credential.is_signed:
        return TRUST_BASIC

    # Signed -> at least Level 2
    if not credential.has_hardware_attestation or not credential.has_guardrails:
        return TRUST_VERIFIED

    # Signed + HW + guardrails -> at least Level 3
    if credential.clearing_level < 2:
        return TRUST_ATTESTED

    # Full sovereign
    return TRUST_SOVEREIGN


def verify_credential(
    credential: TrustCredential,
    registry: TrustRegistry,
    own_tenant_id: str,
) -> TrustResult:
    """Verify a counterpart agent's trust credential.

    Performs all verification checks and returns a TrustResult.
    Does NOT mint anchors -- the Witness method handles that.

    Returns:
        TrustResult with granted status, trust level, and denial reason.
    """
    checks = 0
    passed = 0
    base = dict(
        counterpart_agent_id=credential.agent_id,
        counterpart_tenant_id=credential.tenant_id,
    )

    def _denied(reason: str, record_rate_limit: bool = True) -> TrustResult:
        if record_rate_limit and registry._rate_limiter:
            registry._rate_limiter.record_failure(credential.agent_id)
        return TrustResult(granted=False, trust_level=TRUST_DENIED,
                           denial_reason=reason,
                           checks_performed=checks, checks_passed=passed, **base)

    # Check 0: rate limiting
    if registry._rate_limiter and registry._rate_limiter.is_exceeded(credential.agent_id):
        return _denied(DENIAL_RATE_LIMITED, record_rate_limit=False)

    # Check 1: deny list
    checks += 1
    if registry.is_agent_denied(credential.agent_id):
        return _denied(DENIAL_DENY_LISTED)
    if registry.is_tenant_denied(credential.tenant_id):
        return _denied(DENIAL_DENY_LISTED)
    passed += 1

    # Check 2: tenant trust
    checks += 1
    if not registry.is_agent_trusted(credential.tenant_id, credential.agent_id, own_tenant_id):
        return _denied(DENIAL_TENANT_NOT_TRUSTED)
    passed += 1

    # Check 3: anchor freshness (default window)
    checks += 1
    now_ms = int(time.time() * 1000)
    age_ms = now_ms - credential.anchor_timestamp_ms
    if age_ms > registry._freshness_window_ms:
        return _denied(DENIAL_ANCHOR_EXPIRED)
    # Reject future-dated credentials (allow 60s clock skew)
    if credential.anchor_timestamp_ms > now_ms + 60_000:
        return _denied(DENIAL_TIMESTAMP_FUTURE)
    passed += 1

    # Check 4: signing key presence
    checks += 1
    if registry._require_signature and not credential.is_signed:
        return _denied(DENIAL_SIGNATURE_MISSING)
    passed += 1

    # Check 5: credential signature verification
    signature_verified = False
    if credential.credential_signature:
        checks += 1
        counterpart_key = registry.get_signing_key(credential.agent_id)
        if not counterpart_key:
            return _denied(DENIAL_SIGNATURE_UNVERIFIABLE)
        if not verify_credential_signature(credential, counterpart_key):
            return _denied(DENIAL_SIGNATURE_INVALID)
        signature_verified = True
        passed += 1

    # Check 6: procedure requirements
    if registry._required_procedures:
        checks += 1
        cred_procs = set(credential.procedures)
        if not all(p in cred_procs for p in registry._required_procedures):
            return _denied(DENIAL_INSUFFICIENT_PROCEDURES)
        passed += 1

    # All checks passed -- compute trust level
    level = evaluate_trust_level(credential)

    # Cap: unsigned or unverifiable credentials cannot exceed TRUST_BASIC
    if not signature_verified and level > TRUST_BASIC:
        level = TRUST_BASIC

    # Check 7: per-level freshness (stricter windows for higher trust levels)
    if registry._per_level_freshness_ms:
        level_freshness = registry._per_level_freshness_ms.get(level)
        if level_freshness is not None and age_ms > level_freshness:
            return _denied(DENIAL_ANCHOR_EXPIRED)

    # Check 8: verifiable boolean claims (degrade, don't deny)
    if registry._verify_boolean_claims:
        cred_procs = set(credential.procedures)
        if credential.has_hardware_attestation and "AI-HW.1" not in cred_procs:
            level = TRUST_BASIC
        if credential.has_guardrails and not any(p.startswith("AI-GRD.") for p in cred_procs):
            level = TRUST_BASIC

    # Check minimum trust level
    if level < registry._min_trust_level:
        return _denied(DENIAL_INSUFFICIENT_TRUST_LEVEL)

    return TrustResult(
        granted=True, trust_level=level,
        checks_performed=checks, checks_passed=passed, **base,
    )


# ── Task 6: Key Attestation ──────────────────────────────────────────


@dataclass
class KeyAttestation:
    """Cryptographic binding of a public key to an anchor fingerprint."""

    agent_id: str
    public_key: str
    anchor_fingerprint: str
    anchor_timestamp_ms: int
    key_purpose: str = "signing"  # signing | encryption | delegation
    attestation_proof: str = ""


def generate_key_attestation(
    agent_id: str,
    public_key: str,
    anchor_fingerprint: str,
    anchor_timestamp_ms: int,
    signing_key: str,
    key_purpose: str = "signing",
) -> KeyAttestation:
    """Generate a key attestation binding a public key to an anchor fingerprint."""
    message = f"{agent_id}:{public_key}:{anchor_fingerprint}:{anchor_timestamp_ms}:{key_purpose}"
    proof = hmac.new(
        signing_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return KeyAttestation(
        agent_id=agent_id,
        public_key=public_key,
        anchor_fingerprint=anchor_fingerprint,
        anchor_timestamp_ms=anchor_timestamp_ms,
        key_purpose=key_purpose,
        attestation_proof=proof,
    )


def verify_key_attestation(attestation: KeyAttestation, signing_key: str) -> bool:
    """Verify a key attestation against a known signing key."""
    message = f"{attestation.agent_id}:{attestation.public_key}:{attestation.anchor_fingerprint}:{attestation.anchor_timestamp_ms}:{attestation.key_purpose}"
    expected = hmac.new(
        signing_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, attestation.attestation_proof)


def is_key_attestation_fresh(attestation: KeyAttestation, freshness_window_ms: int) -> bool:
    """Check if a key attestation's bound anchor is still fresh."""
    now_ms = int(time.time() * 1000)
    return (now_ms - attestation.anchor_timestamp_ms) <= freshness_window_ms


# ── Task 7: Challenge-Response Liveness ──────────────────────────────


@dataclass
class LivenessChallenge:
    """Challenge sent by a verifier to prove live key possession."""

    nonce: str
    challenge_timestamp_ms: int
    target_agent_id: str


@dataclass
class LivenessResponse:
    """Response to a liveness challenge, signed by the prover."""

    nonce: str
    challenge_timestamp_ms: int
    agent_id: str
    anchor_fingerprint: str
    response_signature: str


@dataclass
class LivenessResult:
    """Result of verifying a liveness response."""

    valid: bool
    reason: Optional[str] = None


def generate_challenge(target_agent_id: str) -> LivenessChallenge:
    """Generate a liveness challenge with a random 32-byte nonce."""
    nonce = os.urandom(32).hex()
    return LivenessChallenge(
        nonce=nonce,
        challenge_timestamp_ms=int(time.time() * 1000),
        target_agent_id=target_agent_id,
    )


def respond_to_challenge(
    challenge: LivenessChallenge,
    agent_id: str,
    anchor_fingerprint: str,
    signing_key: str,
) -> LivenessResponse:
    """Respond to a liveness challenge by signing the challenge data."""
    message = f"{agent_id}:{anchor_fingerprint}:{challenge.nonce}:{challenge.challenge_timestamp_ms}"
    signature = hmac.new(
        signing_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return LivenessResponse(
        nonce=challenge.nonce,
        challenge_timestamp_ms=challenge.challenge_timestamp_ms,
        agent_id=agent_id,
        anchor_fingerprint=anchor_fingerprint,
        response_signature=signature,
    )


def verify_liveness_response(
    response: LivenessResponse,
    challenge: LivenessChallenge,
    signing_key: str,
    timeout_ms: int = 5000,
) -> LivenessResult:
    """Verify a liveness response against the original challenge."""
    # Check nonce matches
    if response.nonce != challenge.nonce:
        return LivenessResult(valid=False, reason="nonce_mismatch")
    # Check timestamp matches
    if response.challenge_timestamp_ms != challenge.challenge_timestamp_ms:
        return LivenessResult(valid=False, reason="timestamp_mismatch")
    # Check agent matches target
    if response.agent_id != challenge.target_agent_id:
        return LivenessResult(valid=False, reason="agent_mismatch")
    # Check timeout
    elapsed = int(time.time() * 1000) - challenge.challenge_timestamp_ms
    if elapsed > timeout_ms:
        return LivenessResult(valid=False, reason="liveness_timeout")
    # Verify signature
    message = f"{response.agent_id}:{response.anchor_fingerprint}:{response.nonce}:{response.challenge_timestamp_ms}"
    expected = hmac.new(
        signing_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, response.response_signature):
        return LivenessResult(valid=False, reason="signature_invalid")
    return LivenessResult(valid=True)
