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
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .fingerprint import sha256_truncated

logger = logging.getLogger("swt3_ai.trust")

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

    def trust_tenant(self, tenant_id: str) -> None:
        """Trust all agents from a tenant."""
        self._trusted_tenants.add(tenant_id)
        self._denied_tenants.discard(tenant_id)

    def trust_agent(self, tenant_id: str, agent_id: str) -> None:
        """Trust a specific agent from a specific tenant."""
        self._trusted_agents.add(f"{tenant_id}:{agent_id}")

    def deny_agent(self, agent_id: str) -> None:
        """Deny a specific agent regardless of tenant."""
        self._denied_agents.add(agent_id)

    def deny_tenant(self, tenant_id: str) -> None:
        """Deny all agents from a tenant."""
        self._denied_tenants.add(tenant_id)
        self._trusted_tenants.discard(tenant_id)

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

    def is_agent_denied(self, agent_id: str) -> bool:
        return agent_id in self._denied_agents

    def is_tenant_denied(self, tenant_id: str) -> bool:
        return tenant_id in self._denied_tenants

    def is_tenant_trusted(self, tenant_id: str, own_tenant_id: str) -> bool:
        """Check if a tenant is trusted (same tenant always trusted)."""
        if tenant_id == own_tenant_id:
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

    Checks performed:
      1. Deny list check
      2. Tenant trust check
      3. Anchor freshness check
      4. Signature requirement check
      5. Procedure requirement check

    Returns:
        TrustResult with granted status, trust level, and denial reason.
    """
    checks = 0
    passed = 0
    base = dict(
        counterpart_agent_id=credential.agent_id,
        counterpart_tenant_id=credential.tenant_id,
    )

    # Check 1: deny list
    checks += 1
    if registry.is_agent_denied(credential.agent_id):
        return TrustResult(granted=False, trust_level=TRUST_DENIED,
                           denial_reason=DENIAL_DENY_LISTED,
                           checks_performed=checks, checks_passed=passed, **base)
    if registry.is_tenant_denied(credential.tenant_id):
        return TrustResult(granted=False, trust_level=TRUST_DENIED,
                           denial_reason=DENIAL_DENY_LISTED,
                           checks_performed=checks, checks_passed=passed, **base)
    passed += 1

    # Check 2: tenant trust
    checks += 1
    if not registry.is_agent_trusted(credential.tenant_id, credential.agent_id, own_tenant_id):
        return TrustResult(granted=False, trust_level=TRUST_DENIED,
                           denial_reason=DENIAL_TENANT_NOT_TRUSTED,
                           checks_performed=checks, checks_passed=passed, **base)
    passed += 1

    # Check 3: anchor freshness
    checks += 1
    now_ms = int(time.time() * 1000)
    age_ms = now_ms - credential.anchor_timestamp_ms
    if age_ms > registry._freshness_window_ms:
        return TrustResult(granted=False, trust_level=TRUST_DENIED,
                           denial_reason=DENIAL_ANCHOR_EXPIRED,
                           checks_performed=checks, checks_passed=passed, **base)
    # Reject future-dated credentials (allow 60s clock skew)
    if credential.anchor_timestamp_ms > now_ms + 60_000:
        return TrustResult(granted=False, trust_level=TRUST_DENIED,
                           denial_reason=DENIAL_TIMESTAMP_FUTURE,
                           checks_performed=checks, checks_passed=passed, **base)
    passed += 1

    # Check 4: signing key presence
    checks += 1
    if registry._require_signature and not credential.is_signed:
        return TrustResult(granted=False, trust_level=TRUST_DENIED,
                           denial_reason=DENIAL_SIGNATURE_MISSING,
                           checks_performed=checks, checks_passed=passed, **base)
    passed += 1

    # Check 5: credential signature verification
    signature_verified = False
    if credential.credential_signature:
        checks += 1
        counterpart_key = registry.get_signing_key(credential.agent_id)
        if not counterpart_key:
            return TrustResult(granted=False, trust_level=TRUST_DENIED,
                               denial_reason=DENIAL_SIGNATURE_UNVERIFIABLE,
                               checks_performed=checks, checks_passed=passed, **base)
        if not verify_credential_signature(credential, counterpart_key):
            return TrustResult(granted=False, trust_level=TRUST_DENIED,
                               denial_reason=DENIAL_SIGNATURE_INVALID,
                               checks_performed=checks, checks_passed=passed, **base)
        signature_verified = True
        passed += 1

    # Check 6: procedure requirements
    if registry._required_procedures:
        checks += 1
        cred_procs = set(credential.procedures)
        if not all(p in cred_procs for p in registry._required_procedures):
            return TrustResult(granted=False, trust_level=TRUST_DENIED,
                               denial_reason=DENIAL_INSUFFICIENT_PROCEDURES,
                               checks_performed=checks, checks_passed=passed, **base)
        passed += 1

    # All checks passed -- compute trust level
    level = evaluate_trust_level(credential)

    # Cap: unsigned or unverifiable credentials cannot exceed TRUST_BASIC
    if not signature_verified and level > TRUST_BASIC:
        level = TRUST_BASIC

    # Check minimum trust level
    if level < registry._min_trust_level:
        return TrustResult(granted=False, trust_level=level,
                           denial_reason=DENIAL_INSUFFICIENT_TRUST_LEVEL,
                           checks_performed=checks, checks_passed=passed, **base)

    return TrustResult(
        granted=True, trust_level=level,
        checks_performed=checks, checks_passed=passed, **base,
    )
