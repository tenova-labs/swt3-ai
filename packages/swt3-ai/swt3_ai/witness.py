"""SWT3 AI Witness SDK — Core Witness class.

Public API:
    from swt3_ai import Witness

    witness = Witness(
        endpoint="https://sovereign.tenova.io",
        api_key="axm_live_...",
        clearing_level=1,
    )

    # Adapter pattern — wrap the client, everything else is automatic
    client = witness.wrap(OpenAI())
    response = client.chat.completions.create(model="gpt-4o", messages=[...])

    # Manual decorator for custom pipelines
    @witness.inference()
    def my_pipeline(prompt: str) -> str: ...

    # Graceful shutdown
    receipts = witness.flush()
"""

from __future__ import annotations

import functools
import logging
import time
from typing import Any, Callable, Dict, List, Optional, TypeVar

from .types import (
    WitnessConfig, WitnessPayload, WitnessReceipt, InferenceRecord,
    RagChunk, ModelWeightInfo, AdapterInfo, SkillInfo, MemorySource,
    McpPolicyConfig, ChainPolicyViolation,
)
from .buffer import WitnessBuffer
from .clearing import extract_payloads, extract_revocation_payload, extract_chain_trust_degradation_payload, REVOCATION_REASONS, _apply_operational_metadata
from .fingerprint import sha256_truncated, mint_fingerprint, timestamp_ms
from .handoff import write_handoff_files

logger = logging.getLogger("swt3_ai")


# ── Chain Density Enforcement ──────────────────────────────────────────

import re as _re
import threading as _threading
from collections import deque as _deque


def _glob_to_regex(pattern: str) -> _re.Pattern:
    escaped = _re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return _re.compile("^" + escaped + "$")


def _parse_velocity(spec: str) -> tuple:
    parts = spec.split("/")
    limit = int(parts[0])
    window_s = int(parts[1].rstrip("s"))
    return limit, window_s


class PolicyViolationError(Exception):
    """Raised when a chain density policy rule blocks tool execution."""

    def __init__(self, violation: ChainPolicyViolation) -> None:
        super().__init__(f"Chain policy violation: {violation.reason}")
        self.violation = violation


class ChainEnforcer:
    """Chain density enforcement engine.

    Evaluates tool calls against rate limits, depth limits, allow/blocklists,
    and custom rules. All checks are in-memory, zero network calls.
    """

    def __init__(self, policy: McpPolicyConfig) -> None:
        self._velocity_limit = 0
        self._velocity_window_s = 0.0
        if policy.max_velocity:
            self._velocity_limit, ws = _parse_velocity(policy.max_velocity)
            self._velocity_window_s = float(ws)
        self._velocity_timestamps: _deque = _deque()
        self._max_chain_depth = policy.max_chain_depth if policy.max_chain_depth is not None else float("inf")
        self._allow_patterns = [_glob_to_regex(p) for p in policy.tool_allowlist] if policy.tool_allowlist else None
        self._block_patterns = [_glob_to_regex(p) for p in (policy.tool_blocklist or [])]
        self._fail_secure = policy.fail_secure
        self._custom_rules = [
            (r, _glob_to_regex(r.match)) for r in (policy.rules or [])
        ]
        self._chain_depth = 0
        self._last_tool_name: Optional[str] = None
        self._token_count = 0
        self._max_tokens_per_session = (
            policy.max_tokens_per_session if policy.max_tokens_per_session is not None else float("inf")
        )
        self._violations: list = []
        self._lock = _threading.Lock()

    def check(self, tool_name: str) -> Optional[ChainPolicyViolation]:
        now = time.monotonic()

        # 1. Blocklist
        for pattern in self._block_patterns:
            if pattern.match(tool_name):
                return self._violation("blocklist", tool_name, "blocked",
                    f'Tool "{tool_name}" is on the blocklist', now)

        # 2. Allowlist
        if self._allow_patterns is not None:
            if not any(p.match(tool_name) for p in self._allow_patterns):
                return self._violation("allowlist", tool_name, "blocked",
                    f'Tool "{tool_name}" is not on the allowlist', now)

        with self._lock:
            # 3. Velocity
            if self._velocity_limit > 0:
                cutoff = now - self._velocity_window_s
                while self._velocity_timestamps and self._velocity_timestamps[0] <= cutoff:
                    self._velocity_timestamps.popleft()
                if len(self._velocity_timestamps) >= self._velocity_limit:
                    action = "blocked" if self._fail_secure else "logged"
                    return self._violation("velocity", tool_name, action,
                        f"Rate limit exceeded: {self._velocity_limit} calls per {self._velocity_window_s}s", now,
                        {"current_count": len(self._velocity_timestamps), "limit": self._velocity_limit})
                self._velocity_timestamps.append(now)

            # 4. Depth
            if self._max_chain_depth < float("inf"):
                if tool_name != self._last_tool_name and self._last_tool_name is not None:
                    self._chain_depth = 0
                self._chain_depth += 1
                self._last_tool_name = tool_name
                if self._chain_depth > self._max_chain_depth:
                    action = "blocked" if self._fail_secure else "logged"
                    return self._violation("depth", tool_name, action,
                        f"Chain depth {self._chain_depth} exceeds max {int(self._max_chain_depth)}", now,
                        {"current_depth": self._chain_depth, "max_depth": int(self._max_chain_depth)})

            # 5. Token budget
            if self._max_tokens_per_session < float("inf") and self._token_count >= self._max_tokens_per_session:
                action = "blocked" if self._fail_secure else "logged"
                return self._violation("token_budget", tool_name, action,
                    f"Token budget exceeded: {self._token_count} tokens consumed, limit is {int(self._max_tokens_per_session)}",
                    now, {"current_tokens": self._token_count, "limit": int(self._max_tokens_per_session)})

        # 6. Custom rules
        for rule, regex in self._custom_rules:
            if regex.match(tool_name):
                return self._violation(
                    f"custom:{rule.reason}", tool_name,
                    "blocked" if rule.action == "block" else "logged",
                    rule.reason, now, rule.params or None)

        return None

    def reset_depth(self) -> None:
        with self._lock:
            self._chain_depth = 0
            self._last_tool_name = None

    def record_tokens(self, count: int) -> None:
        with self._lock:
            self._token_count += count

    def reset_tokens(self) -> None:
        with self._lock:
            self._token_count = 0

    @property
    def current_token_count(self) -> int:
        return self._token_count

    @property
    def violations(self) -> list:
        return list(self._violations)

    def clear_violations(self) -> None:
        self._violations.clear()

    def _violation(
        self, rule: str, tool_name: str, action: str,
        reason: str, timestamp: float, context: Optional[dict] = None,
    ) -> ChainPolicyViolation:
        v = ChainPolicyViolation(
            rule=rule, tool_name=tool_name, action=action,
            reason=reason, timestamp=timestamp,
            context=context or {},
        )
        self._violations.append(v)
        return v

F = TypeVar("F", bound=Callable[..., Any])

POLICY_CATEGORIES = {"unspecified": 0, "content": 1, "access": 2, "data": 3, "safety": 4, "regulatory": 5}
BINDING_METHODS = {"none": 0, "session": 1, "cryptographic": 2}
APPROVAL_STATUS = {"approved": 0, "pending": 1, "denied": 2}
PII_EVENT_TYPES = {"unspecified": 0, "pseudonymization": 1, "anonymization": 2, "access_restriction": 3, "deletion": 4, "encryption": 5}
CONTENT_TYPE_CODES: Dict[str, int] = {"text": 0, "image": 1, "audio": 2, "video": 3, "multimodal": 4, "code": 5, "structured_data": 6}
MARKING_METHODS = ("c2pa", "watermark", "metadata_tag", "steganographic", "manifest")
BASELINE_MODE_CODES: Dict[str, int] = {"establishing": 0, "monitoring": 1, "drift_detected": 2, "baseline_reset": 3}
LICENSE_TYPE_CODES: Dict[str, int] = {"permissive": 0, "copyleft": 1, "proprietary": 2, "dual": 3, "openmdw": 4, "unknown": 5}
SBOM_FORMAT_CODES: Dict[str, int] = {"cyclonedx": 0, "spdx": 1, "custom": 2, "unknown": 3}
REDTEAM_CATEGORY_CODES: Dict[str, int] = {"prompt_injection": 0, "jailbreak": 1, "data_poisoning": 2, "model_extraction": 3, "membership_inference": 4, "adversarial_examples": 5, "supply_chain": 6, "denial_of_service": 7, "output_manipulation": 8, "privilege_escalation": 9, "comprehensive": 10}
CONSENT_BASIS_CODES: Dict[str, int] = {"consent": 0, "contract": 1, "legal_obligation": 2, "vital_interest": 3, "public_task": 4, "legitimate_interest": 5}
DRIFT_TYPE_CODES: Dict[str, int] = {"data": 0, "concept": 1, "prediction": 2, "feature": 3, "label": 4, "prior_probability": 5}
LOG_FORMAT_CODES: Dict[str, int] = {"jsonl": 0, "syslog": 1, "otel": 2, "custom": 3}
INCIDENT_SEVERITY_CODES: Dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
INCIDENT_TYPE_CODES: Dict[str, int] = {"safety": 0, "rights": 1, "security": 2, "performance": 3, "bias": 4, "other": 5}
BENCHMARK_TYPE_CODES: Dict[str, int] = {"accuracy": 0, "precision": 1, "recall": 2, "f1": 3, "auc": 4, "custom": 5}
PERTURBATION_TYPE_CODES: Dict[str, int] = {"noise": 0, "corruption": 1, "missing_data": 2, "out_of_distribution": 3, "edge_case": 4, "adversarial_input": 5}
CYBER_FRAMEWORK_CODES: Dict[str, int] = {"nist_csf": 0, "iso27001": 1, "owasp": 2, "cis": 3, "custom": 4}
DISCLOSURE_TYPE_CODES: Dict[str, int] = {"ai_usage": 0, "data_processing": 1, "automated_decision": 2, "profiling": 3, "capability_limitation": 4}
RECIPIENT_TYPE_CODES: Dict[str, int] = {"deployer": 0, "end_user": 1, "data_subject": 2, "authority": 3}
DETECTION_METHOD_CODES: Dict[str, int] = {"c2pa_verify": 0, "synthid_check": 1, "metadata_scan": 2, "spectral_analysis": 3, "classifier": 4}
PROCESSING_TYPE_CODES: Dict[str, int] = {"profiling": 0, "automated_decision": 1, "large_scale_monitoring": 2, "sensitive_data": 3, "combined": 4}
DECISION_TYPE_CODES: Dict[str, int] = {"credit": 0, "employment": 1, "insurance": 2, "benefits": 3, "legal": 4, "other": 5}
CLASSIFICATION_CODES: Dict[str, int] = {"standard": 0, "dual_use": 1, "high_impact": 2}
REPORTING_STATUS_CODES: Dict[str, int] = {"not_required": 0, "pending": 1, "notified": 2, "acknowledged": 3}
SUPPLY_RISK_CODES: Dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
PMM_TYPE_CODES: Dict[str, int] = {"performance": 0, "fairness": 1, "safety": 2, "security": 3, "comprehensive": 4}


class GatekeeperError(Exception):
    """Raised when strict mode blocks an inference due to insufficient guardrails.

    Attributes:
        required: Number of guardrails required by policy.
        active: Number of guardrails active at call time.
        missing_names: Guardrail names required but not configured.
    """

    def __init__(
        self,
        required: int,
        active: int,
        missing_names: Optional[List[str]] = None,
    ) -> None:
        self.required = required
        self.active = active
        self.missing_names = missing_names or []
        msg = f"Gatekeeper blocked: {active} guardrails active, {required} required"
        if self.missing_names:
            msg += f". Missing: {', '.join(self.missing_names)}"
        super().__init__(msg)


class ChainTrustError(Exception):
    """Raised when a chain handoff would drop effective trust below the minimum.

    Attributes:
        effective_trust_level: The computed effective (minimum) trust level.
        minimum_required: The configured minimum acceptable trust level.
    """

    def __init__(self, effective: int, minimum: int) -> None:
        self.effective_trust_level = effective
        self.minimum_required = minimum
        super().__init__(
            f"Chain trust blocked: effective level {effective} below minimum {minimum}"
        )


class Witness:
    """SWT3 AI Witness -- cryptographic attestation for AI inference.

    The Witness observes AI inferences, extracts compliance factors,
    applies clearing, and anchors evidence to the SWT3 ledger.

    Create from a .swt3.yaml config file:

        witness = Witness.from_config()              # auto-finds .swt3.yaml
        witness = Witness.from_config("prod.yaml")   # explicit path
        witness = Witness.from_config(clearing_level=3)  # override

    By default, anchoring happens in a background thread (non-blocking).
    When ``strict=True`` (gatekeeper mode), the Witness checks guardrail
    requirements BEFORE each inference and raises ``GatekeeperError`` if
    the configured policy is not met. The inference never reaches the model.
    """

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        tenant_id: str = "",
        clearing_level: int = 1,
        *,
        buffer_size: int = 10,
        flush_interval: float = 5.0,
        timeout: float = 10.0,
        max_retries: int = 3,
        latency_threshold_ms: int = 30000,
        guardrails_required: int = 0,
        guardrail_names: Optional[List[str]] = None,
        procedures: Optional[List[str]] = None,
        factor_handoff: Optional[str] = None,
        factor_handoff_path: Optional[str] = None,
        agent_id: Optional[str] = None,
        signing_key: Optional[str] = None,
        signing_key_id: Optional[str] = None,
        signing_key_version: Optional[int] = None,
        signing_algorithm: Optional[str] = None,
        cycle_id: Optional[str] = None,
        strict: bool = False,
        policy_version: Optional[str] = None,
        jurisdiction: Optional[str] = None,
        legal_basis: Optional[str] = None,
        purpose_class: Optional[str] = None,
        on_flush: Optional[Callable] = None,
        gateway_mode: bool = False,
        token_budget: Optional[int] = None,
        flush_target: Optional[str] = None,
        redis_url: Optional[str] = None,
        redis_stream: Optional[str] = None,
        wal_path: Optional[str] = None,
        replay_window: Optional[int] = None,
        chain_min_trust_level: Optional[int] = None,
        on_violation: Optional[Callable] = None,
    ) -> None:
        self._gateway_mode = gateway_mode

        # Gateway mode: SDK defers all witnessing to the SWT3 Gateway.
        # No endpoint, API key, or buffer needed.
        if gateway_mode:
            self._config = WitnessConfig(
                endpoint=endpoint or "unused",
                api_key=api_key or "axm_gateway",
                clearing_level=clearing_level,
                buffer_size=1,
                flush_interval=86400,
                timeout=timeout,
                max_retries=0,
                procedures=procedures,
                agent_id=agent_id,
                signing_key=signing_key,
                signing_key_id=signing_key_id,
                signing_key_version=signing_key_version,
                signing_algorithm=signing_algorithm,
                cycle_id=cycle_id,
                policy_version=policy_version,
                jurisdiction=jurisdiction,
                legal_basis=legal_basis,
                purpose_class=purpose_class,
            )
            # Initialize a real buffer (thread starts but never fires since
            # record() returns early and flush_interval is 24h)
            self._buffer = WitnessBuffer(self._config)
            self._latency_threshold_ms = latency_threshold_ms
            self._guardrails_required = guardrails_required
            self._guardrail_names = guardrail_names or []
            self._strict = strict
            self._tenant_id = tenant_id or "GATEWAY"
            return

        # Validate required args (non-gateway mode)
        if not endpoint:
            raise ValueError("endpoint is required (or set gateway_mode=True)")
        if not api_key:
            raise ValueError("api_key is required (or set gateway_mode=True)")

        # Validate handoff config
        if factor_handoff and factor_handoff != "file":
            raise ValueError("factor_handoff must be 'file'")
        if factor_handoff == "file" and not factor_handoff_path:
            raise ValueError("factor_handoff_path is required when factor_handoff='file'")

        self._config = WitnessConfig(
            endpoint=endpoint,
            api_key=api_key,
            clearing_level=clearing_level,
            buffer_size=buffer_size,
            flush_interval=flush_interval,
            timeout=timeout,
            max_retries=max_retries,
            procedures=procedures,
            factor_handoff=factor_handoff,
            factor_handoff_path=factor_handoff_path,
            agent_id=agent_id,
            signing_key=signing_key,
            signing_key_id=signing_key_id,
            signing_key_version=signing_key_version,
            signing_algorithm=signing_algorithm,
            cycle_id=cycle_id,
            policy_version=policy_version,
            jurisdiction=jurisdiction,
            legal_basis=legal_basis,
            purpose_class=purpose_class,
            token_budget=token_budget,
            chain_min_trust_level=chain_min_trust_level,
            flush_target=flush_target,
            redis_url=redis_url,
            redis_stream=redis_stream,
        )
        # WAL: crash-resilient buffer persistence + replay protection (patent pending)
        self._wal_path = wal_path
        wal = None
        if wal_path:
            from .wal import WriteAheadLog
            wal_kwargs = {"wal_dir": wal_path}
            if replay_window is not None:
                wal_kwargs["replay_window"] = replay_window
            wal = WriteAheadLog(tenant_id, **wal_kwargs)

        self._buffer = WitnessBuffer(self._config, on_flush=on_flush, wal=wal)

        # Recover unflushed payloads from a previous crash
        if wal is not None:
            recovered = wal.recover()
            if recovered:
                self._buffer.enqueue_many(recovered)

        self._latency_threshold_ms = latency_threshold_ms
        self._guardrails_required = guardrails_required
        self._guardrail_names = guardrail_names or []
        self._strict = strict
        self._chain_trust_levels: List[int] = []
        self._on_violation = on_violation
        if not tenant_id:
            raise ValueError("tenant_id is required (e.g., 'MY_ENCLAVE')")
        self._tenant_id = tenant_id
        self._sentinel = None  # SentinelClient, set by from_config or connect_sentinel

    @classmethod
    def from_config(cls, path: Optional[str] = None, **overrides: Any) -> "Witness":
        """Create a Witness from a .swt3.yaml config file.

        Auto-configures the TrustRegistry from the trust_mesh section,
        triggers hardware attestation if configured, and stores the
        config hash for trust handshake exchange.

        Args:
            path: Explicit path to YAML file. If None, searches for
                  swt3.yaml or .swt3.yaml in the current directory.
            **overrides: Override any field from the YAML file.
                         Code takes precedence over config file.

        Returns:
            Configured Witness instance.

        Requires: ``pip install pyyaml`` (or ``pip install swt3-ai[yaml]``)
        """
        from .config import load_full_config, validate_policy
        loaded = load_full_config(path)
        kwargs = loaded.witness_kwargs
        kwargs.update(overrides)

        # Re-validate policy AFTER overrides to prevent silent downgrades
        if loaded.policy and overrides:
            validate_policy(kwargs, loaded.policy)

        witness = cls(**kwargs)

        witness._config_hash = loaded.config_hash

        if loaded.trust_mesh:
            witness._configure_trust_mesh(loaded.trust_mesh)

        if loaded.hardware:
            witness._hardware_config = loaded.hardware
            if loaded.hardware.require_attestation:
                witness.witness_hardware()
            if loaded.hardware.runtime_profile and hasattr(witness, "_last_hw_snapshot"):
                witness._validate_runtime_profile(loaded.hardware.runtime_profile, witness._last_hw_snapshot)

        if loaded.skill_card and loaded.skill_card.skills:
            witness.witness_skill_manifest(
                loaded.skill_card.skills,
                expected_manifest_hash=loaded.skill_card.expected_manifest_hash,
            )

        if loaded.density_policy:
            witness._density_policy = loaded.density_policy

        if loaded.mcp_policy:
            witness._mcp_policy = loaded.mcp_policy
            p = loaded.mcp_policy
            if (p.max_velocity or p.max_chain_depth is not None
                    or p.max_tokens_per_session is not None
                    or p.tool_allowlist or p.tool_blocklist or p.rules):
                witness._chain_enforcer = ChainEnforcer(p)

        if loaded.merkle:
            witness._merkle_config = loaded.merkle

        # Fire-and-forget sentinel auto-detection (patent pending).
        # Non-blocking: <10ms probe in a background thread.
        # If daemon is running, wrap_tool/record_session_tokens will mirror to it.
        # If not, SDK operates standalone as before.
        witness._detect_sentinel_async()

        return witness

    def connect_sentinel(self, socket_path: Optional[str] = None) -> bool:
        """Connect to a running swt3-sentinel daemon.

        When connected, chain enforcement and token budget operations are
        mirrored to the isolated daemon for cross-process shared state.
        If the daemon is not running, returns False and the SDK continues
        with local enforcement.

        This method is called automatically by from_config() in
        fire-and-forget mode. You only need to call it explicitly if you
        want to confirm the connection or use a custom socket path.
        """
        try:
            from .sentinel_client import SentinelClient
            client = SentinelClient.detect(socket_path)
            if client is not None:
                self._sentinel = client
                return True
        except Exception:
            pass
        return False

    def _detect_sentinel_async(self) -> None:
        """Fire-and-forget sentinel detection in a background thread."""
        import threading
        t = threading.Thread(target=self.connect_sentinel, daemon=True)
        t.start()

    @property
    def sentinel(self):
        """Connected sentinel daemon client (None if no daemon detected)."""
        return self._sentinel

    @property
    def config_hash(self) -> Optional[str]:
        """SHA-256 hash of the config file used to construct this Witness."""
        return getattr(self, "_config_hash", None)

    @property
    def chain_enforcer(self) -> Optional[ChainEnforcer]:
        """Chain density enforcer (created when chain density fields are configured)."""
        return getattr(self, "_chain_enforcer", None)

    def record_session_tokens(self, count: int) -> None:
        """Record token usage against the chain enforcer's session budget."""
        enforcer = getattr(self, "_chain_enforcer", None)
        if enforcer is not None:
            enforcer.record_tokens(count)
        # Mirror to sentinel for cross-process shared budget
        sentinel = getattr(self, "_sentinel", None)
        if sentinel is not None and sentinel.connected:
            try:
                sentinel.record_tokens(count)
            except Exception:
                pass

    @property
    def on_violation(self) -> Optional[Callable]:
        """Get or set the violation callback."""
        return self._on_violation

    @on_violation.setter
    def on_violation(self, cb: Optional[Callable]) -> None:
        self._on_violation = cb

    def _fire_violation(self, violation: ChainPolicyViolation) -> None:
        if self._on_violation:
            try:
                self._on_violation(violation)
            except Exception:
                logger.debug("onViolation callback threw", exc_info=True)

    def _record_chain_violation(self, violation: ChainPolicyViolation) -> None:
        record = InferenceRecord(
            model_id=violation.tool_name,
            model_hash=sha256_truncated(violation.tool_name),
            prompt_hash=sha256_truncated(violation.rule),
            response_hash=sha256_truncated(violation.reason),
            latency_ms=0,
            provider="chain-enforcer",
            has_refusal=True,
            tool_name=violation.tool_name,
            tool_call_id=f"chain-{violation.timestamp}",
        )
        self.record(record)
        self._fire_violation(violation)

    def _configure_trust_mesh(self, mesh: Any) -> None:
        """Auto-configure TrustRegistry from a TrustMeshConfig."""
        from .trust import TrustRegistry
        registry = self.trust_registry

        for t in mesh.trusted_tenants:
            registry.trust_tenant(t)
        for ta in mesh.trusted_agents:
            registry.trust_agent(ta["tenant"], ta["agent"])
        for a in mesh.deny_agents:
            registry.deny_agent(a)
        for t in mesh.deny_tenants:
            registry.deny_tenant(t)

        registry.set_require_signature(mesh.require_signature)
        registry.set_min_trust_level(mesh.min_trust_level)
        registry.set_freshness_window(mesh.freshness_window)
        if mesh.required_procedures:
            registry.require_procedures(mesh.required_procedures)
        for sk in mesh.signing_keys:
            registry.register_signing_key(sk["agent"], sk["key"])

        if mesh.mode == "strict" and not mesh.require_signature:
            registry.set_require_signature(True)

    _witnessed_procedures: set

    def _mint_and_sign(self, procedure_id: str, fa: float, fb: float, fc: float) -> WitnessPayload:
        """Mint a fingerprint, build a base payload, and apply operational metadata.

        Consolidates the repeated boilerplate across all standalone witness methods:
        timestamp, fingerprint, payload construction, policy hash, signing, CJT fields.
        """
        if not hasattr(self, "_witnessed_procedures"):
            self._witnessed_procedures = set()
        self._witnessed_procedures.add(procedure_id)
        ts_ms, ep = timestamp_ms()
        fp = mint_fingerprint(self._tenant_id, procedure_id, fa, fb, fc, ts_ms)
        policy_hash = (
            sha256_truncated(self._config.policy_version, 12)
            if self._config.policy_version else None
        )
        payload = WitnessPayload(
            procedure_id=procedure_id,
            factor_a=fa, factor_b=fb, factor_c=fc,
            clearing_level=self._config.clearing_level,
            anchor_fingerprint=fp,
            anchor_epoch=ep,
            fingerprint_timestamp_ms=ts_ms,
        )
        _apply_operational_metadata(
            payload, agent_id=self._config.agent_id, cycle_id=self._config.cycle_id,
            signing_key=self._config.signing_key, signing_key_id=self._config.signing_key_id,
            signing_key_version=self._config.signing_key_version,
            signing_algorithm=self._config.signing_algorithm,
            policy_version_hash=policy_hash,
            jurisdiction=self._config.jurisdiction, legal_basis=self._config.legal_basis,
            purpose_class=self._config.purpose_class,
        )
        return payload

    def wrap(self, client: Any) -> Any:
        """Wrap an AI client with transparent witnessing.

        Supported clients:
            - openai.OpenAI / openai.AsyncOpenAI (auto-detected)
            - Ollama via OpenAI client with base_url :11434 (auto-detected)
            - anthropic.Anthropic / anthropic.AsyncAnthropic (auto-detected)
            - boto3 BedrockRuntimeClient (auto-detected)
            - litellm module (auto-detected)
            - vLLM via wrap_vllm() (explicit -- port 8000 too generic)
            - LangChain via SWT3CallbackHandler (callback, not proxy)

        Returns a proxy that behaves identically to the original client
        but silently witnesses every inference.
        """
        # Module-level detection (litellm is passed as the module itself)
        if hasattr(client, "__name__") and "litellm" in getattr(client, "__name__", ""):
            from .adapters.litellm import wrap_litellm
            return wrap_litellm(client, self)

        client_type = type(client).__module__

        if "openai" in client_type:
            # Check for Ollama before defaulting to OpenAI
            from .adapters.ollama import is_ollama_client
            if is_ollama_client(client):
                from .adapters.ollama import wrap_ollama
                return wrap_ollama(client, self)
            from .adapters.openai import wrap_openai
            return wrap_openai(client, self)

        if "anthropic" in client_type:
            from .adapters.anthropic import wrap_anthropic
            return wrap_anthropic(client, self)

        if "botocore" in client_type or "bedrock" in client_type.lower():
            from .adapters.bedrock import wrap_bedrock
            return wrap_bedrock(client, self)

        raise TypeError(
            f"Unsupported client type: {type(client).__name__}. "
            f"Supported: openai.OpenAI, Ollama (via OpenAI), anthropic.Anthropic, "
            f"boto3 BedrockRuntimeClient, litellm, vLLM (via wrap_vllm)."
        )

    def gate_check(self, messages: Any = None, model: str = "unknown") -> str:
        """Pre-call guardrail gate (strict mode only).

        Evaluates whether configured guardrail requirements are met BEFORE
        the inference call reaches the AI model. If requirements are not met,
        raises ``GatekeeperError`` and mints an AI-GRD.3 anchor recording
        the rejection. The rejection is evidence — it is enqueued for flush
        like any other anchor.

        This method is SYNCHRONOUS — it evaluates local config only, no network.
        """
        required = self._guardrails_required
        active = len(self._guardrail_names)
        gate_passed = active >= required

        # Mint AI-GRD.3 anchor regardless of outcome — rejection is evidence
        from .clearing import extract_gatekeeper_payload
        policy_hash = (
            sha256_truncated(self._config.policy_version, 12)
            if self._config.policy_version else None
        )
        payload = extract_gatekeeper_payload(
            tenant_id=self._tenant_id,
            required=required,
            active=active,
            gate_passed=gate_passed,
            clearing_level=self._config.clearing_level,
            agent_id=self._config.agent_id,
            signing_key=self._config.signing_key,
            signing_algorithm=self._config.signing_algorithm,
            cycle_id=self._config.cycle_id,
            policy_version_hash=policy_hash,
            jurisdiction=self._config.jurisdiction,
            legal_basis=self._config.legal_basis,
            purpose_class=self._config.purpose_class,
        )
        self._buffer.enqueue_many([payload])

        if not gate_passed:
            raise GatekeeperError(required, active)

        return payload.anchor_fingerprint

    def inference(
        self,
        procedure_ids: Optional[List[str]] = None,
    ) -> Callable[[F], F]:
        """Decorator for witnessing custom inference functions.

        Usage:
            @witness.inference()
            def my_llm_call(prompt: str) -> str:
                # Your custom LLM logic
                return result

        The decorated function must accept a `prompt` string as its first
        argument and return a string response. For more control, use
        `witness.record()` directly.
        """
        def decorator(fn: F) -> F:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                prompt = args[0] if args else kwargs.get("prompt", "")
                prompt_str = str(prompt) if prompt else ""

                start = time.monotonic()
                result = fn(*args, **kwargs)
                elapsed_ms = int((time.monotonic() - start) * 1000)

                response_str = str(result) if result else ""

                record = InferenceRecord(
                    model_id="custom",
                    model_hash=sha256_truncated("custom"),
                    prompt_hash=sha256_truncated(prompt_str),
                    response_hash=sha256_truncated(response_str),
                    latency_ms=elapsed_ms,
                    provider="custom",
                )

                self.record(record, procedures=procedure_ids)
                return result

            return wrapper  # type: ignore[return-value]
        return decorator

    def wrap_tool(
        self,
        fn: Optional[F] = None,
        *,
        tool_name: Optional[str] = None,
    ) -> Any:
        """Wrap a function as a witnessed tool call (AI-TOOL.1).

        Can be used as a decorator or as a wrapper:
            @witness.wrap_tool(tool_name="search_db")
            def search(query: str) -> str: ...

            # Or:
            wrapped = witness.wrap_tool(my_fn, tool_name="search_db")

        Each call mints an AI-TOOL.1 anchor with:
            factor_a = 1 (tool was called)
            factor_b = latency_ms
            factor_c = 1 if succeeded, 0 if exception raised
        """
        import asyncio
        import uuid

        def decorator(func: F) -> F:
            name = tool_name or getattr(func, "__name__", "anonymous")

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Chain density enforcement -- BEFORE execution.
                # Local enforcer runs synchronously (fast path).
                enforcer = getattr(self, "_chain_enforcer", None)
                if enforcer is not None:
                    violation = enforcer.check(name)
                    if violation is not None:
                        if violation.action == "blocked":
                            self._fire_violation(violation)
                            raise PolicyViolationError(violation)
                        self._record_chain_violation(violation)
                # Mirror to sentinel for cross-process state (fire-and-forget).
                sentinel = getattr(self, "_sentinel", None)
                if sentinel is not None and sentinel.connected:
                    try:
                        sentinel.check(name)
                    except Exception:
                        pass

                call_id = uuid.uuid4().hex[:12]
                start = time.monotonic()
                succeeded = True
                result = None
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception:
                    succeeded = False
                    raise
                finally:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    input_hash = sha256_truncated(str(args) + str(kwargs))
                    output_hash = sha256_truncated(
                        str(result) if succeeded else "ERROR"
                    )
                    record = InferenceRecord(
                        model_id=name,
                        model_hash=sha256_truncated(name),
                        prompt_hash=input_hash,
                        response_hash=output_hash,
                        latency_ms=elapsed_ms,
                        provider="tool",
                        has_refusal=not succeeded,
                        tool_name=name,
                        tool_call_id=call_id,
                    )
                    self.record(record)

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Chain density enforcement -- BEFORE execution.
                enforcer = getattr(self, "_chain_enforcer", None)
                if enforcer is not None:
                    violation = enforcer.check(name)
                    if violation is not None:
                        if violation.action == "blocked":
                            self._fire_violation(violation)
                            raise PolicyViolationError(violation)
                        self._record_chain_violation(violation)
                # Mirror to sentinel for cross-process state (fire-and-forget).
                sentinel = getattr(self, "_sentinel", None)
                if sentinel is not None and sentinel.connected:
                    try:
                        sentinel.check(name)
                    except Exception:
                        pass

                call_id = uuid.uuid4().hex[:12]
                start = time.monotonic()
                succeeded = True
                result = None
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception:
                    succeeded = False
                    raise
                finally:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    input_hash = sha256_truncated(str(args) + str(kwargs))
                    output_hash = sha256_truncated(
                        str(result) if succeeded else "ERROR"
                    )
                    record = InferenceRecord(
                        model_id=name,
                        model_hash=sha256_truncated(name),
                        prompt_hash=input_hash,
                        response_hash=output_hash,
                        latency_ms=elapsed_ms,
                        provider="tool",
                        has_refusal=not succeeded,
                        tool_name=name,
                        tool_call_id=call_id,
                    )
                    self.record(record)

            if asyncio.iscoroutinefunction(func):
                return async_wrapper  # type: ignore[return-value]
            return sync_wrapper  # type: ignore[return-value]

        if fn is not None:
            return decorator(fn)
        return decorator

    def wrap_access(
        self,
        fn: Optional[F] = None,
        *,
        resource_name: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Any:
        """Wrap a function as a witnessed access attempt (AI-ACC.1).

        Can be used as a decorator or as a wrapper:
            @witness.wrap_access(resource_name="prod-db", scope="read-only")
            def query(sql: str) -> list: ...

            # Or:
            wrapped = witness.wrap_access(my_fn, resource_name="api-gateway")

        Each call mints an AI-ACC.1 anchor with:
            factor_a = 1 (access attempt occurred)
            factor_b = 1 if within declared scope (or no scope set), 0 if out of scope
            factor_c = 1 if access granted, 0 if denied/failed
        """
        import asyncio
        import uuid

        def decorator(func: F) -> F:
            name = resource_name or getattr(func, "__name__", "unknown-resource")

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                start = time.monotonic()
                granted = True
                result = None
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception:
                    granted = False
                    raise
                finally:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    input_hash = sha256_truncated(str(args) + str(kwargs))
                    output_hash = sha256_truncated(
                        str(result) if granted else "ACCESS_DENIED"
                    )
                    record = InferenceRecord(
                        model_id=name,
                        model_hash=sha256_truncated(name),
                        prompt_hash=input_hash,
                        response_hash=output_hash,
                        latency_ms=elapsed_ms,
                        provider="access",
                        has_refusal=not granted,
                        access_target=name,
                        access_granted=granted,
                        access_scope=scope,
                    )
                    self.record(record)

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                start = time.monotonic()
                granted = True
                result = None
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception:
                    granted = False
                    raise
                finally:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    input_hash = sha256_truncated(str(args) + str(kwargs))
                    output_hash = sha256_truncated(
                        str(result) if granted else "ACCESS_DENIED"
                    )
                    record = InferenceRecord(
                        model_id=name,
                        model_hash=sha256_truncated(name),
                        prompt_hash=input_hash,
                        response_hash=output_hash,
                        latency_ms=elapsed_ms,
                        provider="access",
                        has_refusal=not granted,
                        access_target=name,
                        access_granted=granted,
                        access_scope=scope,
                    )
                    self.record(record)

            if asyncio.iscoroutinefunction(func):
                return async_wrapper  # type: ignore[return-value]
            return sync_wrapper  # type: ignore[return-value]

        if fn is not None:
            return decorator(fn)
        return decorator

    def witness_security_scan(
        self,
        threat_score: float,
        *,
        threshold: float = 500,
        threat_type: str = "none",
    ) -> None:
        """Witness a security/adversarial detection result (AI-SEC.1).

        Call this after running your own detection system (Prompt Guard,
        LlamaGuard, NeMo Guardrails, etc.) to record the result as a
        tamper-evident anchor.

        Args:
            threat_score: Detection score from your system (0-1000 scale).
            threshold: Score above which an input is considered a threat.
                Default 500. Verdict is PASS when threat_score <= threshold.
            threat_type: One of: none, prompt_injection, data_poisoning,
                model_extraction, jailbreak, adversarial_input. Default "none".

        Example:
            score = my_prompt_guard.scan(user_input)
            witness.witness_security_scan(score, threat_type="prompt_injection")
        """
        threat_codes = {
            "none": 0, "prompt_injection": 1, "data_poisoning": 2,
            "model_extraction": 3, "jailbreak": 4, "adversarial_input": 5,
        }
        payload = self._mint_and_sign(
            "AI-SEC.1", float(threshold), float(threat_score),
            float(threat_codes.get(threat_type, 0)),
        )
        if self._config.clearing_level <= 1:
            payload.ai_model_id = "security-scan"
            payload.ai_context = {"provider": "security", "threat_type": threat_type}
        self._buffer.enqueue_many([payload])

    def witness_input_validation(
        self,
        passed: bool,
        *,
        sanitized: bool = False,
    ) -> None:
        """Witness an input validation/sanitization result (AI-SEC.2).

        Call this after validating or sanitizing user input before
        inference. Records whether input was clean, sanitized, or blocked.

        Args:
            passed: True if input was accepted (clean or sanitized).
                False if input was blocked.
            sanitized: True if input was modified during validation
                (e.g., PII stripped, HTML escaped). Only relevant when
                passed=True.

        Example:
            clean, was_modified = my_sanitizer.validate(user_input)
            witness.witness_input_validation(passed=clean, sanitized=was_modified)
        """
        fb = 1.0 if passed else 0.0
        fc = 0.0 if (passed and not sanitized) else 1.0 if (passed and sanitized) else 2.0
        payload = self._mint_and_sign("AI-SEC.2", 1.0, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = "input-validation"
            payload.ai_context = {"provider": "security"}
        self._buffer.enqueue_many([payload])

    def witness_rag_context(
        self,
        chunks: Any,
        *,
        corpus_id: Optional[str] = None,
        corpus_hash: Optional[str] = None,
        embedding_model: Optional[str] = None,
        retrieval_latency_ms: Optional[int] = None,
        top_k: Optional[int] = None,
        similarity_threshold: Optional[float] = None,
    ) -> List[WitnessPayload]:
        """Witness a RAG retrieval step (AI-RAG.1 + optional AI-RAG.2).

        Records what context chunks were retrieved and from which corpus,
        creating tamper-evident anchors for the retrieval pipeline. Chunk
        text is NEVER transmitted -- only SHA-256 hashes.

        Automatically emits AI-RAG.2 (Context Relevance) when
        similarity_threshold is set and chunks have similarity scores.

        Args:
            chunks: Retrieved context. Either a list of raw strings
                (auto-hashed) or a list of RagChunk instances.
            corpus_id: Identifier for the retrieval corpus/index.
            corpus_hash: SHA-256 hash of the corpus version.
            embedding_model: Name of the embedding model used.
            retrieval_latency_ms: Time taken for retrieval in ms.
            top_k: Number of chunks requested from the retriever.
            similarity_threshold: Minimum relevance threshold (0.0-1.0).
                When set and chunks have similarity_score, AI-RAG.2
                is emitted alongside AI-RAG.1.

        Returns:
            List of WitnessPayload objects (1 for AI-RAG.1, optionally
            2 if AI-RAG.2 is also emitted).

        Example (zero-friction):
            witness.witness_rag_context(
                ["chunk text 1", "chunk text 2"],
                corpus_id="legal-docs-v3",
            )

        Example (full control):
            from swt3_ai import RagChunk
            witness.witness_rag_context(
                [
                    RagChunk(content_hash="abc123...", source_id="doc-7/p3", similarity_score=0.92),
                    RagChunk(content_hash="def456...", source_id="doc-2/p1", similarity_score=0.78),
                ],
                corpus_id="legal-docs-v3",
                similarity_threshold=0.75,
            )
        """
        # Normalize chunks: auto-hash raw strings into RagChunk objects
        normalized: List[RagChunk] = []
        for chunk in chunks:
            if isinstance(chunk, str):
                normalized.append(RagChunk(content_hash=sha256_truncated(chunk)))
            elif isinstance(chunk, RagChunk):
                normalized.append(chunk)
            else:
                normalized.append(RagChunk(content_hash=sha256_truncated(str(chunk))))

        payloads: List[WitnessPayload] = []

        # --- AI-RAG.1: Context Retrieval Provenance ---
        p1 = self._mint_and_sign("AI-RAG.1", float(len(normalized)), 1.0 if corpus_id else 0.0, 0.0)
        if self._config.clearing_level <= 1:
            p1.ai_model_id = embedding_model or "rag-retrieval"
            ctx: Dict[str, Any] = {
                "provider": "rag",
                "chunk_count": len(normalized),
                "chunk_hashes": [c.content_hash for c in normalized],
            }
            if corpus_id:
                ctx["corpus_id"] = corpus_id
            if corpus_hash:
                ctx["corpus_hash"] = corpus_hash
            if embedding_model:
                ctx["embedding_model"] = embedding_model
            if retrieval_latency_ms is not None:
                ctx["retrieval_latency_ms"] = retrieval_latency_ms
            if top_k is not None:
                ctx["top_k"] = top_k
            p1.ai_context = ctx
        if self._config.clearing_level <= 2 and retrieval_latency_ms is not None:
            p1.ai_latency_ms = retrieval_latency_ms
        payloads.append(p1)

        # --- AI-RAG.2: Context Relevance (conditional) ---
        scored_chunks = [c for c in normalized if c.similarity_score is not None]
        if similarity_threshold is not None and scored_chunks:
            scores = [c.similarity_score for c in scored_chunks]
            avg_sim = sum(scores) / len(scores)
            below_count = sum(1 for s in scores if s < similarity_threshold)

            p2 = self._mint_and_sign(
                "AI-RAG.2", float(round(similarity_threshold * 1000)),
                float(round(avg_sim * 1000)), float(below_count),
            )
            if self._config.clearing_level <= 1:
                p2.ai_model_id = embedding_model or "rag-retrieval"
                p2.ai_context = {
                    "provider": "rag",
                    "similarity_threshold": similarity_threshold,
                    "avg_similarity": round(avg_sim, 4),
                    "min_similarity": round(min(scores), 4),
                    "chunks_below_threshold": below_count,
                    "chunk_scores": [round(s, 4) for s in scores],
                }
            payloads.append(p2)

        self._buffer.enqueue_many(payloads)
        logger.info(
            "RAG context witnessed: %d chunks, %d anchors minted (corpus=%s)",
            len(normalized), len(payloads), corpus_id or "anonymous",
        )

        return payloads

    # -- Model Weight & Adapter Methods (AI-MDL.5/6/7) --

    @staticmethod
    def hash_model_file(path: str, format: Optional[str] = None) -> "ModelWeightInfo":
        """Hash a model weight file and return a ModelWeightInfo.

        Call this ONCE at startup, not per-inference. File I/O is
        synchronous and can take seconds for large models.

        Args:
            path: Path to the weight file.
            format: Override format (default: detected from extension).

        Returns:
            ModelWeightInfo ready to pass to witness_model_weights().

        Example:
            info = Witness.hash_model_file("/models/llama-3.1-70b.safetensors")
            # ... later, per-inference or periodic:
            witness.witness_model_weights(info)
        """
        import hashlib as _hashlib
        import os as _os

        h = _hashlib.sha256()
        file_size = 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
                file_size += len(chunk)
        return ModelWeightInfo(
            file_hash=h.hexdigest(), file_path=path,
            file_size_bytes=file_size,
            format=format or _os.path.splitext(path)[1].lstrip(".") or None,
        )

    def witness_model_weights(
        self,
        weights: Any,
        *,
        expected_hash: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness model weight file integrity (AI-MDL.5).

        Args:
            weights: A ModelWeightInfo (from hash_model_file() or constructed
                manually), or a file path string (auto-hashed, but blocks
                for large files -- prefer hash_model_file() at startup).
            expected_hash: Expected SHA-256 hash. Match=PASS, mismatch=FAIL, omit=attested.

        Example (recommended -- hash once at startup):
            info = Witness.hash_model_file("/models/llama-3.1-70b.safetensors")
            witness.witness_model_weights(info, expected_hash="abc123...")

        Example (quick prototyping -- blocks for large files):
            witness.witness_model_weights("/models/small-model.bin")
        """
        if isinstance(weights, str):
            info = self.hash_model_file(weights)
        elif isinstance(weights, ModelWeightInfo):
            info = weights
        else:
            raise TypeError("weights must be a file path string or ModelWeightInfo")

        match = info.file_hash == expected_hash if expected_hash else True
        payload = self._mint_and_sign("AI-MDL.5", 1.0, 1.0 if match else 0.0, 0.0)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = info.format or "model-weights"
            ctx: Dict[str, Any] = {"provider": "model-weights", "file_hash": info.file_hash}
            if info.file_path:
                ctx["file_path"] = info.file_path
            if info.file_size_bytes is not None:
                ctx["file_size_bytes"] = info.file_size_bytes
            if info.format:
                ctx["format"] = info.format
            if expected_hash:
                ctx["expected_hash"] = expected_hash
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    def witness_adapter_stack(
        self,
        adapters: List[AdapterInfo],
        *,
        base_model_id: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness active LoRA/QLoRA/PEFT adapter stack (AI-MDL.6)."""
        all_verified = all(a.adapter_hash for a in adapters) if adapters else True
        payload = self._mint_and_sign("AI-MDL.6", float(len(adapters)), 1.0 if all_verified else 0.0, 0.0)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = base_model_id or "unknown-base"
            payload.ai_context = {
                "provider": "adapter",
                "adapters": [
                    {"name": a.name, "hash": a.adapter_hash, **({"base_model": a.base_model} if a.base_model else {})}
                    for a in adapters
                ],
            }
            if base_model_id:
                payload.ai_context["base_model_id"] = base_model_id
        self._buffer.enqueue_many([payload])
        return payload

    QUANTIZATION_CODES: Dict[str, int] = {
        "fp32": 0, "fp16": 1, "bf16": 2, "int8": 3, "int4": 4,
        "gptq": 5, "awq": 6, "gguf": 7,
    }

    def witness_quantization(
        self,
        method: str,
        *,
        bits: Optional[int] = None,
        group_size: Optional[int] = None,
    ) -> WitnessPayload:
        """Witness model quantization method (AI-MDL.7).

        Args:
            method: fp32, fp16, bf16, int8, int4, gptq, awq, gguf.
            bits: Bit width (e.g., 4, 8, 16).
            group_size: Quantization group size (GPTQ/AWQ).
        """
        code = float(self.QUANTIZATION_CODES.get(method.lower(), 0))
        payload = self._mint_and_sign("AI-MDL.7", 1.0, 1.0, code)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"quantization-{method.lower()}"
            ctx: Dict[str, Any] = {"provider": "quantization", "method": method.lower()}
            if bits is not None:
                ctx["bits"] = bits
            if group_size is not None:
                ctx["group_size"] = group_size
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # -- Procedural Knowledge / Skills Methods (AI-SKILL.1/2/3) --

    def witness_skill_manifest(
        self,
        skills: Any,
        *,
        expected_manifest_hash: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness active skill/tool/plugin manifest (AI-SKILL.1).

        Args:
            skills: Skill name strings (auto-hashed) or SkillInfo objects.
            expected_manifest_hash: Expected hash. Match=PASS, mismatch=FAIL.

        Example:
            witness.witness_skill_manifest(["code_exec", "web_search", "file_read"])
        """
        normalized: List[SkillInfo] = []
        for s in skills:
            if isinstance(s, str):
                normalized.append(SkillInfo(name=s, skill_hash=sha256_truncated(s)))
            elif isinstance(s, SkillInfo):
                normalized.append(s)
            else:
                normalized.append(SkillInfo(name=str(s), skill_hash=sha256_truncated(str(s))))

        manifest_parts = sorted((si.skill_hash or sha256_truncated(si.name)) for si in normalized)
        computed_manifest = sha256_truncated(":".join(manifest_parts))
        match = computed_manifest == expected_manifest_hash if expected_manifest_hash else True

        payload = self._mint_and_sign("AI-SKILL.1", float(len(normalized)), 1.0 if match else 0.0, 0.0)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = "skill-manifest"
            payload.ai_context = {
                "provider": "skill-manifest",
                "skills": [
                    {"name": si.name, **({"version": si.version} if si.version else {}), **({"hash": si.skill_hash} if si.skill_hash else {})}
                    for si in normalized
                ],
                "manifest_hash": computed_manifest,
            }
        self._buffer.enqueue_many([payload])
        return payload

    def witness_memory_context(
        self,
        sources: List[MemorySource],
    ) -> WitnessPayload:
        """Witness persistent memory sources influencing a decision (AI-SKILL.2)."""
        all_identified = all(s.source_id or s.content_hash for s in sources) if sources else False
        payload = self._mint_and_sign("AI-SKILL.2", float(len(sources)), 1.0 if all_identified else 0.0, 0.0)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = "memory-context"
            payload.ai_context = {
                "provider": "memory",
                "sources": [
                    {"type": s.source_type, **({"id": s.source_id} if s.source_id else {}), **({"hash": s.content_hash} if s.content_hash else {})}
                    for s in sources
                ],
                "total_sources": len(sources),
            }
        self._buffer.enqueue_many([payload])
        return payload

    def witness_reward_model(
        self,
        model_id: str,
        *,
        model_hash: Optional[str] = None,
        method: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness RLHF/DPO reward model binding (AI-SKILL.3)."""
        identified = bool(model_id and model_id.strip())
        payload = self._mint_and_sign("AI-SKILL.3", 1.0, 1.0 if identified else 0.0, 0.0)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = model_id
            ctx: Dict[str, Any] = {"provider": "reward-model", "model_id": model_id}
            if model_hash:
                ctx["model_hash"] = model_hash
            if method:
                ctx["method"] = method
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    def witness_hardware(
        self,
        snapshot: Optional[Any] = None,
        expected_topology: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness accelerator hardware inventory (AI-HW.1).

        Records what GPU/accelerator hardware is present. Call ONCE at
        service startup, not per-inference. If no GPUs are detectable,
        returns a payload with factor_a=0, factor_b=0 (graceful no-op).

        Args:
            snapshot: Pre-computed HardwareSnapshot (from query_hardware()).
                If None, auto-detects via pynvml or nvidia-smi.
            expected_topology: Expected topology string (e.g., "NVL72").
                If provided and doesn't match detected topology, factor_b=0.

        Returns:
            WitnessPayload for the AI-HW.1 anchor.
        """
        from .hardware import query_hardware, topology_code, HardwareSnapshot

        if snapshot is None:
            snapshot = query_hardware()

        self._last_hw_snapshot = snapshot
        gpu_count = len(snapshot.gpus)
        all_healthy = gpu_count > 0
        if expected_topology and snapshot.topology != expected_topology:
            all_healthy = False

        fa = float(gpu_count)
        fb = 1.0 if all_healthy else 0.0
        fc = float(topology_code(snapshot.topology))

        payload = self._mint_and_sign("AI-HW.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"hw-{snapshot.topology}"
            ctx: Dict[str, Any] = {
                "provider": "nvidia-hw",
                "topology": snapshot.topology,
                "interconnect": snapshot.interconnect,
                "total_memory_mb": snapshot.total_memory_mb,
                "gpu_count": gpu_count,
                "hostname_hash": snapshot.hostname_hash,
            }
            if snapshot.driver_version:
                ctx["driver_version"] = snapshot.driver_version
            if snapshot.cuda_version:
                ctx["cuda_version"] = snapshot.cuda_version
            if snapshot.gpus:
                ctx["gpus"] = [
                    {
                        "name": g.name,
                        "memory_mb": g.memory_mb,
                        "bus_id_hash": g.bus_id_hash,
                        "uuid_hash": g.uuid_hash,
                    }
                    for g in snapshot.gpus
                ]
            if expected_topology:
                ctx["expected_topology"] = expected_topology
            payload.ai_context = ctx

        self._buffer.enqueue_many([payload])
        return payload

    def witness_tpm_attestation(
        self,
        snapshot: Optional[Any] = None,
    ) -> WitnessPayload:
        """Witness TPM 2.0 platform attestation (AI-HW.3).

        Reads PCR registers 0-7 via tpm2-tools and mints an anchor proving
        host firmware integrity. All raw PCR digests are SHA-256 hashed
        before leaving the module.

        Args:
            snapshot: Pre-computed TPMSnapshot (from query_tpm()).
                If None, auto-detects via tpm2-tools.

        Returns:
            WitnessPayload for the AI-HW.3 anchor.
        """
        from .hardware import query_tpm, ZERO_PCR_HASH

        if snapshot is None:
            snapshot = query_tpm()

        pcr_count = len(snapshot.pcrs)
        all_non_zero = pcr_count > 0 and all(
            pcr.digest_hash != ZERO_PCR_HASH for pcr in snapshot.pcrs
        )

        fa = float(pcr_count)
        fb = 1.0 if all_non_zero else 0.0
        fc = 0.0  # reserved

        payload = self._mint_and_sign("AI-HW.3", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = "tpm-attestation"
            ctx: Dict[str, Any] = {
                "provider": "tpm-2.0",
                "pcr_count": pcr_count,
                "all_non_zero": all_non_zero,
                "manufacturer_hash": snapshot.manufacturer,
                "firmware_hash": snapshot.firmware_version,
                "endorsement_key_hash": snapshot.endorsement_key_hash,
                "hostname_hash": snapshot.hostname_hash,
            }
            if snapshot.pcrs:
                ctx["pcrs"] = [
                    {
                        "index": pcr.index,
                        "bank": pcr.bank,
                        "digest_hash": pcr.digest_hash,
                    }
                    for pcr in snapshot.pcrs
                ]
            payload.ai_context = ctx

        self._buffer.enqueue_many([payload])
        return payload

    # ── Environment (AI-ENV.1 / AI-ENV.2) ──────────────────────────────

    def witness_environment(
        self,
        temperature_celsius: Optional[int] = None,
        threshold_celsius: int = 85,
        *,
        snapshot: Optional[Any] = None,
        node_type: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness thermal integrity of the compute environment (AI-ENV.1).

        Call at service startup or on a periodic schedule, not per-inference.
        Auto-detects Linux thermal zones. Pass manual values for XFRA/Span nodes.

        Args:
            temperature_celsius: Measured temperature. Auto-detected if omitted.
            threshold_celsius: Safe maximum (default 85).
            snapshot: Pre-computed EnvironmentSnapshot.
            node_type: Node type: datacenter, edge, residential, mobile.

        Returns:
            WitnessPayload for the AI-ENV.1 anchor.
        """
        from .environment import query_environment

        if snapshot is None:
            snapshot = query_environment()

        temp = temperature_celsius if temperature_celsius is not None else snapshot.temperature_celsius
        nt = node_type or snapshot.node_type or "unknown"

        fa = float(round(temp))
        fb = float(threshold_celsius)
        fc = 1.0 if fa <= fb else 0.0

        payload = self._mint_and_sign("AI-ENV.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"env-thermal-{nt}"
            payload.ai_context = {
                "provider": "env-telemetry",
                "node_type": nt,
                "temperature_celsius": temp,
                "threshold_celsius": threshold_celsius,
                "thermal_zones": snapshot.thermal_zones,
                "hostname_hash": snapshot.hostname_hash,
            }

        self._buffer.enqueue_many([payload])
        return payload

    def witness_energy_draw(
        self,
        power_watts: Optional[int] = None,
        capacity_watts: int = 0,
        *,
        throttled: bool = False,
        snapshot: Optional[Any] = None,
        node_type: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness power integrity of the compute environment (AI-ENV.2).

        Call at service startup or on a periodic schedule, not per-inference.
        Pass manual values from Span panel API, IPMI, or other power monitoring.

        Args:
            power_watts: Current power draw in watts. Auto-detected if omitted.
            capacity_watts: Total available capacity in watts.
            throttled: Whether power throttling is active.
            snapshot: Pre-computed EnvironmentSnapshot.
            node_type: Node type: datacenter, edge, residential, mobile.

        Returns:
            WitnessPayload for the AI-ENV.2 anchor.
        """
        from .environment import query_environment

        if snapshot is None:
            snapshot = query_environment()

        power = power_watts if power_watts is not None else snapshot.power_watts
        headroom = max(0, capacity_watts - power)
        nt = node_type or snapshot.node_type or "unknown"

        fa = float(round(power))
        fb = float(round(headroom))
        fc = 1.0 if throttled else 0.0

        payload = self._mint_and_sign("AI-ENV.2", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"env-power-{nt}"
            payload.ai_context = {
                "provider": "env-telemetry",
                "node_type": nt,
                "power_watts": power,
                "capacity_watts": capacity_watts,
                "headroom_watts": headroom,
                "throttled": throttled,
                "power_domains": snapshot.power_domains,
                "hostname_hash": snapshot.hostname_hash,
            }

        self._buffer.enqueue_many([payload])
        return payload

    # ── Runtime Profile Validation ──────────────────────────────────────

    def _validate_runtime_profile(self, profile: Any, snapshot: Any) -> None:
        """Validate hardware snapshot against a runtime profile. Logs warnings
        on mismatch but never blocks -- we are a witness, not enforcement."""
        import logging
        log = logging.getLogger("swt3")
        if profile.expected_topology and snapshot.topology != profile.expected_topology:
            log.warning("runtime profile: expected topology %r, got %r", profile.expected_topology, snapshot.topology)
        if profile.min_gpu_count is not None and len(snapshot.gpus) < profile.min_gpu_count:
            log.warning("runtime profile: expected min_gpu_count=%d, got %d", profile.min_gpu_count, len(snapshot.gpus))
        if profile.min_memory_mb is not None and snapshot.total_memory_mb < profile.min_memory_mb:
            log.warning("runtime profile: expected min_memory_mb=%d, got %d", profile.min_memory_mb, snapshot.total_memory_mb)
        if profile.expected_accelerator:
            match = any(profile.expected_accelerator.upper() in g.name.upper() for g in snapshot.gpus)
            if not match:
                log.warning("runtime profile: expected accelerator containing %r, none found", profile.expected_accelerator)

    # ── Content Provenance (AI-MARK.1) ────────────────────────────────

    def witness_content_mark(
        self,
        content_count: int,
        content_type: str,
        marking_method: str,
        has_metadata: bool = False,
        *,
        content_hash: Optional[str] = None,
        content: Optional[str] = None,
        manifest_hash: Optional[str] = None,
        standard: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness content provenance marking (AI-MARK.1).

        Records when AI-generated content is labelled for machine
        detectability per EU AI Act Art. 50(2) and GPAI Code of Practice.

        Args:
            content_count: Number of content items marked.
            content_type: Content type (text, image, audio, video, multimodal, code, structured_data).
            marking_method: Marking method (c2pa, watermark, metadata_tag, steganographic, manifest).
            has_metadata: True if C2PA/watermark metadata was attached.
            content_hash: Pre-computed SHA-256 of content.
            content: Raw content string (auto-hashed if content_hash not provided).
            manifest_hash: SHA-256 of C2PA manifest.
            standard: Standard identifier (e.g., "C2PA-1.4", "IPTC", "XMP").

        Returns:
            WitnessPayload for the AI-MARK.1 anchor.
        """
        fa = float(content_count)
        fb = 1.0 if has_metadata else 0.0
        fc = float(CONTENT_TYPE_CODES.get(content_type, 0))

        resolved_hash = content_hash
        if resolved_hash is None and content is not None:
            resolved_hash = sha256_truncated(content)

        payload = self._mint_and_sign("AI-MARK.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"mark-{content_type}"
            ctx: Dict[str, Any] = {
                "provider": "content-provenance",
                "content_type": content_type,
                "marking_method": marking_method,
            }
            if resolved_hash:
                ctx["content_hash"] = resolved_hash
            if manifest_hash:
                ctx["manifest_hash"] = manifest_hash
            if standard:
                ctx["standard"] = standard
            payload.ai_context = ctx

        self._buffer.enqueue_many([payload])
        return payload

    # ── Agent Behavioral Baseline (AI-BASE.1) ─────────────────────────

    def witness_agent_baseline(
        self,
        dimensions: int,
        within_envelope: bool,
        mode: str,
        drift_score: float,
        baseline_hash: str,
        current_hash: str,
        *,
        drift_threshold: float = 0.5,
        baseline_window_hours: Optional[float] = None,
    ) -> WitnessPayload:
        """Witness an agent behavioral baseline (AI-BASE.1).

        Records the establishment or monitoring of an agent's behavior
        envelope and detects drift from baseline.

        Args:
            dimensions: Number of behavioral dimensions measured.
            within_envelope: True if behavior is within baseline.
            mode: Baseline mode (establishing, monitoring, drift_detected, baseline_reset).
            drift_score: Normalized distance from baseline center (0.0-1.0).
            baseline_hash: SHA-256 of the baseline vector.
            current_hash: SHA-256 of current observation vector.
            drift_threshold: Threshold above which drift is flagged (default 0.5).
            baseline_window_hours: Hours of data the baseline covers.

        Returns:
            WitnessPayload for the AI-BASE.1 anchor.
        """
        fa = float(dimensions)
        fb = 1.0 if within_envelope else 0.0
        fc = float(BASELINE_MODE_CODES.get(mode, 0))

        agent_id_hash = sha256_truncated(self._config.agent_id) if self._config.agent_id else None

        payload = self._mint_and_sign("AI-BASE.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"baseline-{mode}"
            ctx: Dict[str, Any] = {
                "provider": "agent-baseline",
                "dimensions": dimensions,
                "drift_score": drift_score,
                "baseline_hash": baseline_hash,
                "current_hash": current_hash,
                "drift_threshold": drift_threshold,
            }
            if baseline_window_hours is not None:
                ctx["baseline_window_hours"] = baseline_window_hours
            if agent_id_hash:
                ctx["agent_id_hash"] = agent_id_hash
            payload.ai_context = ctx

        self._buffer.enqueue_many([payload])
        return payload

    # ── License Provenance (AI-LIC.1) ──────────────────────────────────

    def witness_license_provenance(
        self,
        components_checked: int,
        all_compliant: bool,
        license_type: str,
        *,
        base_model_license: Optional[str] = None,
        adapter_licenses: Optional[List[str]] = None,
        spdx_ids: Optional[List[str]] = None,
        license_hash: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness license provenance of a model stack (AI-LIC.1).

        Records the license composition of base models, adapters, and
        training data. Detects license drift when components from
        different license families are combined.

        Args:
            components_checked: Number of license components verified.
            all_compliant: True if all components are license-compatible.
            license_type: Primary license type (permissive, copyleft, proprietary, dual, openmdw, unknown).
            base_model_license: SPDX identifier of the base model license.
            adapter_licenses: List of adapter/LoRA license identifiers.
            spdx_ids: SPDX identifiers for all components.
            license_hash: SHA-256 of the full license manifest.

        Returns:
            WitnessPayload for the AI-LIC.1 anchor.
        """
        fa = float(components_checked)
        fb = 1.0 if all_compliant else 0.0
        fc = float(LICENSE_TYPE_CODES.get(license_type, 5))

        payload = self._mint_and_sign("AI-LIC.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"license-{license_type}"
            ctx: Dict[str, Any] = {
                "provider": "license-provenance",
                "license_type": license_type,
            }
            if base_model_license:
                ctx["base_model_license"] = base_model_license
            if adapter_licenses:
                ctx["adapter_licenses"] = adapter_licenses
            if spdx_ids:
                ctx["spdx_ids"] = spdx_ids
            if license_hash:
                ctx["license_hash"] = license_hash
            payload.ai_context = ctx

        self._buffer.enqueue_many([payload])
        return payload

    # ── AI Bill of Materials (AI-SBOM.1) ────────────────────────────────

    def witness_sbom(
        self,
        total_components: int,
        clusters_documented: int,
        format: str,
        bom_hash: str,
        *,
        version: Optional[str] = None,
        model_count: Optional[int] = None,
        dataset_count: Optional[int] = None,
        infrastructure_components: Optional[int] = None,
    ) -> WitnessPayload:
        """Witness an AI bill of materials snapshot (AI-SBOM.1).

        Records the component inventory of an AI system at build or deploy
        time, covering models, datasets, infrastructure, and security
        posture per G7/CISA "SBOM for AI Minimum Elements" (May 2026).

        Args:
            total_components: Number of components in the BOM.
            clusters_documented: G7 clusters documented (0-7).
            format: BOM format (cyclonedx, spdx, custom, unknown).
            bom_hash: SHA-256 of the full BOM document.
            version: BOM version string.
            model_count: Number of AI models in BOM.
            dataset_count: Number of datasets in BOM.
            infrastructure_components: Number of infra components.

        Returns:
            WitnessPayload for the AI-SBOM.1 anchor.
        """
        fa = float(total_components)
        fb = float(clusters_documented)
        fc = float(SBOM_FORMAT_CODES.get(format, 3))

        payload = self._mint_and_sign("AI-SBOM.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"sbom-{format}"
            ctx: Dict[str, Any] = {
                "provider": "ai-sbom",
                "bom_hash": bom_hash,
                "format": format,
            }
            if version:
                ctx["version"] = version
            if model_count is not None:
                ctx["model_count"] = model_count
            if dataset_count is not None:
                ctx["dataset_count"] = dataset_count
            if infrastructure_components is not None:
                ctx["infrastructure_components"] = infrastructure_components
            payload.ai_context = ctx

        self._buffer.enqueue_many([payload])
        return payload

    # ── Adversarial Test Campaign (AI-REDTEAM.1) ──────────────────────

    def witness_red_team(
        self,
        tests_executed: int,
        tests_passed: int,
        coverage_category: str,
        *,
        framework: Optional[str] = None,
        campaign_id: Optional[str] = None,
        model_under_test: Optional[str] = None,
        attack_taxonomy: Optional[str] = None,
        pass_rate: Optional[float] = None,
        duration_seconds: Optional[int] = None,
    ) -> WitnessPayload:
        """Witness an adversarial test campaign (AI-REDTEAM.1).

        Records red team or adversarial testing results, transforming
        point-in-time reports into continuous verifiable evidence per
        EO 14110, EU AI Act Art. 9(7), and NIST AI 100-2.

        Args:
            tests_executed: Number of attack scenarios run.
            tests_passed: Number of attacks successfully mitigated.
            coverage_category: Category key (prompt_injection, jailbreak, etc.).
            framework: Testing framework (e.g. "OWASP-LLM-Top10").
            campaign_id: Unique identifier for this test campaign.
            model_under_test: Model identifier being tested.
            attack_taxonomy: Attack taxonomy version or reference.
            pass_rate: Computed pass rate (0-1).
            duration_seconds: Campaign duration in seconds.

        Returns:
            WitnessPayload for the AI-REDTEAM.1 anchor.
        """
        fa = float(tests_executed)
        fb = float(tests_passed)
        fc = float(REDTEAM_CATEGORY_CODES.get(coverage_category, 10))

        payload = self._mint_and_sign("AI-REDTEAM.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"redteam-{coverage_category}"
            ctx: Dict[str, Any] = {
                "provider": "red-team",
                "coverage_category": coverage_category,
            }
            if framework:
                ctx["framework"] = framework
            if campaign_id:
                ctx["campaign_id"] = campaign_id
            if model_under_test:
                ctx["model_under_test"] = model_under_test
            if attack_taxonomy:
                ctx["attack_taxonomy"] = attack_taxonomy
            if pass_rate is not None:
                ctx["pass_rate"] = pass_rate
            if duration_seconds is not None:
                ctx["duration_seconds"] = duration_seconds
            payload.ai_context = ctx

        self._buffer.enqueue_many([payload])
        return payload

    # ── Data Subject Consent (AI-CONSENT.1) ───────────────────────────

    def witness_consent(
        self,
        subjects_covered: int,
        legal_basis_type: str,
        withdrawal_available: bool,
        *,
        purpose: Optional[str] = None,
        retention_days: Optional[int] = None,
        consent_mechanism: Optional[str] = None,
        consent_hash: Optional[str] = None,
        data_categories: Optional[List[str]] = None,
    ) -> WitnessPayload:
        """Witness data subject consent documentation (AI-CONSENT.1).

        Records that consent or lawful basis was documented before
        processing. Complements CJT fields (which declare legal basis)
        by proving consent was actually obtained per GDPR Art. 6/7
        and EU AI Act Art. 10.

        Args:
            subjects_covered: Number of data subjects in scope.
            legal_basis_type: GDPR lawful basis (consent, contract, etc.).
            withdrawal_available: True if withdrawal mechanism exists.
            purpose: Processing purpose description.
            retention_days: Data retention period in days.
            consent_mechanism: Mechanism used (e.g. "opt-in-form").
            consent_hash: SHA-256 of the consent record.
            data_categories: Categories of personal data processed.

        Returns:
            WitnessPayload for the AI-CONSENT.1 anchor.
        """
        fa = float(subjects_covered)
        fb = float(CONSENT_BASIS_CODES.get(legal_basis_type, 0))
        fc = 1.0 if withdrawal_available else 0.0

        payload = self._mint_and_sign("AI-CONSENT.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"consent-{legal_basis_type}"
            ctx: Dict[str, Any] = {
                "provider": "consent-management",
                "legal_basis_type": legal_basis_type,
            }
            if purpose:
                ctx["purpose"] = purpose
            if retention_days is not None:
                ctx["retention_days"] = retention_days
            if consent_mechanism:
                ctx["consent_mechanism"] = consent_mechanism
            if consent_hash:
                ctx["consent_hash"] = consent_hash
            if data_categories:
                ctx["data_categories"] = data_categories
            payload.ai_context = ctx

        self._buffer.enqueue_many([payload])
        return payload

    # ── Multi-Agent Delegation (AI-MULTI.1) ───────────────────────────

    def witness_multi_agent_delegation(
        self,
        delegation_depth: int,
        permissions_granted: int,
        time_bound_minutes: int,
        parent_agent_id: str,
        child_agent_id: str,
        *,
        delegated_tools: Optional[List[str]] = None,
        scope_hash: Optional[str] = None,
        authorization_chain: Optional[List[str]] = None,
    ) -> WitnessPayload:
        """Witness inter-agent permission delegation (AI-MULTI.1).

        Records the permission envelope when one agent delegates tasks
        to another. Complements AI-CHAIN.1/2 (which witness handoffs and
        trust degradation) by witnessing WHAT was delegated per
        EU AI Act Art. 9 and NIST AI RMF GOVERN 1.3.

        Args:
            delegation_depth: Hops from original human authorization.
            permissions_granted: Count of distinct permissions delegated.
            time_bound_minutes: Minutes until expiry (0 = unbounded).
            parent_agent_id: Delegating agent identifier (hashed in context).
            child_agent_id: Receiving agent identifier (hashed in context).
            delegated_tools: List of tool names being delegated.
            scope_hash: SHA-256 of the permission manifest.
            authorization_chain: Ordered agent IDs from human to child.

        Returns:
            WitnessPayload for the AI-MULTI.1 anchor.
        """
        fa = float(delegation_depth)
        fb = float(permissions_granted)
        fc = float(time_bound_minutes)

        payload = self._mint_and_sign("AI-MULTI.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"delegation-depth-{delegation_depth}"
            ctx: Dict[str, Any] = {
                "provider": "multi-agent",
                "parent_agent_hash": sha256_truncated(parent_agent_id),
                "child_agent_hash": sha256_truncated(child_agent_id),
            }
            if delegated_tools:
                ctx["delegated_tools"] = delegated_tools
            if scope_hash:
                ctx["scope_hash"] = scope_hash
            if authorization_chain:
                ctx["authorization_chain"] = [
                    sha256_truncated(aid) for aid in authorization_chain
                ]
            payload.ai_context = ctx

        self._buffer.enqueue_many([payload])
        return payload

    # ── Model Drift Detection (AI-DRIFT.1) ──────────────────────────────

    def witness_drift(self, metrics_evaluated: int, drifted_count: int, drift_type: str, *, baseline_hash: Optional[str] = None, drift_score: Optional[float] = None, detection_method: Optional[str] = None, window_size: Optional[int] = None, threshold: Optional[float] = None) -> WitnessPayload:
        """Witness model drift detection (AI-DRIFT.1). Art. 9(2)(b), NIST MEASURE 2.6."""
        fa, fb, fc = float(metrics_evaluated), float(drifted_count), float(DRIFT_TYPE_CODES.get(drift_type, 0))
        payload = self._mint_and_sign("AI-DRIFT.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"drift-{drift_type}"
            ctx: Dict[str, Any] = {"provider": "drift-detection", "drift_type": drift_type}
            if baseline_hash: ctx["baseline_hash"] = baseline_hash
            if drift_score is not None: ctx["drift_score"] = drift_score
            if detection_method: ctx["detection_method"] = detection_method
            if window_size is not None: ctx["window_size"] = window_size
            if threshold is not None: ctx["threshold"] = threshold
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Audit Log Integrity (AI-AUDIT.1) ──────────────────────────────

    def witness_audit_integrity(self, entries_checked: int, integrity_verified: bool, log_format: str, *, log_hash: Optional[str] = None, period_start: Optional[str] = None, period_end: Optional[str] = None, gaps_detected: Optional[int] = None) -> WitnessPayload:
        """Witness audit log integrity (AI-AUDIT.1). Art. 12, GDPR Art. 30."""
        fa, fb, fc = float(entries_checked), 1.0 if integrity_verified else 0.0, float(LOG_FORMAT_CODES.get(log_format, 3))
        payload = self._mint_and_sign("AI-AUDIT.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"audit-{log_format}"
            ctx: Dict[str, Any] = {"provider": "audit-integrity", "log_format": log_format}
            if log_hash: ctx["log_hash"] = log_hash
            if period_start: ctx["period_start"] = period_start
            if period_end: ctx["period_end"] = period_end
            if gaps_detected is not None: ctx["gaps_detected"] = gaps_detected
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Incident Reporting (AI-INCIDENT.1) ────────────────────────────

    def witness_incident(self, severity_code: int, authority_notified: bool, incident_type: str, *, incident_id: Optional[str] = None, authority: Optional[str] = None, affected_subjects: Optional[int] = None, remediation_status: Optional[str] = None) -> WitnessPayload:
        """Witness incident reporting (AI-INCIDENT.1). Art. 62, NIST MANAGE 3.2."""
        fa, fb, fc = float(severity_code), 1.0 if authority_notified else 0.0, float(INCIDENT_TYPE_CODES.get(incident_type, 5))
        payload = self._mint_and_sign("AI-INCIDENT.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"incident-{incident_type}"
            ctx: Dict[str, Any] = {"provider": "incident-reporting", "incident_type": incident_type}
            if incident_id: ctx["incident_id"] = incident_id
            if authority: ctx["authority"] = authority
            if affected_subjects is not None: ctx["affected_subjects"] = affected_subjects
            if remediation_status: ctx["remediation_status"] = remediation_status
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Performance Metrics (AI-PERF.1) ───────────────────────────────

    def witness_performance(self, metrics_evaluated: int, metrics_passing: int, benchmark_type: str, *, benchmark_id: Optional[str] = None, dataset_hash: Optional[str] = None, threshold: Optional[float] = None, score: Optional[float] = None, model_under_test: Optional[str] = None) -> WitnessPayload:
        """Witness performance metrics (AI-PERF.1). Art. 15(1), NIST MEASURE 2.5."""
        fa, fb, fc = float(metrics_evaluated), float(metrics_passing), float(BENCHMARK_TYPE_CODES.get(benchmark_type, 5))
        payload = self._mint_and_sign("AI-PERF.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"perf-{model_under_test or benchmark_type}"
            ctx: Dict[str, Any] = {"provider": "performance-metrics", "benchmark_type": benchmark_type}
            if benchmark_id: ctx["benchmark_id"] = benchmark_id
            if dataset_hash: ctx["dataset_hash"] = dataset_hash
            if threshold is not None: ctx["threshold"] = threshold
            if score is not None: ctx["score"] = score
            if model_under_test: ctx["model_under_test"] = model_under_test
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Robustness Testing (AI-ROBUST.1) ──────────────────────────────

    def witness_robustness(self, perturbations_tested: int, perturbations_survived: int, perturbation_type: str, *, test_suite_id: Optional[str] = None, degradation_pct: Optional[float] = None, baseline_score: Optional[float] = None, perturbed_score: Optional[float] = None) -> WitnessPayload:
        """Witness robustness testing (AI-ROBUST.1). Art. 15(3), NIST MEASURE 2.6."""
        fa, fb, fc = float(perturbations_tested), float(perturbations_survived), float(PERTURBATION_TYPE_CODES.get(perturbation_type, 5))
        payload = self._mint_and_sign("AI-ROBUST.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"robust-{perturbation_type}"
            ctx: Dict[str, Any] = {"provider": "robustness-testing", "perturbation_type": perturbation_type}
            if test_suite_id: ctx["test_suite_id"] = test_suite_id
            if degradation_pct is not None: ctx["degradation_pct"] = degradation_pct
            if baseline_score is not None: ctx["baseline_score"] = baseline_score
            if perturbed_score is not None: ctx["perturbed_score"] = perturbed_score
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Cybersecurity Attestation (AI-CYBER.1) ────────────────────────

    def witness_cybersecurity(self, controls_assessed: int, controls_compliant: int, framework: str, *, assessment_id: Optional[str] = None, framework_version: Optional[str] = None, findings_count: Optional[int] = None, critical_findings: Optional[int] = None) -> WitnessPayload:
        """Witness cybersecurity attestation (AI-CYBER.1). Art. 15(4), NIST CSF."""
        fa, fb, fc = float(controls_assessed), float(controls_compliant), float(CYBER_FRAMEWORK_CODES.get(framework, 4))
        payload = self._mint_and_sign("AI-CYBER.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"cyber-{framework}"
            ctx: Dict[str, Any] = {"provider": "cybersecurity-assessment", "framework": framework}
            if assessment_id: ctx["assessment_id"] = assessment_id
            if framework_version: ctx["framework_version"] = framework_version
            if findings_count is not None: ctx["findings_count"] = findings_count
            if critical_findings is not None: ctx["critical_findings"] = critical_findings
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Transparency Disclosure (AI-TRANS.1) ──────────────────────────

    def witness_transparency(self, disclosures_made: int, disclosure_type: str, recipient_type: str, *, disclosure_id: Optional[str] = None, content_hash: Optional[str] = None, channel: Optional[str] = None) -> WitnessPayload:
        """Witness transparency disclosure (AI-TRANS.1). Art. 13, GDPR Art. 13/14."""
        fa, fb, fc = float(disclosures_made), float(DISCLOSURE_TYPE_CODES.get(disclosure_type, 0)), float(RECIPIENT_TYPE_CODES.get(recipient_type, 0))
        payload = self._mint_and_sign("AI-TRANS.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"trans-{disclosure_type}"
            ctx: Dict[str, Any] = {"provider": "transparency-disclosure", "disclosure_type": disclosure_type, "recipient_type": recipient_type}
            if disclosure_id: ctx["disclosure_id"] = disclosure_id
            if content_hash: ctx["content_hash"] = content_hash
            if channel: ctx["channel"] = channel
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Watermark Verification (AI-WATERMARK.1) ──────────────────────

    def witness_watermark_verification(self, items_checked: int, watermarks_detected: int, detection_method: str, *, content_hash: Optional[str] = None, watermark_provider: Optional[str] = None, confidence_score: Optional[float] = None, stripped_count: Optional[int] = None) -> WitnessPayload:
        """Witness watermark verification (AI-WATERMARK.1). Art. 50(2), GPAI CoP."""
        fa, fb, fc = float(items_checked), float(watermarks_detected), float(DETECTION_METHOD_CODES.get(detection_method, 4))
        payload = self._mint_and_sign("AI-WATERMARK.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"watermark-{detection_method}"
            ctx: Dict[str, Any] = {"provider": "watermark-verification", "detection_method": detection_method}
            if content_hash: ctx["content_hash"] = content_hash
            if watermark_provider: ctx["watermark_provider"] = watermark_provider
            if confidence_score is not None: ctx["confidence_score"] = confidence_score
            if stripped_count is not None: ctx["stripped_count"] = stripped_count
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Data Protection Impact Assessment (AI-DPIA.1) ────────────────

    def witness_dpia(self, risks_identified: int, risks_mitigated: int, processing_type: str, *, dpia_id: Optional[str] = None, assessment_date: Optional[str] = None, dpo_consulted: Optional[bool] = None, residual_risk_level: Optional[str] = None, supervisory_authority_consulted: Optional[bool] = None) -> WitnessPayload:
        """Witness DPIA completion (AI-DPIA.1). GDPR Art. 35, Art. 27."""
        fa, fb, fc = float(risks_identified), float(risks_mitigated), float(PROCESSING_TYPE_CODES.get(processing_type, 4))
        payload = self._mint_and_sign("AI-DPIA.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"dpia-{processing_type}"
            ctx: Dict[str, Any] = {"provider": "impact-assessment", "processing_type": processing_type}
            if dpia_id: ctx["dpia_id"] = dpia_id
            if assessment_date: ctx["assessment_date"] = assessment_date
            if dpo_consulted is not None: ctx["dpo_consulted"] = dpo_consulted
            if residual_risk_level: ctx["residual_risk_level"] = residual_risk_level
            if supervisory_authority_consulted is not None: ctx["supervisory_authority_consulted"] = supervisory_authority_consulted
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Automated Decision Notification (AI-AUTO.1) ──────────────────

    def witness_automated_decision(self, decisions_made: int, human_reviewed: int, decision_type: str, *, decision_id: Optional[str] = None, subject_notified: Optional[bool] = None, opt_out_available: Optional[bool] = None, human_review_requested: Optional[bool] = None) -> WitnessPayload:
        """Witness automated decision notification (AI-AUTO.1). GDPR Art. 22, Art. 14."""
        fa, fb, fc = float(decisions_made), float(human_reviewed), float(DECISION_TYPE_CODES.get(decision_type, 5))
        payload = self._mint_and_sign("AI-AUTO.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"auto-{decision_type}"
            ctx: Dict[str, Any] = {"provider": "automated-decision", "decision_type": decision_type}
            if decision_id: ctx["decision_id"] = decision_id
            if subject_notified is not None: ctx["subject_notified"] = subject_notified
            if opt_out_available is not None: ctx["opt_out_available"] = opt_out_available
            if human_review_requested is not None: ctx["human_review_requested"] = human_review_requested
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Autonomous Generation Depth (AI-AUTO.2) ──────────────────────

    def witness_generation_depth(self, max_depth: int, observed_depth: int, human_gate_present: bool, *, generation_context: Optional[str] = None, source_agent_id: Optional[str] = None, merge_target: Optional[str] = None) -> WitnessPayload:
        """Witness autonomous generation depth (AI-AUTO.2). EU AI Act Art. 14, EO 14110 Sec. 3."""
        fa, fb, fc = float(max_depth), float(observed_depth), 1.0 if human_gate_present else 0.0
        payload = self._mint_and_sign("AI-AUTO.2", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = source_agent_id or "autonomous-generator"
            ctx: Dict[str, Any] = {"provider": "generation-depth", "max_depth": max_depth, "observed_depth": observed_depth}
            if generation_context: ctx["generation_context"] = generation_context
            if source_agent_id: ctx["source_agent_id"] = source_agent_id
            if merge_target: ctx["merge_target"] = merge_target
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── External Timestamp Attestation (AI-AUDIT.2) ──────────────────

    TSA_PROVIDER_CODES: Dict[str, int] = {"none": 0, "freetsa": 1, "digicert": 2, "sectigo": 3, "custom": 4}

    def witness_timestamp_attestation(self, anchor_count: int, tsa_verified: bool, tsa_provider: str, *, merkle_root: Optional[str] = None, tsa_url: Optional[str] = None, tsa_serial: Optional[str] = None) -> WitnessPayload:
        """Witness external timestamp attestation (AI-AUDIT.2). NIST 800-53 AU-10."""
        fa, fb = float(anchor_count), 1.0 if tsa_verified else 0.0
        fc = float(self.TSA_PROVIDER_CODES.get(tsa_provider, 4))
        payload = self._mint_and_sign("AI-AUDIT.2", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = "merkle-rollup"
            ctx: Dict[str, Any] = {"provider": "timestamp-attestation", "tsa_provider": tsa_provider}
            if merkle_root: ctx["merkle_root"] = merkle_root
            if tsa_url: ctx["tsa_url"] = tsa_url
            if tsa_serial: ctx["tsa_serial"] = tsa_serial
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Dual-Use Model Classification (AI-DUALUSE.1) ─────────────────

    def witness_dual_use(self, classification_code: int, reporting_status: str, days_since_classification: int, *, model_id: Optional[str] = None, classification_basis: Optional[str] = None, compute_threshold: Optional[str] = None, authority_notified: Optional[str] = None) -> WitnessPayload:
        """Witness dual-use model classification (AI-DUALUSE.1). EO 14110 Sec 4(a)."""
        fa, fb, fc = float(classification_code), float(REPORTING_STATUS_CODES.get(reporting_status, 0)), float(days_since_classification)
        payload = self._mint_and_sign("AI-DUALUSE.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = model_id or f"dualuse-class-{classification_code}"
            ctx: Dict[str, Any] = {"provider": "dual-use-classification", "reporting_status": reporting_status}
            if model_id: ctx["model_id"] = model_id
            if classification_basis: ctx["classification_basis"] = classification_basis
            if compute_threshold: ctx["compute_threshold"] = compute_threshold
            if authority_notified: ctx["authority_notified"] = authority_notified
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Supply Chain Risk (AI-SUPPLY.1) ───────────────────────────────

    def witness_supply_chain_risk(self, suppliers_assessed: int, suppliers_compliant: int, risk_level: str, *, supplier_id_hash: Optional[str] = None, vulnerability_count: Optional[int] = None, last_audit_date: Optional[str] = None, update_cadence_days: Optional[int] = None) -> WitnessPayload:
        """Witness supply chain risk (AI-SUPPLY.1). NIST MEASURE 3.1, G7/CISA."""
        fa, fb, fc = float(suppliers_assessed), float(suppliers_compliant), float(SUPPLY_RISK_CODES.get(risk_level, 0))
        payload = self._mint_and_sign("AI-SUPPLY.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"supply-risk-{risk_level}"
            ctx: Dict[str, Any] = {"provider": "supply-chain-risk", "risk_level": risk_level}
            if supplier_id_hash: ctx["supplier_id_hash"] = supplier_id_hash
            if vulnerability_count is not None: ctx["vulnerability_count"] = vulnerability_count
            if last_audit_date: ctx["last_audit_date"] = last_audit_date
            if update_cadence_days is not None: ctx["update_cadence_days"] = update_cadence_days
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Post-Market Monitoring (AI-PMM.1) ─────────────────────────────

    def witness_post_market_monitoring(self, monitoring_checks_run: int, anomalies_detected: int, monitoring_type: str, *, monitoring_plan_hash: Optional[str] = None, period_start: Optional[str] = None, period_end: Optional[str] = None, report_generated: Optional[bool] = None) -> WitnessPayload:
        """Witness post-market monitoring (AI-PMM.1). Art. 72, NIST MANAGE 4.1."""
        fa, fb, fc = float(monitoring_checks_run), float(anomalies_detected), float(PMM_TYPE_CODES.get(monitoring_type, 4))
        payload = self._mint_and_sign("AI-PMM.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"pmm-{monitoring_type}"
            ctx: Dict[str, Any] = {"provider": "post-market-monitoring", "monitoring_type": monitoring_type}
            if monitoring_plan_hash: ctx["monitoring_plan_hash"] = monitoring_plan_hash
            if period_start: ctx["period_start"] = period_start
            if period_end: ctx["period_end"] = period_end
            if report_generated is not None: ctx["report_generated"] = report_generated
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Chain, Violation, Charter, Registry, Reviewer, Safe State ───────

    def witness_chain_handoff(
        self,
        depth: int,
        target_agent: str,
        *,
        accepted: bool = True,
    ) -> WitnessPayload:
        """Witness a multi-agent chain handoff (AI-CHAIN.1).

        Args:
            depth: Position in the chain sequence (1-based).
            target_agent: Identifier of the agent receiving the handoff.
            accepted: Whether the handoff was accepted by the target.
        """
        fa = float(depth)
        fb = 1.0 if (self._config.cycle_id) else 0.0
        fc = 1.0 if accepted else 0.0
        payload = self._mint_and_sign("AI-CHAIN.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = target_agent
            ctx: Dict[str, Any] = {
                "provider": "chain",
                "target_agent": target_agent,
                "depth": depth,
                "accepted": accepted,
            }
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    def witness_chain_trust_handoff(
        self,
        target_agent_id: str,
        target_trust_level: int,
        *,
        cycle_id: Optional[str] = None,
        accepted: bool = True,
    ) -> WitnessPayload:
        """Witness a trust-level-aware chain handoff (AI-CHAIN.1 + optional AI-CHAIN.2).

        Tracks the effective trust level across all agents in the chain.
        If chain_min_trust_level is configured and strict mode is active,
        raises ChainTrustError when the effective level drops below the minimum.

        Auto-mints AI-CHAIN.2 (trust degradation) when the effective trust
        level drops compared to the previous handoff.

        Args:
            target_agent_id: Identifier of the target agent.
            target_trust_level: Trust level of the target agent (0-4).
            cycle_id: Override cycle_id for this chain.
            accepted: Whether the handoff was accepted.
        """
        prev_effective = (
            min(self._chain_trust_levels) if self._chain_trust_levels
            else target_trust_level
        )

        self._chain_trust_levels.append(target_trust_level)
        effective = min(self._chain_trust_levels)

        # Enforce minimum if configured
        min_level = getattr(self._config, "chain_min_trust_level", None)
        if min_level is not None and effective < min_level and self._strict:
            raise ChainTrustError(effective, min_level)

        fa = float(len(self._chain_trust_levels))
        fb = float(target_trust_level)
        fc = float(effective)
        payload = self._mint_and_sign("AI-CHAIN.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = target_agent_id
            payload.ai_context = {
                "provider": "chain-trust",
                "target_agent": target_agent_id,
                "target_trust_level": target_trust_level,
                "effective_trust_level": effective,
                "chain_depth": len(self._chain_trust_levels),
            }

        cid = cycle_id or self._config.cycle_id
        if cid:
            payload.cycle_id = cid

        payloads = [payload]

        # Auto-mint AI-CHAIN.2 if trust degraded
        if len(self._chain_trust_levels) > 1 and effective < prev_effective:
            degradation = extract_chain_trust_degradation_payload(
                self._tenant_id, prev_effective, effective,
                self._config.clearing_level,
                agent_id=self._config.agent_id,
                signing_key=self._config.signing_key,
                signing_key_id=getattr(self._config, "signing_key_id", None),
                signing_key_version=getattr(self._config, "signing_key_version", None),
                signing_algorithm=self._config.signing_algorithm,
                cycle_id=cid,
            )
            if self._config.clearing_level <= 1:
                degradation.ai_context = {
                    "provider": "chain-trust-degradation",
                    "previous_effective": prev_effective,
                    "new_effective": effective,
                    "target_agent": target_agent_id,
                }
            payloads.append(degradation)

        self._buffer.enqueue_many(payloads)
        return payload

    @property
    def chain_effective_trust_level(self) -> int:
        """The effective (minimum) trust level across all chain handoffs. Returns 4 if none."""
        return 4 if not self._chain_trust_levels else min(self._chain_trust_levels)

    @property
    def chain_trust_levels(self) -> List[int]:
        """The trust levels recorded at each chain handoff."""
        return list(self._chain_trust_levels)

    def witness_violation(
        self,
        severity: int,
        description: str,
        *,
        auto_detected: bool = False,
        policy_category: str = "unspecified",
    ) -> WitnessPayload:
        """Witness a policy violation (AI-VIO.1).

        Args:
            severity: Violation severity (1=low, 2=medium, 3=high, 4=critical).
            description: Human-readable violation description.
            auto_detected: True if detected automatically, False if manually reported.
            policy_category: One of: unspecified, content, access, data, safety, regulatory.
        """
        fa = float(max(1, min(4, severity)))
        fb = 1.0 if auto_detected else 0.0
        fc = float(POLICY_CATEGORIES.get(policy_category, 0))
        payload = self._mint_and_sign("AI-VIO.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"violation-sev{int(fa)}"
            payload.ai_context = {
                "provider": "violation",
                "severity": int(fa),
                "description": description,
                "auto_detected": auto_detected,
                "policy_category": policy_category,
            }
        self._buffer.enqueue_many([payload])
        return payload

    def witness_charter(
        self,
        charter_text: Optional[str] = None,
        *,
        charter_hash: Optional[str] = None,
        expected_hash: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness an agent charter or system prompt hash (AI-CHR.1).

        Args:
            charter_text: Raw charter/system prompt text (auto-hashed, never transmitted).
            charter_hash: Pre-computed hash. Provide this OR charter_text.
            expected_hash: Expected hash to verify against. Match=PASS, mismatch=FAIL.
        """
        if not charter_text and not charter_hash:
            raise ValueError("Provide charter_text or charter_hash")
        computed = charter_hash or sha256_truncated(charter_text)
        match = (computed == expected_hash) if expected_hash else True
        payload = self._mint_and_sign("AI-CHR.1", 1.0, 1.0 if match else 0.0, 0.0)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = "charter"
            ctx: Dict[str, Any] = {"provider": "charter", "charter_hash": computed}
            if expected_hash:
                ctx["expected_hash"] = expected_hash
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    def witness_model_registry(
        self,
        model_id: str,
        registry_id: str,
        *,
        found: bool = True,
        status: str = "approved",
    ) -> WitnessPayload:
        """Witness a model registry check (AI-MDL.8).

        Args:
            model_id: Model identifier checked against the registry.
            registry_id: Registry or database identifier.
            found: Whether the model was found in the registry.
            status: Approval status: approved, pending, or denied.
        """
        fa = 1.0
        fb = 1.0 if found else 0.0
        fc = float(APPROVAL_STATUS.get(status, 0))
        payload = self._mint_and_sign("AI-MDL.8", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = model_id
            payload.ai_context = {
                "provider": "model-registry",
                "model_id": model_id,
                "registry_id": registry_id,
                "found": found,
                "status": status,
            }
        self._buffer.enqueue_many([payload])
        return payload

    def witness_reviewer_identity(
        self,
        required: int,
        actual: int,
        *,
        method: str = "session",
        reviewer_id_hash: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness reviewer identity binding (AI-HITL.3).

        Args:
            required: Number of reviewers required (e.g., 2 for four-eyes).
            actual: Number of reviewers who actually reviewed.
            method: Binding method: none, session, or cryptographic.
            reviewer_id_hash: Pre-hashed reviewer identifier (never cleartext).
        """
        fa = float(required)
        fb = float(actual)
        fc = float(BINDING_METHODS.get(method, 0))
        payload = self._mint_and_sign("AI-HITL.3", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = "reviewer-identity"
            ctx: Dict[str, Any] = {
                "provider": "reviewer",
                "required": required,
                "actual": actual,
                "method": method,
            }
            if reviewer_id_hash:
                ctx["reviewer_id_hash"] = reviewer_id_hash
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    def witness_safe_state(
        self,
        *,
        mechanism_exists: bool = True,
        safe_state_confirmed: bool = True,
        mechanism_type: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness safe state attestation (AI-SAFE.1).

        Args:
            mechanism_exists: Whether a stop/interrupt mechanism exists and was tested.
            safe_state_confirmed: Whether safe state was confirmed after last invocation.
            mechanism_type: Type of mechanism (e.g., "kill_switch", "graceful_shutdown").
        """
        fa = 1.0
        fb = 1.0 if mechanism_exists else 0.0
        fc = 1.0 if safe_state_confirmed else 0.0
        payload = self._mint_and_sign("AI-SAFE.1", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = "safe-state"
            ctx: Dict[str, Any] = {
                "provider": "safe-state",
                "mechanism_exists": mechanism_exists,
                "safe_state_confirmed": safe_state_confirmed,
            }
            if mechanism_type:
                ctx["mechanism_type"] = mechanism_type
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Training Data (AI-DATA.3 / AI-DATA.4) ─────���────────────────────

    def witness_training_stats(
        self,
        row_count: int,
        feature_count: int,
        *,
        class_balance_ratio: Optional[float] = None,
        distribution_hash: Optional[str] = None,
        class_labels: Optional[List[str]] = None,
        summary: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness training dataset summary statistics (AI-DATA.3).

        Args:
            row_count: Total samples in the dataset.
            feature_count: Number of features/dimensions.
            class_balance_ratio: Majority/minority class ratio (0.0-1.0).
            distribution_hash: SHA-256 hash of the feature distribution summary.
            class_labels: List of class label names.
            summary: Human-readable dataset summary.
        """
        fa = float(row_count)
        fb = float(feature_count)
        fc = float(int(class_balance_ratio * 1000)) if class_balance_ratio is not None else 0.0
        payload = self._mint_and_sign("AI-DATA.3", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = "training-stats"
            ctx: Dict[str, Any] = {
                "provider": "training-stats",
                "row_count": row_count,
                "feature_count": feature_count,
            }
            if class_balance_ratio is not None:
                ctx["class_balance_ratio"] = class_balance_ratio
            if distribution_hash:
                ctx["distribution_hash"] = distribution_hash
            if class_labels:
                ctx["class_labels"] = class_labels
            if summary:
                ctx["summary"] = summary
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    def witness_training_pii_lifecycle(
        self,
        records_affected: int,
        *,
        completed: bool = True,
        event_type: str = "unspecified",
        dataset_id: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> WitnessPayload:
        """Witness a training data PII lifecycle event (AI-DATA.4).

        Args:
            records_affected: Number of records involved in the event.
            completed: Whether the event completed successfully.
            event_type: One of: unspecified, pseudonymization, anonymization,
                access_restriction, deletion, encryption.
            dataset_id: Identifier of the affected dataset.
            scope: Description of the event scope (e.g., "EU subjects only").
        """
        fa = float(records_affected)
        fb = 1.0 if completed else 0.0
        fc = float(PII_EVENT_TYPES.get(event_type, 0))
        payload = self._mint_and_sign("AI-DATA.4", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = "pii-lifecycle"
            ctx: Dict[str, Any] = {
                "provider": "pii-lifecycle",
                "event_type": event_type,
                "records_affected": records_affected,
                "completed": completed,
            }
            if dataset_id:
                ctx["dataset_id"] = dataset_id
            if scope:
                ctx["scope"] = scope
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Bias Assessment (AI-FAIR.3) ────────────────────────────────────

    def witness_bias_assessment(
        self,
        protected_attribute_count: int,
        all_thresholds_met: bool,
        *,
        max_disparity_pct: Optional[float] = None,
        methodology: Optional[str] = None,
        protected_attributes: Optional[List[str]] = None,
    ) -> "WitnessPayload":
        """Witness a bias assessment (AI-FAIR.3).

        Records that a bias assessment was conducted, how many protected
        attributes were tested, and whether all fairness thresholds were met.

        Args:
            protected_attribute_count: Number of demographic dimensions tested.
            all_thresholds_met: True if all fairness thresholds passed.
            max_disparity_pct: Worst-case disparity percentage (0-100).
            methodology: Assessment methodology name.
            protected_attributes: List of protected attributes tested.
        """
        fa = float(protected_attribute_count)
        fb = 1.0 if all_thresholds_met else 0.0
        fc = float(round(max_disparity_pct)) if max_disparity_pct is not None else 0.0
        payload = self._mint_and_sign("AI-FAIR.3", fa, fb, fc)
        if self._config.clearing_level <= 1:
            payload.ai_model_id = self._config.default_model_id or "bias-assessment"
            ctx: Dict[str, Any] = {
                "provider": "bias-assessment",
                "protected_attribute_count": protected_attribute_count,
                "all_thresholds_met": all_thresholds_met,
            }
            if methodology:
                ctx["methodology"] = methodology
            if protected_attributes:
                ctx["protected_attributes"] = protected_attributes
            if max_disparity_pct is not None:
                ctx["max_disparity_pct"] = max_disparity_pct
            payload.ai_context = ctx
        self._buffer.enqueue_many([payload])
        return payload

    # ── Trust Mesh (AI-TRUST.1 / AI-TRUST.2) ────────────────────────────

    @property
    def trust_registry(self) -> "TrustRegistry":
        """Lazy-initialized trust registry for this Witness."""
        if not hasattr(self, "_trust_registry"):
            from .trust import TrustRegistry
            self._trust_registry = TrustRegistry()
        return self._trust_registry

    @trust_registry.setter
    def trust_registry(self, registry: "TrustRegistry") -> None:
        self._trust_registry = registry

    def present_credential(self) -> "TrustCredential":
        """Build this agent's trust credential for presentation to another agent.

        Assembles a TrustCredential from the Witness's current config.
        Pure data assembly, no I/O, <1ms.

        Returns:
            TrustCredential ready to send to a counterpart.
        """
        from .trust import TrustCredential

        ts_ms = int(time.time() * 1000)
        # Use the agent_id + tenant as a pseudo-anchor fingerprint
        # In production, this would be the latest AI-ID.1 anchor
        fp_input = f"{self._config.agent_id or 'anonymous'}:{self._tenant_id}:{ts_ms}"

        from .trust import sign_credential

        procs = list(getattr(self, "_witnessed_procedures", set()))

        credential = TrustCredential(
            agent_id=self._config.agent_id or "anonymous",
            tenant_id=self._tenant_id,
            anchor_fingerprint=sha256_truncated(fp_input, 12),
            anchor_timestamp_ms=ts_ms,
            is_signed=bool(self._config.signing_key),
            procedures=procs,
            clearing_level=self._config.clearing_level,
            has_hardware_attestation=bool({"AI-HW.1", "AI-HW.3"} & getattr(self, "_witnessed_procedures", set())),
            has_guardrails=self._guardrails_required > 0 or len(self._guardrail_names) > 0,
        )
        if self._config.signing_key:
            credential.credential_signature = sign_credential(credential, self._config.signing_key)
        return credential

    def verify_trust(self, credential: "TrustCredential") -> "TrustResult":
        """Verify a counterpart agent's trust credential (AI-TRUST.1).

        Runs the 5-check verification pipeline against the trust registry.
        Mints an AI-TRUST.1 anchor recording the verification result (pass
        or fail). Both outcomes produce evidence.

        Args:
            credential: TrustCredential from the counterpart agent.

        Returns:
            TrustResult with granted status, trust level, and denial reason.
        """
        from .trust import verify_credential, TRUST_LEVEL_NAMES

        result = verify_credential(credential, self.trust_registry, self._tenant_id)

        # Mint AI-TRUST.1 anchor
        fa = 1.0  # verification was attempted
        fb = 1.0 if result.granted else 0.0
        fc = float(result.trust_level)
        payload = self._mint_and_sign("AI-TRUST.1", fa, fb, fc)

        if self._config.clearing_level <= 1:
            payload.ai_model_id = f"trust-{TRUST_LEVEL_NAMES.get(result.trust_level, 'unknown')}"
            ctx: Dict[str, Any] = {
                "provider": "trust-mesh",
                "counterpart_agent_id": credential.agent_id,
                "counterpart_tenant_id": credential.tenant_id,
                "trust_level": result.trust_level,
                "trust_level_name": TRUST_LEVEL_NAMES.get(result.trust_level, "unknown"),
                "checks_performed": result.checks_performed,
                "checks_passed": result.checks_passed,
                "granted": result.granted,
            }
            if result.denial_reason:
                ctx["denial_reason"] = result.denial_reason
            payload.ai_context = ctx

        self._buffer.enqueue_many([payload])

        # Mint AI-TRUST.2 (handshake evidence) with check counts
        t2_fa = float(result.checks_performed)
        t2_fb = float(result.checks_passed)
        t2_fc = 1.0 if result.granted else 0.0
        payload2 = self._mint_and_sign("AI-TRUST.2", t2_fa, t2_fb, t2_fc)

        if self._config.clearing_level <= 1:
            payload2.ai_model_id = "trust-handshake"
            payload2.ai_context = {
                "provider": "trust-mesh",
                "counterpart_agent_id": credential.agent_id,
                "handshake_result": "granted" if result.granted else "denied",
            }

        self._buffer.enqueue_many([payload2])

        return result

    def revoke(
        self,
        fingerprint: str,
        reason: str = "unspecified",
    ) -> str:
        """Revoke a previously-issued witness anchor (AI-REV.1).

        Mints an AI-REV.1 anchor that references the target anchor's
        fingerprint, creating an immutable revocation receipt. The
        revocation is enqueued for flush like any other anchor.

        Args:
            fingerprint: The 12-character anchor fingerprint to revoke.
            reason: Revocation reason. One of: model_recall, policy_violation,
                data_contamination, consent_withdrawal, regulatory_order,
                error_correction, unspecified.

        Returns:
            The fingerprint of the revocation anchor itself.

        Raises:
            ValueError: If fingerprint is empty or reason is not recognized.
        """
        if not fingerprint or not fingerprint.strip():
            raise ValueError("fingerprint is required for revocation")
        if reason not in REVOCATION_REASONS:
            raise ValueError(
                f"Unknown revocation reason: {reason!r}. "
                f"Valid: {', '.join(sorted(REVOCATION_REASONS.keys()))}"
            )

        policy_hash = (
            sha256_truncated(self._config.policy_version, 12)
            if self._config.policy_version else None
        )
        payload = extract_revocation_payload(
            tenant_id=self._tenant_id,
            target_fingerprint=fingerprint.strip(),
            reason=reason,
            clearing_level=self._config.clearing_level,
            agent_id=self._config.agent_id,
            signing_key=self._config.signing_key,
            signing_algorithm=self._config.signing_algorithm,
            cycle_id=self._config.cycle_id,
            policy_version_hash=policy_hash,
            jurisdiction=self._config.jurisdiction,
            legal_basis=self._config.legal_basis,
            purpose_class=self._config.purpose_class,
        )
        self._buffer.enqueue_many([payload])

        logger.info(
            "Revocation anchor minted: %s -> target %s (reason: %s)",
            payload.anchor_fingerprint, fingerprint, reason,
        )

        return payload.anchor_fingerprint

    def manifest(
        self,
        *,
        model: Optional[str] = None,
        procedure: Optional[str] = None,
        framework: Optional[str] = None,
        verdict: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 500,
    ) -> Dict[str, Any]:
        """Query the Compliance Manifest API for this tenant's anchors.

        Returns a structured compliance manifest with summary, coverage,
        and individual anchor records. Requires a connected endpoint.

        Args:
            model: Filter by AI model identifier.
            procedure: Filter by procedure ID (prefix supported, e.g., "AI-").
            framework: Filter to procedures mapped in a specific framework.
            verdict: "PASS", "FAIL", or None for all.
            since: ISO date string for window start (default: 30 days ago).
            until: ISO date string for window end (default: now).
            agent_id: Filter by agent identity.
            limit: Maximum anchors returned (default 500, max 5000).

        Returns:
            Dict with keys: tenant_id, summary, anchors, integrity, etc.

        Raises:
            RuntimeError: If the endpoint is unreachable or returns an error.
        """
        import json as json_mod
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError, URLError

        # Build query string
        params: List[str] = [f"limit={limit}", "format=json"]
        if model:
            params.append(f"model={model}")
        if procedure:
            params.append(f"procedure={procedure}")
        if framework:
            params.append(f"framework={framework}")
        if verdict:
            params.append(f"verdict={verdict}")
        if since:
            params.append(f"since={since}")
        if until:
            params.append(f"until={until}")
        if agent_id:
            params.append(f"agent_id={agent_id}")

        url = f"{self._config.endpoint.rstrip('/')}/manifest?{'&'.join(params)}"

        req = Request(url)
        req.add_header("Authorization", f"Bearer {self._config.api_key}")
        req.add_header("Accept", "application/json")

        try:
            with urlopen(req, timeout=self._config.timeout) as resp:
                return json_mod.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Manifest API returned {e.code}: {body}")
        except URLError as e:
            raise RuntimeError(f"Manifest API unreachable: {e.reason}")

    @property
    def gateway_mode(self) -> bool:
        """True if the SDK is deferring witnessing to an SWT3 Gateway."""
        return self._gateway_mode

    def record(
        self,
        inference: InferenceRecord,
        *,
        procedures: Optional[List[str]] = None,
        authorization_id: Optional[str] = None,
    ) -> None:
        """Record a witnessed inference. Extracts factors, applies clearing,
        and enqueues payloads for background flush.

        If gateway_mode is active, this is a no-op (the gateway handles witnessing).

        If factor_handoff is configured, factors are written to the handoff
        destination BEFORE clearing proceeds. If the handoff fails, the
        payload is NOT transmitted. This is a hard guarantee.

        This is the low-level API. Most users should use `wrap()` or
        `@inference()` instead.
        """
        if self._gateway_mode:
            logger.debug("Gateway mode: skipping witness for %s", inference.model_id)
            return

        # Merge guardrail config
        if self._guardrail_names and not inference.guardrail_names:
            inference.guardrail_names = self._guardrail_names
            inference.guardrails_active = len(self._guardrail_names)
            inference.guardrails_required = self._guardrails_required

        policy_hash = (
            sha256_truncated(self._config.policy_version, 12)
            if self._config.policy_version else None
        )
        payloads = extract_payloads(
            record=inference,
            tenant_id=self._tenant_id,
            clearing_level=self._config.clearing_level,
            latency_threshold_ms=self._latency_threshold_ms,
            guardrails_required=self._guardrails_required,
            procedures=procedures or self._config.procedures,
            agent_id=self._config.agent_id,
            signing_key=self._config.signing_key,
            signing_key_id=self._config.signing_key_id,
            signing_key_version=self._config.signing_key_version,
            signing_algorithm=self._config.signing_algorithm,
            cycle_id=self._config.cycle_id,
            policy_version_hash=policy_hash,
            jurisdiction=self._config.jurisdiction,
            legal_basis=self._config.legal_basis,
            purpose_class=self._config.purpose_class,
            authorization_id=authorization_id,
        )

        # Factor handoff: write full (uncleared) data to custody destination
        # BEFORE enqueuing the cleared payload for transmission.
        # If this fails, we do NOT proceed — factors must be safe first.
        if self._config.factor_handoff == "file" and self._config.factor_handoff_path:
            try:
                write_handoff_files(
                    payloads=payloads,
                    inference=inference,
                    tenant_id=self._tenant_id,
                    handoff_path=self._config.factor_handoff_path,
                )
                if not getattr(self, "_handoff_warned", False):
                    self._handoff_warned = True
                    print(
                        f"\n  [SWT3] {len(payloads)} anchors saved locally to {self._config.factor_handoff_path}"
                        f"\n  [SWT3] \u26a0 Local anchors won\u2019t survive a compliance audit."
                        f"\n  [SWT3] Connect to Axiom Engine \u2192 https://sovereign.tenova.io/signup?ref=sdk (free)\n"
                    )
            except OSError as e:
                logger.error(
                    "Factor handoff FAILED for %s — payload NOT transmitted. "
                    "Factors are retained locally. Error: %s",
                    inference.model_id, e,
                )
                raise

        self._buffer.enqueue_many(payloads)
        logger.debug(
            "Witnessed %s: %d payloads queued (buffer: %d)",
            inference.model_id, len(payloads), self._buffer.pending,
        )

    def export_evidence(self) -> "EvidenceExporter":
        """Return an EvidenceExporter pre-configured with this witness's state.

        Automatically wires WAL path, hardware attestation status, and
        signing key from the witness configuration so the exporter can
        build a complete evidence bundle with zero additional config.
        """
        from .exporters.evidence import EvidenceExporter
        hw = getattr(self, "_hardware_config", None)
        return EvidenceExporter(
            wal_dir=self._wal_path,
            tenant_id=self._config.tenant_id,
            agent_id=getattr(self._config, "agent_id", None),
            clearing_level=self._config.clearing_level,
            api_key=self._config.api_key,
            signing_key=getattr(self._config, "signing_key", None),
            has_hardware_attestation=bool(hw and hw.require_attestation),
        )

    def flush(self) -> List[WitnessReceipt]:
        """Force-flush all buffered payloads. Returns receipts."""
        return self._buffer.flush()

    async def flush_async(self) -> List[WitnessReceipt]:
        """Async force-flush. Non-blocking from the caller's event loop."""
        return await self._buffer.flush_async()

    def stop(self) -> List[WitnessReceipt]:
        """Stop the witness and flush remaining payloads."""
        return self._buffer.stop()

    async def stop_async(self) -> List[WitnessReceipt]:
        """Async stop. Non-blocking from the caller's event loop."""
        return await self._buffer.stop_async()

    @property
    def pending(self) -> int:
        """Number of payloads waiting to be flushed."""
        return self._buffer.pending

    @property
    def receipts(self) -> List[WitnessReceipt]:
        """All receipts from completed flushes."""
        return self._buffer.receipts

    @property
    def config(self) -> WitnessConfig:
        """Current witness configuration (read-only)."""
        return self._config
