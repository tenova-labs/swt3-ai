"""SWT3 AI Witness SDK — Type definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class WitnessConfig:
    """Configuration for the Witness SDK."""

    endpoint: str
    api_key: str
    clearing_level: int = 1  # 0=analytics, 1=standard, 2=sensitive, 3=classified
    buffer_size: int = 10  # flush after N anchors
    flush_interval: float = 5.0  # flush after N seconds
    timeout: float = 10.0  # HTTP timeout for flush
    max_retries: int = 3  # retry count with exponential backoff
    procedures: Optional[List[str]] = None  # subset of AI procedures to witness (None = all)
    factor_handoff: Optional[str] = None  # "file" to enable local file export
    factor_handoff_path: Optional[str] = None  # directory for factor handoff files
    agent_id: Optional[str] = None  # SDK instance identity (survives all clearing levels)
    signing_key: Optional[str] = None  # HMAC-SHA256 shared secret for payload signing
    signing_key_id: Optional[str] = None  # Key identifier for O(1) server-side validation
    signing_key_version: Optional[int] = None  # Monotonic version counter for key rotation
    cycle_id: Optional[str] = None  # Multi-agent chain link (survives all clearing levels)
    policy_version: Optional[str] = None  # Policy config identifier for version binding
    jurisdiction: Optional[str] = None  # ISO 3166-1 jurisdiction code (e.g., "DE", "US-VA")
    legal_basis: Optional[str] = None  # GDPR legal basis (e.g., "consent", "legitimate_interest")
    purpose_class: Optional[str] = None  # CJT purpose classification (e.g., "clinical_decision_support")
    token_budget: Optional[int] = None  # Mint anchor every N tokens (None = disabled, use buffer_size)
    chain_min_trust_level: Optional[int] = None  # Minimum effective trust level for chain handoffs (0-4)
    flush_target: Optional[str] = None  # "http" (default) or "redis" for high-throughput decoupled intake
    redis_url: Optional[str] = None  # Redis URL when flush_target="redis" (e.g., redis://localhost:6379)
    redis_stream: Optional[str] = None  # Redis stream name (default: "swt3:anchors")
    digest_algorithm: Optional[str] = None  # Only "sha256" in v0.5.4 (crypto-agility signal)

    def __post_init__(self) -> None:
        if not self.endpoint:
            raise ValueError("endpoint is required")
        if not self.api_key:
            raise ValueError("api_key is required")
        if not self.api_key.startswith("axm_"):
            raise ValueError("api_key must start with 'axm_'")
        if self.clearing_level not in (0, 1, 2, 3):
            raise ValueError("clearing_level must be 0, 1, 2, or 3")
        if self.agent_id is not None and not self.agent_id.strip():
            raise ValueError("agent_id must be non-empty if provided")
        # Normalize endpoint - strip trailing slash
        self.endpoint = self.endpoint.rstrip("/")


@dataclass
class WitnessPayload:
    """A single witness anchor payload ready for the ingestion endpoint."""

    procedure_id: str
    factor_a: float
    factor_b: float
    factor_c: float
    clearing_level: int
    anchor_fingerprint: str
    anchor_epoch: int
    fingerprint_timestamp_ms: int
    ai_model_id: Optional[str] = None
    ai_prompt_hash: Optional[str] = None
    ai_response_hash: Optional[str] = None
    ai_system_prompt_hash: Optional[str] = None
    ai_latency_ms: Optional[int] = None
    ai_input_tokens: Optional[int] = None
    ai_output_tokens: Optional[int] = None
    ai_context: Optional[Dict[str, Any]] = None
    agent_id: Optional[str] = None  # operational metadata, survives all clearing levels
    cycle_id: Optional[str] = None  # multi-agent chain link, survives all clearing levels
    payload_signature: Optional[str] = None  # HMAC-SHA256 hex string
    signing_key_id: Optional[str] = None  # Key identifier (routing metadata, not part of HMAC)
    signing_key_version: Optional[int] = None  # Key version (routing metadata, not part of HMAC)
    policy_version_hash: Optional[str] = None  # SHA-256[:12] of policy_version (survives all clearing levels)
    jurisdiction: Optional[str] = None  # ISO 3166-1 code (survives all clearing levels)
    legal_basis: Optional[str] = None  # GDPR legal basis (survives all clearing levels)
    purpose_class: Optional[str] = None  # CJT purpose classification (survives all clearing levels)
    authorization_id: Optional[str] = None  # CJT pre-inference authorization receipt (survives all clearing levels)
    revocation_target: Optional[str] = None  # fingerprint of anchor being revoked (survives all clearing levels)
    revocation_reason: Optional[str] = None  # reason for revocation (survives all clearing levels)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for JSON transmission."""
        d: Dict[str, Any] = {
            "procedure_id": self.procedure_id,
            "factor_a": self.factor_a,
            "factor_b": self.factor_b,
            "factor_c": self.factor_c,
            "clearing_level": self.clearing_level,
            "anchor_fingerprint": self.anchor_fingerprint,
            "anchor_epoch": self.anchor_epoch,
            "fingerprint_timestamp_ms": self.fingerprint_timestamp_ms,
        }
        # Optional fields — only include if present
        if self.ai_model_id is not None:
            d["ai_model_id"] = self.ai_model_id
        if self.ai_prompt_hash is not None:
            d["ai_prompt_hash"] = self.ai_prompt_hash
        if self.ai_response_hash is not None:
            d["ai_response_hash"] = self.ai_response_hash
        if self.ai_system_prompt_hash is not None:
            d["ai_system_prompt_hash"] = self.ai_system_prompt_hash
        if self.ai_latency_ms is not None:
            d["ai_latency_ms"] = self.ai_latency_ms
        if self.ai_input_tokens is not None:
            d["ai_input_tokens"] = self.ai_input_tokens
        if self.ai_output_tokens is not None:
            d["ai_output_tokens"] = self.ai_output_tokens
        if self.ai_context is not None:
            d["ai_context"] = self.ai_context
        if self.agent_id is not None:
            d["agent_id"] = self.agent_id
        if self.cycle_id is not None:
            d["cycle_id"] = self.cycle_id
        if self.payload_signature is not None:
            d["payload_signature"] = self.payload_signature
        if self.signing_key_id is not None:
            d["signing_key_id"] = self.signing_key_id
        if self.signing_key_version is not None:
            d["signing_key_version"] = self.signing_key_version
        if self.policy_version_hash is not None:
            d["policy_version_hash"] = self.policy_version_hash
        if self.jurisdiction is not None:
            d["jurisdiction"] = self.jurisdiction
        if self.legal_basis is not None:
            d["legal_basis"] = self.legal_basis
        if self.purpose_class is not None:
            d["purpose_class"] = self.purpose_class
        if self.authorization_id is not None:
            d["authorization_id"] = self.authorization_id
        if self.revocation_target is not None:
            d["revocation_target"] = self.revocation_target
        if self.revocation_reason is not None:
            d["revocation_reason"] = self.revocation_reason
        return d


@dataclass
class WitnessReceipt:
    """Receipt returned by the ingestion endpoint for a single anchor."""

    procedure_id: str
    verdict: str  # "PASS" or "FAIL"
    swt3_anchor: str
    clearing_level: int
    witnessed_at: str
    verification_url: str
    ok: bool = True
    error: Optional[str] = None


@dataclass
class InferenceRecord:
    """Internal record of a witnessed inference before factor extraction."""

    model_id: str
    model_hash: str  # SHA-256 of model identifier string
    prompt_hash: str  # SHA-256 first 16 hex chars
    response_hash: str  # SHA-256 first 16 hex chars
    latency_ms: int
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    guardrails_active: int = 0
    guardrails_required: int = 0
    guardrail_passed: bool = True
    has_refusal: bool = False
    provider: str = "unknown"
    system_fingerprint: Optional[str] = None
    system_prompt_hash: Optional[str] = None  # SHA-256[:16] of system prompt only (instruction drift detection)
    guardrail_names: List[str] = field(default_factory=list)
    tool_name: Optional[str] = None  # for AI-TOOL.1 procedure
    tool_call_id: Optional[str] = None  # auto-generated UUID for tool calls
    access_target: Optional[str] = None  # for AI-ACC.1: URI/endpoint/resource name
    access_granted: bool = True  # for AI-ACC.1: whether access succeeded
    access_scope: Optional[str] = None  # for AI-ACC.1: declared authorization scope


@dataclass
class RagChunk:
    """A single retrieved context chunk for RAG witnessing.

    Pass raw strings to witness_rag_context() for auto-hashing, or
    construct RagChunk instances for full control over chunk metadata.
    """

    content_hash: str  # SHA-256[:16] of chunk text
    source_id: Optional[str] = None  # document or page identifier
    similarity_score: Optional[float] = None  # 0.0-1.0 relevance score
    metadata: Optional[Dict[str, Any]] = None  # extensible chunk metadata


@dataclass
class ModelWeightInfo:
    """Model weight file metadata for AI-MDL.5 witnessing."""

    file_hash: str  # SHA-256 of weight file
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None
    format: Optional[str] = None  # safetensors, gguf, bin, pt


@dataclass
class AdapterInfo:
    """LoRA/QLoRA/PEFT adapter metadata for AI-MDL.6 witnessing."""

    name: str
    adapter_hash: str  # SHA-256 of adapter weights
    base_model: Optional[str] = None


@dataclass
class SkillInfo:
    """Skill/tool/plugin metadata for AI-SKILL.1 witnessing."""

    name: str
    version: Optional[str] = None
    skill_hash: Optional[str] = None  # SHA-256 of skill definition


@dataclass
class MemorySource:
    """Persistent memory source metadata for AI-SKILL.2 witnessing."""

    source_type: str  # vector_store, conversation, scratchpad, knowledge_base
    source_id: Optional[str] = None
    content_hash: Optional[str] = None  # SHA-256 of memory contents


@dataclass
class GpuInfo:
    """GPU metadata for AI-HW.1 witnessing. IDs are pre-hashed."""

    name: str  # e.g., "NVIDIA H100 80GB HBM3"
    memory_mb: int
    bus_id_hash: str  # SHA-256 truncated, never cleartext
    uuid_hash: str  # SHA-256 truncated, never cleartext


@dataclass
class HardwareSnapshot:
    """Accelerator inventory snapshot for AI-HW.1 witnessing."""

    gpus: List[GpuInfo] = field(default_factory=list)
    driver_version: str = ""
    cuda_version: str = ""
    topology: str = "unknown"  # NVL72, DGX-H100, DGX-A100, HGX, multi-gpu, single, unknown
    interconnect: str = "unknown"  # nvswitch, nvlink, pcie, unknown
    total_memory_mb: int = 0
    hostname_hash: str = ""  # SHA-256 truncated, never cleartext


@dataclass
class PcrRegister:
    """TPM PCR register for AI-HW.3 witnessing. Values are pre-hashed."""

    index: int
    bank: str  # "sha256"
    digest_hash: str  # SHA-256 of raw PCR value, never cleartext


@dataclass
class TPMSnapshot:
    """TPM 2.0 attestation snapshot for AI-HW.3 witnessing."""

    available: bool = False
    manufacturer: str = ""  # SHA-256 hashed, never cleartext
    firmware_version: str = ""  # SHA-256 hashed, never cleartext
    pcrs: List[PcrRegister] = field(default_factory=list)
    endorsement_key_hash: str = ""  # SHA-256 of the EK, never cleartext
    hostname_hash: str = ""  # SHA-256 truncated, never cleartext


@dataclass
class EnvironmentSnapshot:
    """Environmental telemetry snapshot for AI-ENV.1 / AI-ENV.2 witnessing."""

    temperature_celsius: int = 0        # highest detected temp (0 if unavailable)
    power_watts: int = 0                # total power draw (0 if unavailable)
    thermal_zones: int = 0              # count of thermal zones detected
    power_domains: int = 0              # count of power domains detected
    hostname_hash: str = ""             # SHA-256 truncated, never cleartext
    node_type: str = "unknown"          # unknown, datacenter, edge, residential, mobile


# ── Declarative Governance Config Types ────────────────────────────────

@dataclass
class TrustMeshConfig:
    """Trust mesh configuration from .swt3.yaml trust_mesh section."""

    mode: str = "permissive"  # strict | permissive | monitor
    min_trust_level: int = 1
    require_signature: bool = False
    freshness_window: int = 86400  # seconds (24h default)
    trusted_tenants: List[str] = field(default_factory=list)
    trusted_agents: List[Dict[str, str]] = field(default_factory=list)
    deny_agents: List[str] = field(default_factory=list)
    deny_tenants: List[str] = field(default_factory=list)
    required_procedures: List[str] = field(default_factory=list)
    signing_keys: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class RuntimeProfileConfig:
    """Hardware runtime profile for config-time topology binding."""

    expected_topology: Optional[str] = None
    min_gpu_count: Optional[int] = None
    min_memory_mb: Optional[int] = None
    expected_accelerator: Optional[str] = None  # substring match against GPU names
    max_temperature_celsius: Optional[int] = None
    max_power_watts: Optional[int] = None


@dataclass
class HardwareConfig:
    """Hardware attestation configuration from .swt3.yaml hardware section."""

    require_attestation: bool = False
    attestation_freshness: int = 3600  # seconds
    allowed_methods: List[str] = field(default_factory=list)
    runtime_profile: Optional[RuntimeProfileConfig] = None


@dataclass
class DensityPolicyConfig:
    """Density policy configuration from .swt3.yaml density_policy section."""

    min_anchors_per_1000_tokens: int = 1
    required_providers: List[str] = field(default_factory=list)
    max_chain_gap_seconds: int = 60
    require_signing_key: bool = False
    min_trust_level: int = 1


@dataclass
class ChainRule:
    """A single chain enforcement rule from .swt3.yaml mcp_policy.rules."""

    match: str = "*"
    action: str = "block"   # "block" | "log"
    reason: str = ""
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChainPolicyViolation:
    """Error context for a chain density policy violation."""

    rule: str = ""
    tool_name: str = ""
    action: str = "blocked"  # "blocked" | "logged"
    reason: str = ""
    timestamp: float = 0.0
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class McpPolicyConfig:
    """MCP tool witnessing policy from .swt3.yaml mcp_policy section."""

    witnessed_tools: List[str] = field(default_factory=list)  # glob patterns
    exempt_tools: List[str] = field(default_factory=list)     # glob patterns
    require_trust_level: int = 0
    auto_witness: bool = True
    block_on_failure: bool = False
    max_velocity: Optional[str] = None        # "N/Xs" format (e.g., "4/30s")
    max_chain_depth: Optional[int] = None     # max sequential dependent tool calls
    tool_allowlist: List[str] = field(default_factory=list)
    tool_blocklist: List[str] = field(default_factory=list)
    fail_secure: bool = True
    rules: List["ChainRule"] = field(default_factory=list)
    max_tokens_per_session: Optional[int] = None


@dataclass
class MerkleConfig:
    """Merkle accumulator configuration from .swt3.yaml merkle section."""

    enabled: bool = True
    accumulator_interval: int = 0


@dataclass
class SkillCardConfig:
    """Skill card configuration from .swt3.yaml skill_card section."""

    skills: List[Any] = field(default_factory=list)  # list of str or SkillInfo
    expected_manifest_hash: Optional[str] = None


@dataclass
class LoadedConfig:
    """Full parsed config returned by load_full_config()."""

    witness_kwargs: Dict[str, Any] = field(default_factory=dict)
    trust_mesh: Optional[TrustMeshConfig] = None
    hardware: Optional[HardwareConfig] = None
    skill_card: Optional[SkillCardConfig] = None
    density_policy: Optional[DensityPolicyConfig] = None
    mcp_policy: Optional[McpPolicyConfig] = None
    merkle: Optional[MerkleConfig] = None
    policy: Optional[Dict[str, Any]] = None
    config_hash: str = ""
