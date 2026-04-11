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
    ai_latency_ms: Optional[int] = None
    ai_input_tokens: Optional[int] = None
    ai_output_tokens: Optional[int] = None
    ai_context: Optional[Dict[str, Any]] = None
    agent_id: Optional[str] = None  # operational metadata, survives all clearing levels
    payload_signature: Optional[str] = None  # HMAC-SHA256 hex string

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
        if self.payload_signature is not None:
            d["payload_signature"] = self.payload_signature
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
    guardrail_names: List[str] = field(default_factory=list)
    tool_name: Optional[str] = None  # for AI-TOOL.1 procedure
    tool_call_id: Optional[str] = None  # auto-generated UUID for tool calls
