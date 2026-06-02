"""SWT3 AI Witness SDK — Cryptographic attestation for AI inference.

Usage:
    from swt3_ai import Witness
    from openai import OpenAI

    witness = Witness(
        endpoint="https://sovereign.tenova.io",
        api_key="axm_live_...",
        tenant_id="YOUR_TENANT_ID",
    )

    client = witness.wrap(OpenAI())
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )

    # response is untouched — witnessing happens in the background
    print(response.choices[0].message.content)

    # Graceful shutdown (also happens automatically at exit)
    receipts = witness.flush()

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

__version__ = "0.5.4"

from .witness import Witness, GatekeeperError, ChainEnforcer, PolicyViolationError
from .exporters.chain_monitor import ChainMonitorExporter
from .exporters.evidence import EvidenceExporter
from .types import (
    WitnessConfig, WitnessReceipt, WitnessPayload, RagChunk,
    ModelWeightInfo, AdapterInfo, SkillInfo, MemorySource,
    GpuInfo, HardwareSnapshot, PcrRegister, TPMSnapshot, EnvironmentSnapshot,
    ChainRule, ChainPolicyViolation,
)
from .signing import (
    sign_payload, generate_mldsa_keypair, verify_mldsa,
    SIGNING_ALGORITHM_HMAC, SIGNING_ALGORITHM_MLDSA, VALID_SIGNING_ALGORITHMS,
)
from .config import load_config, load_full_config, compute_config_hash
from .types import (
    TrustMeshConfig, HardwareConfig, RuntimeProfileConfig, SkillCardConfig, DensityPolicyConfig, McpPolicyConfig, MerkleConfig, LoadedConfig,
)
from .witness import (CONTENT_TYPE_CODES, MARKING_METHODS, BASELINE_MODE_CODES, LICENSE_TYPE_CODES,
    SBOM_FORMAT_CODES, REDTEAM_CATEGORY_CODES, CONSENT_BASIS_CODES,
    DRIFT_TYPE_CODES, LOG_FORMAT_CODES, INCIDENT_SEVERITY_CODES, INCIDENT_TYPE_CODES,
    BENCHMARK_TYPE_CODES, PERTURBATION_TYPE_CODES, CYBER_FRAMEWORK_CODES,
    DISCLOSURE_TYPE_CODES, RECIPIENT_TYPE_CODES, DETECTION_METHOD_CODES,
    PROCESSING_TYPE_CODES, DECISION_TYPE_CODES, CLASSIFICATION_CODES,
    REPORTING_STATUS_CODES, SUPPLY_RISK_CODES, PMM_TYPE_CODES)
from .schema import validate_schema, ValidationResult, ValidationError as SchemaValidationError
from .wal import WriteAheadLog
from .merkle import (
    hash_leaf, hash_node, get_merkle_root, get_merkle_proof, verify_merkle_proof,
    MerkleAccumulator, MerkleProof, MerkleProofStep, SessionRoot,
)
from .trust import (
    TrustCredential, TrustResult, TrustRegistry,
    TRUST_DENIED, TRUST_BASIC, TRUST_VERIFIED, TRUST_ATTESTED, TRUST_SOVEREIGN,
)
from .sentinel_client import SentinelClient, SentinelCheckResult, SentinelViolation

__all__ = [
    "Witness",
    "GatekeeperError",
    "ChainEnforcer",
    "PolicyViolationError",
    "ChainRule",
    "ChainPolicyViolation",
    "ChainMonitorExporter",
    "EvidenceExporter",
    "WitnessConfig",
    "WitnessReceipt",
    "WitnessPayload",
    "RagChunk",
    "ModelWeightInfo",
    "AdapterInfo",
    "SkillInfo",
    "MemorySource",
    "GpuInfo",
    "HardwareSnapshot",
    "EnvironmentSnapshot",
    "sign_payload",
    "generate_mldsa_keypair",
    "verify_mldsa",
    "SIGNING_ALGORITHM_HMAC",
    "SIGNING_ALGORITHM_MLDSA",
    "VALID_SIGNING_ALGORITHMS",
    "load_config",
    "load_full_config",
    "compute_config_hash",
    "TrustMeshConfig",
    "HardwareConfig",
    "RuntimeProfileConfig",
    "SkillCardConfig",
    "DensityPolicyConfig",
    "McpPolicyConfig",
    "MerkleConfig",
    "LoadedConfig",
    "hash_leaf",
    "hash_node",
    "get_merkle_root",
    "get_merkle_proof",
    "verify_merkle_proof",
    "MerkleAccumulator",
    "MerkleProof",
    "MerkleProofStep",
    "SessionRoot",
    "validate_schema",
    "ValidationResult",
    "SchemaValidationError",
    "TrustCredential",
    "TrustResult",
    "TrustRegistry",
    "TRUST_DENIED",
    "TRUST_BASIC",
    "TRUST_VERIFIED",
    "TRUST_ATTESTED",
    "TRUST_SOVEREIGN",
    "WriteAheadLog",
    "SentinelClient",
    "SentinelCheckResult",
    "SentinelViolation",
    "CONTENT_TYPE_CODES",
    "MARKING_METHODS",
    "BASELINE_MODE_CODES",
    "LICENSE_TYPE_CODES",
    "SBOM_FORMAT_CODES",
    "REDTEAM_CATEGORY_CODES",
    "CONSENT_BASIS_CODES",
    "DRIFT_TYPE_CODES",
    "LOG_FORMAT_CODES",
    "INCIDENT_SEVERITY_CODES",
    "INCIDENT_TYPE_CODES",
    "BENCHMARK_TYPE_CODES",
    "PERTURBATION_TYPE_CODES",
    "CYBER_FRAMEWORK_CODES",
    "DISCLOSURE_TYPE_CODES",
    "RECIPIENT_TYPE_CODES",
    "DETECTION_METHOD_CODES",
    "PROCESSING_TYPE_CODES",
    "DECISION_TYPE_CODES",
    "CLASSIFICATION_CODES",
    "REPORTING_STATUS_CODES",
    "SUPPLY_RISK_CODES",
    "PMM_TYPE_CODES",
    "__version__",
]
