//! SWT3 AI Witness SDK type definitions.

/// A witness payload ready for transmission to the witness endpoint.
#[derive(Debug, Clone)]
pub struct WitnessPayload {
    pub procedure_id: String,
    pub factor_a: f64,
    pub factor_b: f64,
    pub factor_c: f64,
    pub clearing_level: u8,
    pub anchor_fingerprint: String,
    pub anchor_epoch: i64,
    pub fingerprint_timestamp_ms: i64,
    pub ai_model_id: Option<String>,
    pub ai_prompt_hash: Option<String>,
    pub ai_response_hash: Option<String>,
    pub ai_latency_ms: Option<i64>,
    pub ai_input_tokens: Option<i64>,
    pub ai_output_tokens: Option<i64>,
    pub agent_id: Option<String>,
    pub cycle_id: Option<String>,
    pub payload_signature: Option<String>,
    pub signing_algorithm: Option<SigningAlgorithm>,
    pub signing_key_id: Option<String>,
    pub signing_key_version: Option<u32>,
    pub policy_version_hash: Option<String>,
    pub jurisdiction: Option<String>,
    pub legal_basis: Option<String>,
    pub purpose_class: Option<String>,
    pub authorization_id: Option<String>,
    pub revocation_target: Option<String>,
    pub revocation_reason: Option<String>,
}

/// A receipt returned by the witness endpoint after successful anchoring.
#[derive(Debug, Clone)]
pub struct WitnessReceipt {
    pub procedure_id: String,
    pub verdict: String,
    pub swt3_anchor: String,
    pub clearing_level: u8,
    pub witnessed_at: String,
    pub verification_url: String,
    pub ok: bool,
    pub error: Option<String>,
}

/// Configuration for a Witness client.
#[derive(Debug, Clone)]
pub struct WitnessConfig {
    pub endpoint: String,
    pub api_key: String,
    pub tenant_id: String,
    pub clearing_level: u8,
    pub buffer_size: usize,
    pub flush_interval_secs: f64,
    pub timeout_ms: u64,
    pub max_retries: u32,
    pub agent_id: Option<String>,
    pub signing_key: Option<String>,
    pub signing_algorithm: Option<SigningAlgorithm>,
    pub cycle_id: Option<String>,
    pub policy_version: Option<String>,
    pub jurisdiction: Option<String>,
    pub legal_basis: Option<String>,
    pub purpose_class: Option<String>,
}

/// Signing algorithm for payload signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// HMAC-SHA256 (default, symmetric).
    HmacSha256,
    /// ML-DSA-65 / FIPS 204 (post-quantum, asymmetric).
    MlDsa65,
}

impl SigningAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha256",
            Self::MlDsa65 => "ml-dsa-65",
        }
    }
}

/// Revocation reason codes for AI-REV.1 anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    Unspecified = 0,
    ModelRecall = 1,
    PolicyViolation = 2,
    DataContamination = 3,
    ConsentWithdrawal = 4,
    RegulatoryOrder = 5,
    ErrorCorrection = 6,
}

impl RevocationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::ModelRecall => "model_recall",
            Self::PolicyViolation => "policy_violation",
            Self::DataContamination => "data_contamination",
            Self::ConsentWithdrawal => "consent_withdrawal",
            Self::RegulatoryOrder => "regulatory_order",
            Self::ErrorCorrection => "error_correction",
        }
    }

    pub fn code(&self) -> u8 {
        *self as u8
    }
}

/// Trust levels for agent-to-agent Trust Mesh verification (AI-TRUST.1).
pub const TRUST_DENIED: u8 = 0;
pub const TRUST_BASIC: u8 = 1;
pub const TRUST_VERIFIED: u8 = 2;
pub const TRUST_ATTESTED: u8 = 3;
pub const TRUST_SOVEREIGN: u8 = 4;

/// Denial reason codes for Trust Mesh verification.
pub const DENIAL_ANCHOR_NOT_FOUND: &str = "anchor_not_found";
pub const DENIAL_ANCHOR_EXPIRED: &str = "anchor_expired";
pub const DENIAL_ANCHOR_REVOKED: &str = "anchor_revoked";
pub const DENIAL_SIGNATURE_MISSING: &str = "signature_missing";
pub const DENIAL_TENANT_NOT_TRUSTED: &str = "tenant_not_trusted";
pub const DENIAL_DENY_LISTED: &str = "deny_listed";
pub const DENIAL_INSUFFICIENT_PROCEDURES: &str = "insufficient_procedures";
pub const DENIAL_SIGNATURE_INVALID: &str = "signature_invalid";
pub const DENIAL_SIGNATURE_UNVERIFIABLE: &str = "signature_unverifiable";
pub const DENIAL_INSUFFICIENT_TRUST_LEVEL: &str = "insufficient_trust_level";
pub const DENIAL_TIMESTAMP_FUTURE: &str = "timestamp_future";
pub const DENIAL_RATE_LIMITED: &str = "rate_limited";

/// Key purpose for key attestation (AI-TRUST.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    Signing,
    Encryption,
    Delegation,
}

impl KeyPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Signing => "signing",
            Self::Encryption => "encryption",
            Self::Delegation => "delegation",
        }
    }
}

/// AI model lifecycle stages (NIST AI RMF MAP 1.3).
pub const LIFECYCLE_STAGES: &[&str] = &[
    "design", "development", "testing", "deployment", "monitoring", "decommission",
];

/// METAGOV governance domain scope codes (AI-METAGOV.5).
pub const METAGOV_SCOPES: &[&str] = &[
    "verdict_rules", "trust_mesh", "enforcement", "clearing", "full",
];

/// METAGOV permission level codes (AI-METAGOV.5).
pub const METAGOV_PERMISSIONS: &[&str] = &["read", "modify", "approve"];

/// METAGOV emergency override reason codes (AI-METAGOV.6).
pub const METAGOV_OVERRIDE_REASONS: &[&str] = &[
    "unspecified", "incident_response", "regulatory_deadline", "system_failure", "security_breach",
];

/// METAGOV review status codes (AI-METAGOV.6).
pub const METAGOV_REVIEW_STATUSES: &[&str] = &["unreviewed", "attested", "revoked"];

/// METAGOV governance divergence codes (AI-METAGOV.7).
pub const METAGOV_DIVERGENCE_TYPES: &[&str] = &[
    "equivalent", "version_divergent", "structural_divergent", "coverage_divergent",
];

/// METAGOV attestation purity tiers (AI-METAGOV.8).
pub const METAGOV_PURITY_TIERS: &[&str] = &["verified_pure", "unverified_purity", "impure"];