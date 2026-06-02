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
