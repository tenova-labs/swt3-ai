//! SWT3 AI Witness SDK for Rust.
//!
//! Cryptographic attestation for AI inference. Mint fingerprints,
//! verify anchors, and sign payloads with cross-language parity.
//!
//! ```rust
//! use swt3_ai::{mint_fingerprint, sha256_truncated, sign_payload};
//!
//! let fp = mint_fingerprint("MY_TENANT", "AI-INF.1", 1.0, 1.0, 0.0, 1774800000000);
//! let hash = sha256_truncated("Hello, world!", 16);
//! let sig = sign_payload("my-key", &fp, Some("agent-1"));
//! ```
//!
//! See <https://tenova.io> for full protocol documentation.

pub mod types;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// SDK version.
pub const VERSION: &str = "0.5.2";

/// Mint an SWT3 fingerprint from the canonical formula.
///
/// The fingerprint is the first 12 hex characters of:
/// `SHA-256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}")`
///
/// This formula is locked and must produce identical output across
/// all SWT3 SDK implementations (Python, TypeScript, Rust, C#, Ruby).
pub fn mint_fingerprint(
    tenant_id: &str,
    procedure_id: &str,
    factor_a: f64,
    factor_b: f64,
    factor_c: f64,
    timestamp_ms: i64,
) -> String {
    let input = format!(
        "WITNESS:{}:{}:{}:{}:{}:{}",
        tenant_id,
        procedure_id,
        num_str(factor_a),
        num_str(factor_b),
        num_str(factor_c),
        timestamp_ms,
    );
    sha256_hex(&input, 12)
}

/// Compute a truncated SHA-256 hash of the input string.
///
/// Default length is 16 hex characters (used for prompt/response hashing).
/// Use 12 for fingerprints, 64 for full digests.
pub fn sha256_truncated(data: &str, length: usize) -> String {
    sha256_hex(data, length)
}

/// Compute a SHA-256 hash and return the first `length` hex characters.
pub fn sha256_hex(data: &str, length: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    let full_hex = hex::encode(result);
    full_hex[..length.min(64)].to_string()
}

/// Sign a payload with HMAC-SHA256 for non-repudiation.
///
/// If `agent_id` is provided, the message is `"{fingerprint}:{agent_id}"`.
/// Otherwise, the message is just the fingerprint.
///
/// Returns a 64-character lowercase hex string.
pub fn sign_payload(
    signing_key: &str,
    anchor_fingerprint: &str,
    agent_id: Option<&str>,
) -> String {
    let message = match agent_id {
        Some(id) => format!("{}:{}", anchor_fingerprint, id),
        None => anchor_fingerprint.to_string(),
    };

    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Get the current timestamp in milliseconds and epoch seconds.
pub fn timestamp_ms() -> (i64, i64) {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as i64;
    let epoch = ms / 1000;
    (ms, epoch)
}

/// Format a numeric factor as a string, matching the canonical formula.
///
/// Integer-valued floats are formatted without decimals: 1.0 -> "1"
/// True floats keep their decimals: 1.5 -> "1.5"
fn num_str(v: f64) -> String {
    if v.is_finite() && v == v.floor() {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fingerprint vectors (tenant ID sanitized to ENCLAVE_ALPHA)
    #[test]
    fn fingerprint_vector_1() {
        assert_eq!(
            mint_fingerprint("ENCLAVE_ALPHA", "AI-INF.1", 1.0, 1.0, 0.0, 1774800000000),
            "f7f20b581cbf"
        );
    }

    #[test]
    fn fingerprint_vector_2() {
        assert_eq!(
            mint_fingerprint("AWS_NITRO_ENCLAVE", "AI-INF.2", 5000.0, 8000.0, 1.0, 1774800001000),
            "4ed784765e6c"
        );
    }

    #[test]
    fn fingerprint_vector_3() {
        assert_eq!(
            mint_fingerprint("ENCLAVE_ALPHA", "AI-GRD.1", 2.0, 3.0, 0.0, 1774800002000),
            "7f8629340cbd"
        );
    }

    #[test]
    fn fingerprint_vector_4() {
        assert_eq!(
            mint_fingerprint("AZURE_TRUSTED_EXEC", "AI-MDL.1", 1.0, 0.0, 1.0, 1774800003000),
            "c36d477b3c2d"
        );
    }

    #[test]
    fn fingerprint_vector_5() {
        assert_eq!(
            mint_fingerprint("ACME_DEFENSE", "AI-FAIR.1", 15.0, 15.0, 0.0, 1774800004000),
            "53180f5ae221"
        );
    }

    #[test]
    fn fingerprint_vector_6() {
        assert_eq!(
            mint_fingerprint("SAAS_TENANT_42", "AI-MDL.2", 1.0, 1.0, 0.0, 1774800005000),
            "c7e61c16ee94"
        );
    }

    #[test]
    fn fingerprint_vector_7() {
        assert_eq!(
            mint_fingerprint("AWS_NITRO_ENCLAVE", "AI-EXPL.2", 85.0, 92.0, 0.0, 1774800006000),
            "2f2b989bb5c6"
        );
    }

    #[test]
    fn fingerprint_vector_8() {
        assert_eq!(
            mint_fingerprint("ENCLAVE_ALPHA", "AI-HITL.1", 1.0, 1.0, 0.0, 1774800007000),
            "9876e04b35ad"
        );
    }

    #[test]
    fn fingerprint_vector_9_large_factors() {
        assert_eq!(
            mint_fingerprint("DEMO_ENCLAVE", "AI-INF.3", 10000.0, 9500.0, 0.0, 1774800008000),
            "05010820e5a4"
        );
    }

    #[test]
    fn fingerprint_vector_10_all_zeros() {
        assert_eq!(
            mint_fingerprint("AZURE_TRUSTED_EXEC", "AI-DATA.1", 0.0, 0.0, 0.0, 1774800009000),
            "289eb7452237"
        );
    }

    #[test]
    fn fingerprint_vector_11() {
        assert_eq!(
            mint_fingerprint("ENCLAVE_ALPHA", "AI-TOOL.1", 1.0, 42.0, 1.0, 1774800010000),
            "8343d0f25ba0"
        );
    }

    #[test]
    fn fingerprint_vector_12() {
        assert_eq!(
            mint_fingerprint("ENCLAVE_ALPHA", "AI-ID.1", 1.0, 1.0, 0.0, 1774800011000),
            "34fa3cf66f00"
        );
    }

    #[test]
    fn fingerprint_vector_13() {
        assert_eq!(
            mint_fingerprint("ACME_DEFENSE", "AI-GRD.3", 2.0, 0.0, 0.0, 1774800012000),
            "62251b4cf593"
        );
    }

    // Signing vectors
    #[test]
    fn signing_with_agent_id() {
        assert_eq!(
            sign_payload("test-signing-key", "b16bf9139c16", Some("agent-007")),
            "f1d6174308e76db6907985ca7a7b28e237e46c7ce150f1bb46dfea3097575dd3"
        );
    }

    #[test]
    fn signing_without_agent_id() {
        assert_eq!(
            sign_payload("test-signing-key", "b16bf9139c16", None),
            "eb05a7746f3311a9907571ad29accad2ef43adf402c8c76f911134f52265ae7e"
        );
    }

    // Hash vectors
    #[test]
    fn hash_hello_world() {
        assert_eq!(sha256_truncated("Hello, world!", 16), "315f5bdb76d078c4");
    }

    #[test]
    fn hash_empty_string() {
        assert_eq!(sha256_truncated("", 16), "e3b0c44298fc1c14");
    }

    #[test]
    fn hash_question() {
        assert_eq!(
            sha256_truncated("What is the meaning of life?", 16),
            "318f903a83b4d30d"
        );
    }
}
