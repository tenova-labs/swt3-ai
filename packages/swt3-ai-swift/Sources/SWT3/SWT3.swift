// SWT3 AI Witness SDK for Swift
//
// Cryptographic attestation for AI inference. Mint fingerprints,
// verify anchors, and sign payloads with cross-language parity.
//
// Copyright 2026 Tenable Nova LLC. Apache-2.0 licensed.
// Patent pending. See https://tenova.io

/// SWT3 AI Witness SDK namespace.
///
/// All core primitives are static methods on this enum. Apple platform
/// features (Core ML witnessing, Secure Enclave signing, spatial
/// provenance) activate automatically via conditional compilation.
///
/// ```swift
/// let fp = SWT3.mintFingerprint(
///     tenant: "MY_TENANT",
///     procedure: "AI-INF.1",
///     factorA: 1, factorB: 1, factorC: 0,
///     timestampMs: 1774800000000
/// )
/// let sig = SWT3.signPayload(key: "swt3_sk_my_key", fingerprint: fp)
/// ```
public enum SWT3 {
    /// SDK version. Matches Python, TypeScript, Rust, C#, Ruby releases.
    public static let version = "0.5.8"
}
