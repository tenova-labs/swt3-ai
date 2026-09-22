// Package swt3 provides the SWT3 AI Witness SDK for Go.
//
// SWT3 (Sovereign Witness Token v3) is a cryptographic attestation protocol
// for AI systems. This core package implements fingerprint minting, HMAC-SHA256
// signing, lifecycle chain IDs, and shared types -- with zero external dependencies.
//
// The fingerprint formula is locked and cross-language:
//
//	SHA256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}").hex()[:12]
//
// All output is byte-identical to the Python, TypeScript, Rust, C#, Ruby,
// Swift, and Kotlin SDKs.
//
// Quick start:
//
//	fp := swt3.MintFingerprint("MY_TENANT", "AI-INF.1", 1, 1, 0, 1774800000000)
//	sig := swt3.SignPayload("my-secret-key", fp, "agent-1")
package swt3
