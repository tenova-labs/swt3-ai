#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

import Foundation

extension SWT3 {

    /// Mint an SWT3 fingerprint from the canonical formula.
    ///
    /// The fingerprint is the first 12 hex characters of:
    /// `SHA-256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}")`
    ///
    /// This formula is locked and produces identical output across
    /// all SWT3 SDK implementations (Python, TypeScript, Rust, C#, Ruby, Swift).
    ///
    /// - Parameters:
    ///   - tenant: Tenant identifier (e.g. "MY_TENANT")
    ///   - procedure: UCT procedure ID (e.g. "AI-INF.1")
    ///   - factorA: Numeric factor A
    ///   - factorB: Numeric factor B
    ///   - factorC: Numeric factor C
    ///   - timestampMs: Millisecond-precision timestamp
    /// - Returns: 12-character hex fingerprint string
    public static func mintFingerprint(
        tenant: String,
        procedure: String,
        factorA: Double,
        factorB: Double,
        factorC: Double,
        timestampMs: Int64
    ) -> String {
        let input = "WITNESS:\(tenant):\(procedure):\(numStr(factorA)):\(numStr(factorB)):\(numStr(factorC)):\(timestampMs)"
        return sha256Hex(input, length: 12)
    }

    /// Compute a truncated SHA-256 hash of the input string.
    ///
    /// Default length is 16 hex characters (used for prompt/response hashing).
    /// Use 12 for fingerprints, 64 for full digests.
    ///
    /// - Parameters:
    ///   - data: The string to hash
    ///   - length: Number of hex characters to return (default: 16)
    /// - Returns: Truncated hex digest
    public static func sha256Truncated(_ data: String, length: Int = 16) -> String {
        sha256Hex(data, length: length)
    }

    /// Compute a SHA-256 hash and return the first N hex characters.
    ///
    /// - Parameters:
    ///   - data: The string to hash
    ///   - length: Number of hex characters to return (default: 64)
    /// - Returns: Hex digest truncated to the specified length
    public static func sha256Hex(_ data: String, length: Int = 64) -> String {
        let digest = SHA256.hash(data: Data(data.utf8))
        let fullHex = digest.map { String(format: "%02x", $0) }.joined()
        let end = min(length, 64)
        return String(fullHex.prefix(end))
    }

    /// Get the current timestamp in milliseconds and epoch seconds.
    ///
    /// - Returns: A tuple of (milliseconds, epoch seconds)
    public static func timestampMs() -> (ms: Int64, epoch: Int64) {
        let ms = Int64(Date().timeIntervalSince1970 * 1000)
        let epoch = ms / 1000
        return (ms, epoch)
    }

    /// Format a numeric factor as a string matching the canonical formula.
    ///
    /// Integer-valued doubles are formatted without decimals: 1.0 -> "1"
    /// True floats keep their decimals: 1.5 -> "1.5"
    static func numStr(_ v: Double) -> String {
        if v.isFinite && v == v.rounded(.down) {
            return String(Int64(v))
        }
        return String(v)
    }
}
