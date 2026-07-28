package io.tenova.swt3

import java.security.MessageDigest

/**
 * SWT3 fingerprint formula -- LOCKED, cross-language parity with 7 other SDKs.
 *
 * Formula: SHA256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}").hex()[:12]
 */
object Fingerprint {

    /**
     * Mint a 12-character hex fingerprint from witness factors.
     *
     * The fingerprint is deterministic: same inputs always produce the same output
     * across Python, TypeScript, Rust, C#, Ruby, Swift, and Kotlin.
     */
    fun mintFingerprint(
        tenant: String,
        procedure: String,
        factorA: Double,
        factorB: Double,
        factorC: Double,
        timestampMs: Long,
    ): String {
        val message = "WITNESS:$tenant:$procedure:${formatFactor(factorA)}:${formatFactor(factorB)}:${formatFactor(factorC)}:$timestampMs"
        return sha256Hex(message).substring(0, 12)
    }

    /**
     * SHA-256 hash truncated to [length] hex characters (default 16).
     */
    fun sha256Truncated(data: String, length: Int = 16): String {
        return sha256Hex(data).substring(0, length)
    }

    /**
     * Full SHA-256 hex digest (64 characters).
     */
    fun sha256Hex(data: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(data.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Current timestamp as (milliseconds, seconds) pair.
     */
    fun timestampMs(): Pair<Long, Long> {
        val ms = System.currentTimeMillis()
        return Pair(ms, ms / 1000)
    }

    /**
     * Format a numeric factor for the fingerprint formula.
     * Integer-valued doubles lose their decimal: 1.0 -> "1", 0.0 -> "0"
     * True floats keep decimals: 1.5 -> "1.5"
     */
    internal fun formatFactor(value: Double): String {
        return if (value == value.toLong().toDouble()) {
            value.toLong().toString()
        } else {
            value.toString()
        }
    }
}
