package io.tenova.swt3

/**
 * SWT3 AI Witness type definitions.
 *
 * Cross-language parity with Python, TypeScript, Rust, C#, Ruby, Swift SDKs.
 */

data class WitnessPayload(
    val procedureId: String,
    val factorA: Double,
    val factorB: Double,
    val factorC: Double,
    val clearingLevel: Int,
    val anchorFingerprint: String,
    val anchorEpoch: Long,
    val fingerprintTimestampMs: Long,
    val aiModelId: String? = null,
    val aiPromptHash: String? = null,
    val aiResponseHash: String? = null,
    val aiLatencyMs: Long? = null,
    val aiInputTokens: Long? = null,
    val aiOutputTokens: Long? = null,
    val agentId: String? = null,
    val cycleId: String? = null,
    val payloadSignature: String? = null,
    val signingAlgorithm: String? = null,
    val signingKeyId: String? = null,
    val signingKeyVersion: Int? = null,
    val policyVersionHash: String? = null,
    val jurisdiction: String? = null,
    val legalBasis: String? = null,
    val purposeClass: String? = null,
    val authorizationId: String? = null,
    val revocationTarget: String? = null,
    val revocationReason: String? = null,
)

data class WitnessReceipt(
    val procedureId: String,
    val verdict: String,
    val swt3Anchor: String,
    val clearingLevel: Int,
    val witnessedAt: String,
    val verificationUrl: String,
    val ok: Boolean,
    val error: String? = null,
)

data class WitnessConfig(
    val tenantId: String,
    val clearingLevel: Int = 1,
    val agentId: String? = null,
    val signingKey: String? = null,
    val signingAlgorithm: String? = null,
    val signingKeyId: String? = null,
    val signingKeyVersion: Int? = null,
    val endpoint: String = "https://sovereign.tenova.io",
    val apiKey: String? = null,
    val bufferSize: Int = 10,
    val flushIntervalSeconds: Double = 5.0,
    val timeoutMs: Long = 10000,
    val maxRetries: Int = 3,
    val cycleId: String? = null,
    val policyVersion: String? = null,
    val jurisdiction: String? = null,
    val legalBasis: String? = null,
    val purposeClass: String? = null,
)

data class WrapResult(
    val response: String,
    val payload: WitnessPayload,
    val fingerprint: String,
)

enum class SigningAlgorithm(val value: String) {
    HMAC_SHA256("hmac-sha256"),
    ML_DSA_65("ml-dsa-65"),
}

enum class RevocationReason(val code: Int) {
    UNSPECIFIED(0),
    MODEL_RECALL(1),
    POLICY_VIOLATION(2),
    DATA_CONTAMINATION(3),
    CONSENT_WITHDRAWAL(4),
    REGULATORY_ORDER(5),
    ERROR_CORRECTION(6),
}

/** Trust Mesh levels (AI-TRUST.1 / TRUST.2) */
object TrustLevel {
    const val DENIED = 0
    const val BASIC = 1
    const val VERIFIED = 2
    const val ATTESTED = 3
    const val SOVEREIGN = 4
}

/** Clearing levels for evidence redaction */
object ClearingLevel {
    const val ANALYTICS = 0
    const val STANDARD = 1
    const val SENSITIVE = 2
    const val CLASSIFIED = 3
}

/** Lifecycle stages (AI-LCM.1) */
val LIFECYCLE_STAGES = listOf("design", "development", "testing", "deployment", "monitoring", "decommission")
