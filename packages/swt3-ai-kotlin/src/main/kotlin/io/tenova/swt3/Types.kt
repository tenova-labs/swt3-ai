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

/** GDPR lawful basis codes (AI-CONSENT.1) */
object ConsentBasis {
    const val CONSENT = 0
    const val CONTRACT = 1
    const val LEGAL_OBLIGATION = 2
    const val VITAL_INTEREST = 3
    const val PUBLIC_TASK = 4
    const val LEGITIMATE_INTEREST = 5
}

/** Incident severity codes (AI-INCIDENT.1) */
object IncidentSeverity {
    const val LOW = 1
    const val MEDIUM = 2
    const val HIGH = 3
    const val CRITICAL = 4
}

/** Incident type codes (AI-INCIDENT.1) */
object IncidentType {
    const val SAFETY = 0
    const val RIGHTS = 1
    const val SECURITY = 2
    const val PERFORMANCE = 3
    const val BIAS = 4
    const val OTHER = 5
}

/** Output filter action codes (AI-GRD.2) */
object FilterAction {
    const val ALLOWED = 0
    const val FLAGGED = 1
    const val REDACTED = 2
    const val BLOCKED = 3
}

/** Consent attestation data for AI-CONSENT.1 witnessing. */
data class ConsentAttestation(
    val subjectsCovered: Int = 1,
    val legalBasisCode: Int = ConsentBasis.CONSENT,
    val withdrawalAvailable: Boolean = true,
    val jurisdiction: String? = null,
    val purpose: String? = null,
    val consentMechanism: String? = null,
)

/** Output content safety classification result for AI-GRD.2 witnessing. */
data class OutputFilterResult(
    val passed: Boolean,
    val filterType: String = "content-safety",
    val confidence: Double? = null,
    val actionTaken: String = "allowed",
    val outputHash: String? = null,
)

/** Incident report for AI-INCIDENT.1 witnessing. */
data class IncidentReport(
    val severityCode: Int = IncidentSeverity.MEDIUM,
    val incidentTypeCode: Int = IncidentType.OTHER,
    val authorityNotified: Boolean = false,
    val descriptionHash: String? = null,
    val detectionMethod: String? = null,
    val reportingDeadlineHours: Int? = null,
    val incidentId: String? = null,
)

/** Training data governance attestation for AI-DATA.1 witnessing.
 *  Attests diligence without disclosing training data contents. */
data class DataProvenanceAttestation(
    val governanceReviewed: Boolean = true,
    val documentationHash: String? = null,
    val licenseVerified: Boolean = false,
    val demographicFeaturesExcluded: Boolean = false,
    val dataSourcesCount: Int? = null,
)

/** Safety classification codes for AI-MOB.6 trajectory decision attestation. */
object SafetyClassification {
    const val RESERVED = 0
    const val NOMINAL = 1
    const val CAUTIONARY = 2
    const val DEGRADED = 3
    const val EMERGENCY = 4
    const val ABORT = 5
}

/** Trajectory decision attestation for AI-MOB.6 witnessing. */
data class TrajectoryAttestation(
    val safetyValidated: Boolean,
    val waypointCount: Int? = null,
    val trajectoryHash: String? = null,
    val cocTraceHash: String? = null,
    val cocNodeCount: Int? = null,
    val actionClass: String? = null,
    val safetyClassification: Int = SafetyClassification.NOMINAL,
    val sensorSources: List<String>? = null,
)

/** VLA inference result for AI-MOB.7 witnessing. */
data class VlaInferenceResult(
    val modelId: String,
    val latencyMs: Int,
    val succeeded: Boolean = true,
    val inputFrameHashes: List<String>? = null,
)
