package io.tenova.swt3

/** SWT3 AI Witness SDK for Kotlin/Android. */
object Swt3 {
    const val VERSION = "0.1.1"
    const val SDK_NAME = "swt3-ai-kotlin"
    const val DESCRIPTION = "SWT3 AI Witness SDK: cryptographic attestation for AI inference. " +
        "113 procedures, 56 namespaces, 36 frameworks. " +
        "EU AI Act, NIST AI RMF, CMMC, SR 11-7."
}

/** Demo: witness an inference, flush, verify. Runnable via `./gradlew run`. */
fun main() {
    println("\n  SWT3 AI Witness SDK v${Swt3.VERSION} (Kotlin)\n")

    val witness = WitnessClient(
        WitnessConfig(
            tenantId = "KOTLIN_DEMO",
            clearingLevel = 1,
            agentId = "demo-agent",
        )
    )

    // Witness an inference
    val result = witness.wrap(
        prompt = "What are the three laws of robotics?",
        response = "1. A robot may not injure a human being...",
        modelId = "demo-model",
        provider = "local",
    )

    println("  Fingerprint: ${result.fingerprint}")
    println("  Pending: ${witness.pending}\n")

    // Flush to local WAL
    println("  Flushing anchors:")
    val receipts = witness.flush()

    // Verify fingerprint
    val recomputed = Fingerprint.mintFingerprint(
        "KOTLIN_DEMO", "AI-INF.1", 1.0, 1.0, 0.0, result.payload.fingerprintTimestampMs,
    )
    val verified = recomputed == result.fingerprint
    println("\n  Verification: ${if (verified) "CERTIFIED TRUTH" else "MISMATCH"}")
    println("  Docs: https://sovereign.tenova.io/docs/\n")
}
