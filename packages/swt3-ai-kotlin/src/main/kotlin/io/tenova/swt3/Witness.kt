package io.tenova.swt3

import java.io.File

/**
 * SWT3 AI Witness client -- the primary API surface.
 *
 * Witnesses AI inferences by hashing inputs/outputs and minting cryptographic
 * fingerprints. Queues payloads locally and flushes to a WAL file.
 *
 * Usage:
 *   val witness = WitnessClient(WitnessConfig(tenantId = "MY_TENANT"))
 *   val result = witness.wrap("What is 2+2?", "4", "gpt-4", "openai")
 *   witness.flush()
 */
class WitnessClient(private val config: WitnessConfig) {

    private val buffer = mutableListOf<WitnessPayload>()
    private var flushedOnce = false

    /** Number of pending (unflushed) payloads. */
    val pending: Int get() = buffer.size

    /**
     * Wrap an inference call -- hash inputs/outputs, mint fingerprint, queue payload.
     */
    fun wrap(
        prompt: String,
        response: String,
        modelId: String,
        provider: String,
        latencyMs: Long? = null,
        inputTokens: Long? = null,
        outputTokens: Long? = null,
    ): WrapResult {
        val (tsMs, tsEpoch) = Fingerprint.timestampMs()
        val promptHash = Fingerprint.sha256Truncated(prompt)
        val responseHash = Fingerprint.sha256Truncated(response)

        val fp = Fingerprint.mintFingerprint(
            config.tenantId, "AI-INF.1", 1.0, 1.0, 0.0, tsMs,
        )

        val payload = WitnessPayload(
            procedureId = "AI-INF.1",
            factorA = 1.0,
            factorB = 1.0,
            factorC = 0.0,
            clearingLevel = config.clearingLevel,
            anchorFingerprint = fp,
            anchorEpoch = tsEpoch,
            fingerprintTimestampMs = tsMs,
            aiModelId = modelId,
            aiPromptHash = if (config.clearingLevel <= 1) promptHash else null,
            aiResponseHash = if (config.clearingLevel <= 1) responseHash else null,
            aiLatencyMs = latencyMs,
            aiInputTokens = inputTokens,
            aiOutputTokens = outputTokens,
            agentId = config.agentId,
            cycleId = config.cycleId,
            payloadSignature = config.signingKey?.let { key ->
                Signing.signPayload(fp, key, config.agentId)
            },
            signingAlgorithm = if (config.signingKey != null) "hmac-sha256" else null,
            signingKeyId = config.signingKeyId,
            jurisdiction = config.jurisdiction,
            legalBasis = config.legalBasis,
            purposeClass = config.purposeClass,
        )

        buffer.add(payload)
        return WrapResult(response = response, payload = payload, fingerprint = fp)
    }

    /**
     * Witness a raw inference (lower-level than wrap).
     */
    fun witnessInference(
        modelId: String,
        inputTokens: Long? = null,
        outputTokens: Long? = null,
        latencyMs: Long? = null,
    ): WitnessPayload {
        val (tsMs, tsEpoch) = Fingerprint.timestampMs()
        val fp = Fingerprint.mintFingerprint(config.tenantId, "AI-INF.1", 1.0, 1.0, 0.0, tsMs)

        val payload = WitnessPayload(
            procedureId = "AI-INF.1",
            factorA = 1.0,
            factorB = 1.0,
            factorC = 0.0,
            clearingLevel = config.clearingLevel,
            anchorFingerprint = fp,
            anchorEpoch = tsEpoch,
            fingerprintTimestampMs = tsMs,
            aiModelId = modelId,
            aiInputTokens = inputTokens,
            aiOutputTokens = outputTokens,
            aiLatencyMs = latencyMs,
            agentId = config.agentId,
        )

        buffer.add(payload)
        return payload
    }

    /**
     * Flush pending payloads to local WAL file and console.
     * Returns receipts for each flushed payload.
     */
    fun flush(): List<WitnessReceipt> {
        if (buffer.isEmpty()) return emptyList()

        val walDir = File(System.getProperty("java.io.tmpdir"), "swt3-wal")
        walDir.mkdirs()
        val safeTenant = config.tenantId.replace(Regex("[^a-zA-Z0-9_-]"), "_")
        val walFile = File(walDir, "$safeTenant.wal")

        val receipts = mutableListOf<WitnessReceipt>()

        walFile.appendText(
            buffer.joinToString("\n", postfix = "\n") { payload ->
                val receipt = WitnessReceipt(
                    procedureId = payload.procedureId,
                    verdict = "PASS",
                    swt3Anchor = "SWT3-L-LOCAL-AI-${payload.procedureId.replace(".", "").replace("-", "")}-PASS-${payload.anchorEpoch}-${payload.anchorFingerprint}",
                    clearingLevel = payload.clearingLevel,
                    witnessedAt = java.time.Instant.ofEpochMilli(payload.fingerprintTimestampMs).toString(),
                    verificationUrl = "local",
                    ok = true,
                )
                receipts.add(receipt)

                // JSON line (minimal, no external serialization dep)
                buildString {
                    append("{\"procedure_id\":\"${payload.procedureId}\"")
                    append(",\"fingerprint\":\"${payload.anchorFingerprint}\"")
                    append(",\"timestamp_ms\":${payload.fingerprintTimestampMs}")
                    append(",\"verdict\":\"PASS\"")
                    append(",\"clearing_level\":${payload.clearingLevel}")
                    payload.aiModelId?.let { append(",\"model_id\":\"$it\"") }
                    payload.agentId?.let { append(",\"agent_id\":\"$it\"") }
                    append("}")
                }
            }
        )

        // Console output
        for (r in receipts) {
            println("  ${r.procedureId}: ${r.swt3Anchor}")
        }

        if (!flushedOnce) {
            flushedOnce = true
            println("\n  ${receipts.size} anchor(s) saved to ${walFile.path}")
            if (config.apiKey == null) {
                println("  Connect to cloud: https://sovereign.tenova.io/signup")
            }
        }

        buffer.clear()
        return receipts
    }
}
