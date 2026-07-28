package io.tenova.swt3

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Cross-language fingerprint parity tests.
 * Validates against shared test-vectors.json (47 vectors).
 */
class FingerprintTest {

    data class FpVector(
        val id: Int,
        val tenantId: String,
        val procedureId: String,
        val factorA: Double,
        val factorB: Double,
        val factorC: Double,
        val timestampMs: Long,
        val expected: String,
    )

    private val vectors: List<FpVector> by lazy {
        val json = javaClass.getResourceAsStream("/test-vectors.json")!!.bufferedReader().readText()
        parseFingerprints(json)
    }

    private fun parseFingerprints(json: String): List<FpVector> {
        // Minimal JSON parsing without external deps
        val results = mutableListOf<FpVector>()
        val arrayStart = json.indexOf("\"fingerprint_vectors\"")
        if (arrayStart == -1) return results
        val bracketStart = json.indexOf('[', arrayStart)
        val bracketEnd = findMatchingBracket(json, bracketStart)
        val arrayContent = json.substring(bracketStart + 1, bracketEnd)

        var pos = 0
        while (true) {
            val objStart = arrayContent.indexOf('{', pos)
            if (objStart == -1) break
            val objEnd = arrayContent.indexOf('}', objStart)
            val obj = arrayContent.substring(objStart, objEnd + 1)
            pos = objEnd + 1

            results.add(FpVector(
                id = extractInt(obj, "id"),
                tenantId = extractString(obj, "tenant_id"),
                procedureId = extractString(obj, "procedure_id"),
                factorA = extractDouble(obj, "factor_a"),
                factorB = extractDouble(obj, "factor_b"),
                factorC = extractDouble(obj, "factor_c"),
                timestampMs = extractLong(obj, "fingerprint_timestamp_ms"),
                expected = extractString(obj, "expected_fingerprint"),
            ))
        }
        return results
    }

    @Test
    fun `all 47 fingerprint vectors match`() {
        assert(vectors.size == 47) { "Expected 47 vectors, got ${vectors.size}" }

        for (v in vectors) {
            val actual = Fingerprint.mintFingerprint(
                v.tenantId, v.procedureId, v.factorA, v.factorB, v.factorC, v.timestampMs,
            )
            assertEquals(v.expected, actual, "Vector #${v.id} (${v.procedureId}) mismatch")
        }
    }

    @Test
    fun `format factor integer valued`() {
        assertEquals("1", Fingerprint.formatFactor(1.0))
        assertEquals("0", Fingerprint.formatFactor(0.0))
        assertEquals("5000", Fingerprint.formatFactor(5000.0))
    }

    @Test
    fun `format factor decimal valued`() {
        assertEquals("1.5", Fingerprint.formatFactor(1.5))
        assertEquals("0.85", Fingerprint.formatFactor(0.85))
    }
}

// ── Minimal JSON helpers (no external deps) ──

internal fun findMatchingBracket(s: String, start: Int): Int {
    var depth = 0
    for (i in start until s.length) {
        when (s[i]) {
            '[' -> depth++
            ']' -> { depth--; if (depth == 0) return i }
        }
    }
    return s.length
}

internal fun extractString(obj: String, key: String): String {
    val keyIdx = obj.indexOf("\"$key\"")
    if (keyIdx == -1) return ""
    val colonIdx = obj.indexOf(':', keyIdx + key.length + 2)
    val quoteStart = obj.indexOf('"', colonIdx + 1)
    val quoteEnd = obj.indexOf('"', quoteStart + 1)
    return obj.substring(quoteStart + 1, quoteEnd)
}

internal fun extractInt(obj: String, key: String): Int {
    return extractNumber(obj, key).toInt()
}

internal fun extractLong(obj: String, key: String): Long {
    return extractNumber(obj, key).toLong()
}

internal fun extractDouble(obj: String, key: String): Double {
    return extractNumber(obj, key).toDouble()
}

internal fun extractNumber(obj: String, key: String): String {
    val keyIdx = obj.indexOf("\"$key\"")
    if (keyIdx == -1) return "0"
    val colonIdx = obj.indexOf(':', keyIdx + key.length + 2)
    val valueStart = (colonIdx + 1 until obj.length).first { !obj[it].isWhitespace() }
    val valueEnd = (valueStart until obj.length).first {
        obj[it] == ',' || obj[it] == '}' || obj[it] == ']'
    }
    return obj.substring(valueStart, valueEnd).trim()
}
