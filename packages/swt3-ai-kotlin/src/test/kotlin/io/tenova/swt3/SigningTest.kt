package io.tenova.swt3

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Cross-language HMAC-SHA256 signing parity tests.
 */
class SigningTest {

    @Test
    fun `signing with agent_id`() {
        val sig = Signing.signPayload(
            fingerprint = "019eaf85fcba",
            signingKey = "test-signing-key",
            agentId = "agent-007",
        )
        assertEquals(
            "00ff82da1659e2e6a7fa875c781ed4635976c8136b8dc2c24672adb8673cb112",
            sig,
            "Signing vector #1 (with agent_id) mismatch",
        )
    }

    @Test
    fun `signing without agent_id`() {
        val sig = Signing.signPayload(
            fingerprint = "019eaf85fcba",
            signingKey = "test-signing-key",
            agentId = null,
        )
        assertEquals(
            "d844102f40fb5dad449a2f57922f5b23f73ffb3a026b5bd5fd537ebe5c6c44d0",
            sig,
            "Signing vector #2 (without agent_id) mismatch",
        )
    }
}
