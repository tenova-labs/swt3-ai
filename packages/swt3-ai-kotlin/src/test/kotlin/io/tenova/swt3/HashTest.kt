package io.tenova.swt3

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Cross-language SHA-256 truncation parity tests.
 */
class HashTest {

    @Test
    fun `hash Hello world`() {
        assertEquals("315f5bdb76d078c4", Fingerprint.sha256Truncated("Hello, world!"))
    }

    @Test
    fun `hash empty string`() {
        assertEquals("e3b0c44298fc1c14", Fingerprint.sha256Truncated(""))
    }

    @Test
    fun `hash meaning of life`() {
        assertEquals("318f903a83b4d30d", Fingerprint.sha256Truncated("What is the meaning of life?"))
    }

    @Test
    fun `hash model identifier`() {
        assertEquals("0f6b04241d237297", Fingerprint.sha256Truncated("gpt-4o-2024-11-20:fp_abc123"))
    }

    @Test
    fun `hash system prompt`() {
        assertEquals(
            "479eaa1ee804f844",
            Fingerprint.sha256Truncated("You are a helpful fraud detection assistant. Flag any transaction over \$10,000."),
        )
    }
}
