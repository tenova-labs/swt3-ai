package io.tenova.swt3

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * SWT3 HMAC-SHA256 payload signing.
 *
 * Signs a fingerprint (optionally with agent_id) to prove origin.
 */
object Signing {

    /**
     * Sign a fingerprint with HMAC-SHA256.
     *
     * @param fingerprint The 12-char hex fingerprint to sign.
     * @param signingKey The HMAC key (UTF-8 encoded).
     * @param agentId Optional agent identifier. If provided, message is "{fp}:{agentId}".
     * @return 64-character lowercase hex signature.
     */
    fun signPayload(fingerprint: String, signingKey: String, agentId: String? = null): String {
        val message = if (agentId != null) "$fingerprint:$agentId" else fingerprint
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(signingKey.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        val bytes = mac.doFinal(message.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
