package swt3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SignPayload computes an HMAC-SHA256 signature for a witness anchor.
//
// If agentID is non-empty, the message is "{fingerprint}:{agentID}".
// Otherwise, the message is just the fingerprint.
func SignPayload(signingKey, anchorFingerprint string, agentID string) string {
	message := anchorFingerprint
	if agentID != "" {
		message = anchorFingerprint + ":" + agentID
	}
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
