package swt3

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

const (
	// FingerprintLength is the number of hex characters in a fingerprint.
	FingerprintLength = 12

	// maxSafeFactor is the maximum absolute value for a factor (2^53, JS safe integer limit).
	maxSafeFactor = 1 << 53
)

// MintFingerprint computes a 12-character SWT3 witness fingerprint.
//
// Formula (LOCKED): SHA256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}").hex()[:12]
func MintFingerprint(tenantID, procedureID string, factorA, factorB, factorC float64, timestampMs int64) string {
	if math.Abs(factorA) > maxSafeFactor || math.Abs(factorB) > maxSafeFactor || math.Abs(factorC) > maxSafeFactor {
		panic("swt3: factor value exceeds 2^53 safe integer range")
	}
	input := fmt.Sprintf("WITNESS:%s:%s:%s:%s:%s:%d",
		tenantID, procedureID,
		formatFactor(factorA), formatFactor(factorB), formatFactor(factorC),
		timestampMs,
	)
	return Sha256Hex(input, FingerprintLength)
}

// Sha256Truncated returns the first `length` hex characters of SHA-256(data).
// Default length for model/content hashing is 16.
func Sha256Truncated(data string, length int) string {
	return Sha256Hex(data, length)
}

// Sha256Hex returns the first `length` hex characters of SHA-256(data).
func Sha256Hex(data string, length int) string {
	h := sha256.Sum256([]byte(data))
	full := hex.EncodeToString(h[:])
	if length > 64 {
		length = 64
	}
	return full[:length]
}

// TimestampMs returns the current time as (milliseconds, epoch seconds).
func TimestampMs() (ms int64, epoch int64) {
	now := time.Now()
	ms = now.UnixMilli()
	epoch = now.Unix()
	return
}

// formatFactor converts a float64 to its canonical string representation.
// Integer-valued floats are formatted without decimals: 1.0 -> "1".
func formatFactor(v float64) string {
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return fmt.Sprintf("%g", v)
	}
	if v == math.Floor(v) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}
