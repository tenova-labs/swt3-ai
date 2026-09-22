package swt3

import "fmt"

const (
	// LifecycleChainIDLength is the number of hex characters in a lifecycle chain ID (after "LC-" prefix).
	LifecycleChainIDLength = 16
)

// Lifecycle stage codes (canonical set).
const (
	StageInitiated  = 0
	StageCheckpoint = 1
	StageEscalated  = 2
	StageResolved   = 3
	StageAbandoned  = 4
	StageSuperseded = 5
)

// MintLifecycleChainID computes a lifecycle chain identifier.
//
// Formula: "LC-" + SHA256("LIFECYCLE:{tenant}:{proc}:{fp}:{ts}").hex()[:16]
func MintLifecycleChainID(tenantID, procedureID, fingerprint string, timestampMs int64) string {
	input := fmt.Sprintf("LIFECYCLE:%s:%s:%s:%d",
		tenantID, procedureID, fingerprint, timestampMs,
	)
	return "LC-" + Sha256Hex(input, LifecycleChainIDLength)
}
