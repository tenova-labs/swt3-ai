package swt3

import "testing"

func TestMintLifecycleChainID(t *testing.T) {
	tests := []struct {
		id          int
		tenantID    string
		procedureID string
		fingerprint string
		timestampMs int64
		expected    string
	}{
		{1, "ENCLAVE_PROD", "AI-EMRG.1", "2e16e2fe92dd", 1774800000000, "LC-7a38936db8ecec94"},
		{2, "ENCLAVE_PROD", "AI-DRIFT.2", "4ed784765e6c", 1774800001000, "LC-60c720a257e2d3b9"},
		{3, "AWS_NITRO_ENCLAVE", "AI-ASSESS.1", "66209137510b", 1774800010000, "LC-9caadba335ca64cd"},
	}
	for _, tt := range tests {
		got := MintLifecycleChainID(tt.tenantID, tt.procedureID, tt.fingerprint, tt.timestampMs)
		if got != tt.expected {
			t.Errorf("vector %d: MintLifecycleChainID(%q, %q, %q, %d) = %q, want %q",
				tt.id, tt.tenantID, tt.procedureID, tt.fingerprint, tt.timestampMs, got, tt.expected)
		}
	}
}
