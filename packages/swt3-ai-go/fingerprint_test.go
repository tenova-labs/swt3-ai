package swt3

import "testing"

// Test vectors from packages/swt3-ai/test-vectors.json (cross-language parity).

var fingerprintVectors = []struct {
	id          int
	tenantID    string
	procedureID string
	factorA     float64
	factorB     float64
	factorC     float64
	timestampMs int64
	expected    string
}{
	{1, "ENCLAVE_PROD", "AI-INF.1", 1, 1, 0, 1774800000000, "2e16e2fe92dd"},
	{2, "AWS_NITRO_ENCLAVE", "AI-INF.2", 5000, 8000, 1, 1774800001000, "4ed784765e6c"},
	{3, "ENCLAVE_PROD", "AI-GRD.1", 2, 3, 0, 1774800002000, "a0aa7669ae6f"},
	{4, "AZURE_TRUSTED_EXEC", "AI-MDL.1", 1, 0, 1, 1774800003000, "c36d477b3c2d"},
	{5, "ACME_DEFENSE", "AI-FAIR.1", 15, 15, 0, 1774800004000, "53180f5ae221"},
	{6, "SAAS_TENANT_42", "AI-MDL.2", 1, 1, 0, 1774800005000, "c7e61c16ee94"},
	{7, "AWS_NITRO_ENCLAVE", "AI-EXPL.2", 85, 92, 0, 1774800006000, "2f2b989bb5c6"},
	{8, "ENCLAVE_PROD", "AI-HITL.1", 1, 1, 0, 1774800007000, "afbab8c9e098"},
	{9, "DEMO_ENCLAVE", "AI-INF.3", 10000, 9500, 0, 1774800008000, "05010820e5a4"},
	{10, "AZURE_TRUSTED_EXEC", "AI-DATA.1", 0, 0, 0, 1774800009000, "289eb7452237"},
	{11, "ENCLAVE_PROD", "AI-TOOL.1", 1, 42, 1, 1774800010000, "019eaf85fcba"},
	{12, "ENCLAVE_PROD", "AI-ID.1", 1, 1, 0, 1774800011000, "7966c8f7fbb6"},
	{13, "ACME_DEFENSE", "AI-GRD.3", 2, 0, 0, 1774800012000, "62251b4cf593"},
	{14, "ENCLAVE_PROD", "AI-RAG.1", 5, 1, 0, 1774800010000, "66209137510b"},
	{15, "ENCLAVE_PROD", "AI-RAG.2", 750, 820, 1, 1774800011000, "f714436c06cf"},
	{16, "ENCLAVE_PROD", "AI-MDL.5", 1, 1, 0, 1774800020000, "eb95216c3841"},
	{17, "ENCLAVE_PROD", "AI-MDL.6", 3, 1, 0, 1774800021000, "8cdb254d3b0f"},
	{18, "ENCLAVE_PROD", "AI-MDL.7", 1, 1, 5, 1774800022000, "e41a794af2b7"},
	{19, "ENCLAVE_PROD", "AI-SKILL.1", 4, 1, 0, 1774800023000, "99e67c3870ab"},
	{20, "ENCLAVE_PROD", "AI-SKILL.2", 2, 1, 0, 1774800024000, "3b7054cb045a"},
	{21, "ENCLAVE_PROD", "AI-SKILL.3", 1, 1, 0, 1774800025000, "737d5adb8f69"},
	{22, "ENCLAVE_PROD", "AI-CHAIN.1", 3, 1, 1, 1774800030000, "c7210714030a"},
	{23, "ACME_DEFENSE", "AI-VIO.1", 3, 1, 4, 1774800031000, "2cf52653ff8a"},
	{24, "ENCLAVE_PROD", "AI-CHR.1", 1, 1, 0, 1774800032000, "0fe7713c8954"},
	{25, "ENCLAVE_PROD", "AI-MDL.8", 1, 1, 0, 1774800033000, "c21161b481d1"},
	{26, "ACME_DEFENSE", "AI-HITL.3", 2, 2, 2, 1774800034000, "d7e3a52bd012"},
	{27, "ENCLAVE_PROD", "AI-SAFE.1", 1, 1, 1, 1774800035000, "44cc01ade479"},
	{28, "ENCLAVE_PROD", "AI-DATA.3", 50000, 128, 850, 1774800036000, "f9ce447c6e19"},
	{29, "ENCLAVE_PROD", "AI-DATA.4", 10000, 1, 1, 1774800037000, "39407008633d"},
	{30, "ENCLAVE_PROD", "AI-ENV.1", 42, 85, 1, 1774800037000, "64c031701878"},
	{31, "ENCLAVE_PROD", "AI-ENV.2", 1200, 1200, 0, 1774800037000, "0b31660c296f"},
	{32, "ENCLAVE_PROD", "AI-MARK.1", 3, 1, 0, 1774800031000, "8ec75a21838f"},
	{33, "ENCLAVE_PROD", "AI-BASE.1", 12, 1, 1, 1774800032000, "e66df4bbdedb"},
	{34, "ENCLAVE_PROD", "AI-METAGOV.1", 5, 123456, 1, 1774800000000, "1c94756db9c1"},
	{35, "ENCLAVE_PROD", "AI-METAGOV.2", 1, 789012, 0, 1774800000000, "aadb6f87dcee"},
	{36, "ENCLAVE_PROD", "AI-METAGOV.3", 2, 345678, 1, 1774800000000, "32a6bd5ad5c9"},
	{37, "ENCLAVE_PROD", "AI-METAGOV.4", 10, 0, 3, 1774800000000, "0b503341c3c4"},
	{38, "ENCLAVE_PROD", "AI-METAGOV.5", 0, 1, 567890, 1774800000000, "dd4fe9576cd2"},
	{39, "ENCLAVE_PROD", "AI-METAGOV.6", 1, 48, 0, 1774800000000, "270738c276fc"},
	{40, "ENCLAVE_PROD", "AI-METAGOV.7", 1, 234567, 876543, 1774800000000, "66601df8b6d7"},
	{41, "ENCLAVE_PROD", "AI-METAGOV.8", 4, 654321, 1, 1774800000000, "1500a3dcab94"},
	{42, "DESIGN_ENCLAVE", "AI-ENG.1", 12, 500, 0, 1774800042000, "3a9ad53541de"},
	{43, "DESIGN_ENCLAVE", "AI-ENG.2", 1000, 1000, 0, 1774800043000, "bd1bb0a1554b"},
	{44, "DESIGN_ENCLAVE", "AI-ENG.3", 3, 3, 1, 1774800044000, "0f7d9d58352d"},
	{45, "DESIGN_ENCLAVE", "AI-ENG.4", 15, 15, 0, 1774800045000, "34bfd6594dff"},
	{46, "DESIGN_ENCLAVE", "AI-ENG.5", 10, 7, 1, 1774800046000, "26ae638d2064"},
	{47, "DESIGN_ENCLAVE", "AI-ENG.6", 1, 5, 2, 1774800047000, "4ff83090bfc4"},
	{48, "ENCLAVE_PROD", "AI-REACH.1", 5, 5, 1, 1774800020000, "84e3c4b4c9df"},
	{49, "ACME_DEFENSE", "AI-REACH.1", 8, 3, 0, 1774800021000, "e87e7975d10e"},
	{50, "ENCLAVE_PROD", "AI-DECOM.1", 4, 4, 0, 1774800022000, "7c3a1b7bdcdd"},
	{51, "AWS_NITRO_ENCLAVE", "AI-DECOM.1", 6, 2, 3, 1774800023000, "6820dea7fc0c"},
	{52, "ENCLAVE_PROD", "AI-RECOMM.1", 10, 10, 0, 1774800024000, "2022f26aef5a"},
	{53, "DEMO_ENCLAVE", "AI-RECOMM.1", 8, 5, 1, 1774800025000, "02eab528668a"},
	{54, "ENCLAVE_PROD", "AI-FREEZE.1", 12, 12, 2, 1774800026000, "fd2541054cb7"},
	{55, "AZURE_TRUSTED_EXEC", "AI-FREEZE.1", 20, 18, 0, 1774800027000, "934ab9388917"},
}

func TestMintFingerprint(t *testing.T) {
	for _, v := range fingerprintVectors {
		got := MintFingerprint(v.tenantID, v.procedureID, v.factorA, v.factorB, v.factorC, v.timestampMs)
		if got != v.expected {
			t.Errorf("vector %d: MintFingerprint(%q, %q, %g, %g, %g, %d) = %q, want %q",
				v.id, v.tenantID, v.procedureID, v.factorA, v.factorB, v.factorC, v.timestampMs, got, v.expected)
		}
	}
}

func TestFormatFactor(t *testing.T) {
	tests := []struct {
		input    float64
		expected string
	}{
		{1.0, "1"},
		{0.0, "0"},
		{42.0, "42"},
		{10000.0, "10000"},
		{1.5, "1.5"},
		{-1.0, "-1"},
	}
	for _, tt := range tests {
		got := formatFactor(tt.input)
		if got != tt.expected {
			t.Errorf("formatFactor(%g) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestTimestampMs(t *testing.T) {
	ms, epoch := TimestampMs()
	if ms <= 0 {
		t.Error("TimestampMs() ms should be positive")
	}
	if epoch <= 0 {
		t.Error("TimestampMs() epoch should be positive")
	}
	if ms/1000 != epoch {
		t.Errorf("TimestampMs() ms/1000=%d != epoch=%d", ms/1000, epoch)
	}
}
