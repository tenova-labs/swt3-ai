package swt3

import "testing"

func newTestWitness(clearingLevel ClearingLevel) *Witness {
	return NewWitness(WitnessConfig{
		Endpoint:      "https://test.example.com",
		APIKey:        "axm_test_key",
		TenantID:      "test_tenant",
		ClearingLevel: clearingLevel,
		AgentID:       "test-agent",
	})
}

// ── NHI Tests ───────────────────────────────────────────────────────

func TestWitnessNhiScope(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessNhiScope("cred-abc-123", "read,write", 3600)
	if p.ProcedureID != "NHI-SCOPE.1" {
		t.Errorf("ProcedureID = %q, want NHI-SCOPE.1", p.ProcedureID)
	}
	if p.FactorC != 3600 {
		t.Errorf("FactorC = %f, want 3600", p.FactorC)
	}
	if len(p.AnchorFingerprint) != 12 {
		t.Errorf("fingerprint length = %d, want 12", len(p.AnchorFingerprint))
	}
	if p.AIContext == nil {
		t.Error("AIContext should not be nil at clearing level 1")
	}
	if p.AgentID != "test-agent" {
		t.Errorf("AgentID = %q, want test-agent", p.AgentID)
	}
	if len(w.Buffer) != 1 {
		t.Errorf("Buffer length = %d, want 1", len(w.Buffer))
	}
}

func TestWitnessNhiScopeStrippedAtLevel2(t *testing.T) {
	w := newTestWitness(ClearingSensitive)
	p := w.WitnessNhiScope("cred", "scope", 0)
	if p.AIContext != nil {
		t.Error("AIContext should be nil at clearing level 2")
	}
	if p.AIModelID != "" {
		t.Error("AIModelID should be empty at clearing level 2")
	}
}

func TestWitnessNhiScopeDeterministic(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p1 := w.WitnessNhiScope("same-cred", "same-scope", 0)
	p2 := w.WitnessNhiScope("same-cred", "same-scope", 0)
	if p1.FactorA != p2.FactorA || p1.FactorB != p2.FactorB {
		t.Error("same inputs should produce same factor_a and factor_b")
	}
}

func TestWitnessNhiLifecycle(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessNhiLifecycle(NHIEventIssued, "cred-123", "EntraID")
	if p.ProcedureID != "NHI-CYCLE.1" {
		t.Errorf("ProcedureID = %q, want NHI-CYCLE.1", p.ProcedureID)
	}
	if p.FactorA != 1 {
		t.Errorf("FactorA = %f, want 1 (issued)", p.FactorA)
	}
}

func TestWitnessNhiLifecycleAllEvents(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	events := []struct {
		code int
		want float64
	}{
		{NHIEventIssued, 1}, {NHIEventActivated, 2}, {NHIEventSuspended, 3},
		{NHIEventExpired, 4}, {NHIEventRevoked, 5},
	}
	for _, e := range events {
		p := w.WitnessNhiLifecycle(e.code, "cred", "issuer")
		if p.FactorA != e.want {
			t.Errorf("event %d: FactorA = %f, want %f", e.code, p.FactorA, e.want)
		}
	}
}

func TestWitnessNhiPrivilegeChange(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessNhiPrivilegeChange("cred", "read", "read,write,admin")
	if p.ProcedureID != "NHI-PRIV.1" {
		t.Errorf("ProcedureID = %q, want NHI-PRIV.1", p.ProcedureID)
	}
	if p.FactorB == 0 {
		t.Error("FactorB should be non-zero when previous scope is provided")
	}
}

func TestWitnessNhiPrivilegeChangeEmptyPrevious(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessNhiPrivilegeChange("cred", "", "read,write")
	if p.FactorB != 0 {
		t.Errorf("FactorB = %f, want 0 for empty previous scope", p.FactorB)
	}
}

func TestWitnessNhiRotation(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessNhiRotation("old-cred", "new-cred", NHIRotationScheduled)
	if p.ProcedureID != "NHI-ROTATE.1" {
		t.Errorf("ProcedureID = %q, want NHI-ROTATE.1", p.ProcedureID)
	}
	if p.FactorC != 1 {
		t.Errorf("FactorC = %f, want 1 (scheduled)", p.FactorC)
	}
	if p.FactorA == p.FactorB {
		t.Error("old and new credential hashes should produce distinct factors")
	}
}

func TestWitnessNhiDelegation(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessNhiDelegation("agent-a", "agent-b", 1)
	if p.ProcedureID != "NHI-AGENT.1" {
		t.Errorf("ProcedureID = %q, want NHI-AGENT.1", p.ProcedureID)
	}
	if p.FactorC != 1 {
		t.Errorf("FactorC = %f, want 1", p.FactorC)
	}
}

func TestWitnessNhiDelegationMinDepth(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessNhiDelegation("a", "b", 0)
	if p.FactorC != 1 {
		t.Errorf("FactorC = %f, want 1 (minimum depth)", p.FactorC)
	}
}

func TestWitnessNhiRevocation(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessNhiRevocation("cred-123", NHIRevocationPolicyViolation, true)
	if p.ProcedureID != "NHI-REVOKE.1" {
		t.Errorf("ProcedureID = %q, want NHI-REVOKE.1", p.ProcedureID)
	}
	if p.FactorB != 2 {
		t.Errorf("FactorB = %f, want 2 (policy_violation)", p.FactorB)
	}
	if p.FactorC != 1 {
		t.Errorf("FactorC = %f, want 1 (cascade)", p.FactorC)
	}
}

func TestWitnessNhiRevocationNoCascade(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessNhiRevocation("cred", NHIRevocationUnspecified, false)
	if p.FactorC != 0 {
		t.Errorf("FactorC = %f, want 0 (no cascade)", p.FactorC)
	}
}

// ── HBOM Tests ──────────────────────────────────────────────────────

func TestWitnessHardwareInventory(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessHardwareInventory(42, "a1b2c3d4e5f60011", 3)
	if p.ProcedureID != "HBOM-INV.1" {
		t.Errorf("ProcedureID = %q, want HBOM-INV.1", p.ProcedureID)
	}
	if p.FactorA != 42 {
		t.Errorf("FactorA = %f, want 42", p.FactorA)
	}
	if p.FactorC != 3 {
		t.Errorf("FactorC = %f, want 3", p.FactorC)
	}
}

func TestWitnessComponentLifecycle(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessComponentLifecycle(HBOMEventInstalled, "GPU-A100-SN123", 0)
	if p.ProcedureID != "HBOM-LIFE.1" {
		t.Errorf("ProcedureID = %q, want HBOM-LIFE.1", p.ProcedureID)
	}
	if p.FactorA != 1 {
		t.Errorf("FactorA = %f, want 1 (installed)", p.FactorA)
	}
}

func TestWitnessComponentLifecycleAllEvents(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	events := []struct {
		code int
		want float64
	}{
		{HBOMEventInstalled, 1}, {HBOMEventCommissioned, 2}, {HBOMEventMaintained, 3},
		{HBOMEventDegraded, 4}, {HBOMEventDecommissioned, 5}, {HBOMEventRecycled, 6},
	}
	for _, e := range events {
		p := w.WitnessComponentLifecycle(e.code, "comp", 0)
		if p.FactorA != e.want {
			t.Errorf("event %d: FactorA = %f, want %f", e.code, p.FactorA, e.want)
		}
	}
}

func TestWitnessThermalProfile(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessThermalProfile(22.5, 65.3, false)
	if p.ProcedureID != "HBOM-THERM.1" {
		t.Errorf("ProcedureID = %q, want HBOM-THERM.1", p.ProcedureID)
	}
	if p.FactorA != 22.5 {
		t.Errorf("FactorA = %f, want 22.5", p.FactorA)
	}
	if p.FactorC != 0 {
		t.Errorf("FactorC = %f, want 0 (no threshold)", p.FactorC)
	}
}

func TestWitnessThermalProfileAlarm(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessThermalProfile(25, 85, true)
	if p.FactorC != 1 {
		t.Errorf("FactorC = %f, want 1 (alarm)", p.FactorC)
	}
}

func TestWitnessWaterConsumption(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessWaterConsumption(5000, 1200, HBOMWaterRecycled)
	if p.ProcedureID != "HBOM-WATER.1" {
		t.Errorf("ProcedureID = %q, want HBOM-WATER.1", p.ProcedureID)
	}
	if p.FactorA != 5000 {
		t.Errorf("FactorA = %f, want 5000", p.FactorA)
	}
	if p.FactorC != 2 {
		t.Errorf("FactorC = %f, want 2 (recycled)", p.FactorC)
	}
}

func TestWitnessPowerUsage(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessPowerUsage(1000, 800, 1250)
	if p.ProcedureID != "HBOM-PUE.1" {
		t.Errorf("ProcedureID = %q, want HBOM-PUE.1", p.ProcedureID)
	}
	if p.FactorA != 1000 {
		t.Errorf("FactorA = %f, want 1000", p.FactorA)
	}
	if p.FactorC != 1250 {
		t.Errorf("FactorC = %f, want 1250", p.FactorC)
	}
}

func TestWitnessSupplyChainProvenance(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessSupplyChainProvenance("Intel Corp", true, "US")
	if p.ProcedureID != "HBOM-SUPPLY.1" {
		t.Errorf("ProcedureID = %q, want HBOM-SUPPLY.1", p.ProcedureID)
	}
	if p.FactorB != 1 {
		t.Errorf("FactorB = %f, want 1 (verified)", p.FactorB)
	}
}

func TestWitnessSupplyChainProvenanceUnverified(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessSupplyChainProvenance("Unknown", false, "CN")
	if p.FactorB != 0 {
		t.Errorf("FactorB = %f, want 0 (unverified)", p.FactorB)
	}
}

// ── DPP Tests ───────────────────────────────────────────────────────

func TestWitnessBatterySoh(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessBatterySoh(92.3, 450, 48.5)
	if p.ProcedureID != "DPP-SOH.1" {
		t.Errorf("ProcedureID = %q, want DPP-SOH.1", p.ProcedureID)
	}
	if p.FactorA != 9230 {
		t.Errorf("FactorA = %f, want 9230", p.FactorA)
	}
	if p.FactorB != 450 {
		t.Errorf("FactorB = %f, want 450", p.FactorB)
	}
	if p.FactorC != 4850 {
		t.Errorf("FactorC = %f, want 4850", p.FactorC)
	}
}

func TestWitnessChargeCycle(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessChargeCycle(DPPChargeStart, 12.5, 28)
	if p.ProcedureID != "DPP-CHRG.1" {
		t.Errorf("ProcedureID = %q, want DPP-CHRG.1", p.ProcedureID)
	}
	if p.FactorA != 1 {
		t.Errorf("FactorA = %f, want 1 (charge_start)", p.FactorA)
	}
	if p.FactorB != 1250 {
		t.Errorf("FactorB = %f, want 1250", p.FactorB)
	}
}

func TestWitnessDegradationEvent(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessDegradationEvent(DPPDegradThermalStress, 0.5, 42)
	if p.ProcedureID != "DPP-DEGRAD.1" {
		t.Errorf("ProcedureID = %q, want DPP-DEGRAD.1", p.ProcedureID)
	}
	if p.FactorA != 2 {
		t.Errorf("FactorA = %f, want 2 (thermal_stress)", p.FactorA)
	}
	if p.FactorB != 50 {
		t.Errorf("FactorB = %f, want 50", p.FactorB)
	}
}

func TestWitnessEndOfLife(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessEndOfLife(DPPDispositionRecycling, "GreenRecycle LLC", 45)
	if p.ProcedureID != "DPP-EOL.1" {
		t.Errorf("ProcedureID = %q, want DPP-EOL.1", p.ProcedureID)
	}
	if p.FactorA != 1 {
		t.Errorf("FactorA = %f, want 1 (recycling)", p.FactorA)
	}
	if p.FactorC != 4500 {
		t.Errorf("FactorC = %f, want 4500", p.FactorC)
	}
}

// ── ADR Tests ───────────────────────────────────────────────────────

func TestWitnessDemandResponse(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessDemandResponse(ADRPhaseSignalReceived, 500, "PJM-ISO")
	if p.ProcedureID != "ADR-EVENT.1" {
		t.Errorf("ProcedureID = %q, want ADR-EVENT.1", p.ProcedureID)
	}
	if p.FactorA != 1 {
		t.Errorf("FactorA = %f, want 1 (signal_received)", p.FactorA)
	}
	if p.FactorB != 500 {
		t.Errorf("FactorB = %f, want 500", p.FactorB)
	}
}

func TestWitnessDemandResponseAllPhases(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	phases := []struct {
		code int
		want float64
	}{
		{ADRPhaseSignalReceived, 1}, {ADRPhaseCurtailmentStart, 2},
		{ADRPhaseCurtailmentEnd, 3}, {ADRPhaseRestoration, 4},
	}
	for _, ph := range phases {
		p := w.WitnessDemandResponse(ph.code, 100, "grid")
		if p.FactorA != ph.want {
			t.Errorf("phase %d: FactorA = %f, want %f", ph.code, p.FactorA, ph.want)
		}
	}
}

func TestWitnessBaselineConsumption(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessBaselineConsumption(2500, ADRBaselineMetered10DayAvg, 950)
	if p.ProcedureID != "ADR-BASE.1" {
		t.Errorf("ProcedureID = %q, want ADR-BASE.1", p.ProcedureID)
	}
	if p.FactorA != 2500 {
		t.Errorf("FactorA = %f, want 2500", p.FactorA)
	}
	if p.FactorB != 1 {
		t.Errorf("FactorB = %f, want 1 (metered_10day_avg)", p.FactorB)
	}
	if p.FactorC != 950 {
		t.Errorf("FactorC = %f, want 950", p.FactorC)
	}
}

func TestWitnessCurtailment(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessCurtailment(480, 500, 960)
	if p.ProcedureID != "ADR-CURT.1" {
		t.Errorf("ProcedureID = %q, want ADR-CURT.1", p.ProcedureID)
	}
	if p.FactorA != 480 {
		t.Errorf("FactorA = %f, want 480", p.FactorA)
	}
}

func TestWitnessSettlement(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessSettlement(125.5, 45, 3)
	if p.ProcedureID != "ADR-SETTLE.1" {
		t.Errorf("ProcedureID = %q, want ADR-SETTLE.1", p.ProcedureID)
	}
	if p.FactorA != 12550 {
		t.Errorf("FactorA = %f, want 12550", p.FactorA)
	}
	if p.FactorB != 4500 {
		t.Errorf("FactorB = %f, want 4500", p.FactorB)
	}
	if p.FactorC != 3 {
		t.Errorf("FactorC = %f, want 3", p.FactorC)
	}
}

func TestWitnessCarbonCredit(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessCarbonCredit(ADRCreditREC, 500, "M-RETS")
	if p.ProcedureID != "ADR-CARBON.1" {
		t.Errorf("ProcedureID = %q, want ADR-CARBON.1", p.ProcedureID)
	}
	if p.FactorA != 1 {
		t.Errorf("FactorA = %f, want 1 (REC)", p.FactorA)
	}
	if p.FactorB != 50000 {
		t.Errorf("FactorB = %f, want 50000", p.FactorB)
	}
}

func TestWitnessGridSignal(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessGridSignal(ADRSignalEmergency, 250, "ERCOT")
	if p.ProcedureID != "ADR-GRID.1" {
		t.Errorf("ProcedureID = %q, want ADR-GRID.1", p.ProcedureID)
	}
	if p.FactorA != 1 {
		t.Errorf("FactorA = %f, want 1 (emergency)", p.FactorA)
	}
	if p.FactorB != 250 {
		t.Errorf("FactorB = %f, want 250", p.FactorB)
	}
}

func TestWitnessGridSignalContextStripped(t *testing.T) {
	w := newTestWitness(ClearingSensitive)
	p := w.WitnessGridSignal(ADRSignalEconomic, 500, "CAISO")
	if p.AIContext != nil {
		t.Error("AIContext should be nil at clearing level 2")
	}
}

// ── A2A Tests ───────────────────────────────────────────────────────

func TestWitnessTaskLifecycle(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessTaskLifecycle(3, 250, 2)
	if p.ProcedureID != "AI-A2A.1" {
		t.Errorf("ProcedureID = %q, want AI-A2A.1", p.ProcedureID)
	}
	if p.FactorA != 3 {
		t.Errorf("FactorA = %f, want 3", p.FactorA)
	}
	if p.FactorB != 250 {
		t.Errorf("FactorB = %f, want 250", p.FactorB)
	}
	if p.FactorC != 2 {
		t.Errorf("FactorC = %f, want 2", p.FactorC)
	}
	if p.AIContext == nil {
		t.Error("AIContext should not be nil at clearing level 1")
	}
	if len(w.Buffer) != 1 {
		t.Errorf("Buffer length = %d, want 1", len(w.Buffer))
	}
}

func TestWitnessAgentCardDiscovery(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessAgentCardDiscovery(1, 5, 3)
	if p.ProcedureID != "AI-A2A.2" {
		t.Errorf("ProcedureID = %q, want AI-A2A.2", p.ProcedureID)
	}
	if p.FactorA != 1 {
		t.Errorf("FactorA = %f, want 1", p.FactorA)
	}
	if p.FactorB != 5 {
		t.Errorf("FactorB = %f, want 5", p.FactorB)
	}
	if p.FactorC != 3 {
		t.Errorf("FactorC = %f, want 3", p.FactorC)
	}
	if p.AIContext == nil {
		t.Error("AIContext should not be nil at clearing level 1")
	}
}

func TestWitnessOauthTokenBinding(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessOauthTokenBinding(0, 4, 2)
	if p.ProcedureID != "AI-MCP.5" {
		t.Errorf("ProcedureID = %q, want AI-MCP.5", p.ProcedureID)
	}
	if p.FactorA != 0 {
		t.Errorf("FactorA = %f, want 0", p.FactorA)
	}
	if p.FactorB != 4 {
		t.Errorf("FactorB = %f, want 4", p.FactorB)
	}
	if p.FactorC != 2 {
		t.Errorf("FactorC = %f, want 2", p.FactorC)
	}
	if p.AIContext == nil {
		t.Error("AIContext should not be nil at clearing level 1")
	}
}

func TestWitnessContextChain(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessContextChain(3, "ctx-abc-123", 5)
	if p.ProcedureID != "AI-A2A.3" {
		t.Errorf("ProcedureID = %q, want AI-A2A.3", p.ProcedureID)
	}
	if p.FactorA != 3 {
		t.Errorf("FactorA = %f, want 3", p.FactorA)
	}
	// fb should be hashToFactor(sha256("ctx-abc-123")[:8])
	expectedHash := Sha256Hex("ctx-abc-123", 8)
	expectedFb := hashToFactor(expectedHash)
	if p.FactorB != expectedFb {
		t.Errorf("FactorB = %f, want %f (hash of contextID)", p.FactorB, expectedFb)
	}
	if p.FactorC != 5 {
		t.Errorf("FactorC = %f, want 5", p.FactorC)
	}
	if p.AIContext == nil {
		t.Error("AIContext should not be nil at clearing level 1")
	}
}

// ── Cross-Cutting Tests ─────────────────────────────────────────────

func TestFlush(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	w.WitnessNhiScope("cred", "scope", 0)
	w.WitnessBatterySoh(90, 100, 50)
	w.WitnessGridSignal(ADRSignalEmergency, 100, "PJM")
	payloads := w.Flush()
	if len(payloads) != 3 {
		t.Errorf("Flush() returned %d payloads, want 3", len(payloads))
	}
	if len(w.Buffer) != 0 {
		t.Errorf("Buffer after flush = %d, want 0", len(w.Buffer))
	}
}

func TestSigningKeyApplied(t *testing.T) {
	w := NewWitness(WitnessConfig{
		Endpoint:      "https://test.example.com",
		APIKey:        "axm_test_key",
		TenantID:      "test_tenant",
		ClearingLevel: ClearingStandard,
		SigningKey:    "my-secret",
		AgentID:       "agent-1",
	})
	p := w.WitnessNhiScope("cred", "scope", 0)
	if p.PayloadSignature == "" {
		t.Error("PayloadSignature should be set when signing key is configured")
	}
	if p.SigningAlgorithm != "hmac-sha256" {
		t.Errorf("SigningAlgorithm = %q, want hmac-sha256", p.SigningAlgorithm)
	}
}

func TestCJTFieldsSurvive(t *testing.T) {
	w := NewWitness(WitnessConfig{
		Endpoint:      "https://test.example.com",
		APIKey:        "axm_test_key",
		TenantID:      "test_tenant",
		ClearingLevel: ClearingClassified,
		Jurisdiction:  "DE",
		LegalBasis:    "GDPR Art. 6(1)(f)",
		PurposeClass:  "fraud_detection",
	})
	p := w.WitnessNhiRevocation("cred", NHIRevocationRegulatoryOrder, true)
	if p.Jurisdiction != "DE" {
		t.Errorf("Jurisdiction = %q, want DE", p.Jurisdiction)
	}
	if p.LegalBasis != "GDPR Art. 6(1)(f)" {
		t.Errorf("LegalBasis = %q", p.LegalBasis)
	}
	if p.PurposeClass != "fraud_detection" {
		t.Errorf("PurposeClass = %q", p.PurposeClass)
	}
	if p.AIContext != nil {
		t.Error("AIContext should be nil at clearing level 3")
	}
}
