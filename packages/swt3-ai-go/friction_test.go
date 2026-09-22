package swt3

import (
	"strings"
	"testing"
)

// ── Cross-SDK Factor Parity ─────────────────────────────────────────
// These tests verify that Go produces the same factor values as Python and TypeScript
// for identical inputs. Factor encoding is part of the protocol -- any divergence
// means auditors see different data across SDK languages.

func TestFactorParity_NHI_SCOPE_1(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessNhiScope("cred-abc-123", "read,write", 3600)

	// factor_c must be literal TTL
	if p.FactorC != 3600 {
		t.Errorf("NHI-SCOPE.1 fc=%f, want 3600 (TTL passthrough)", p.FactorC)
	}
	// factor_a and factor_b must be derived from SHA-256 hash, non-zero
	if p.FactorA == 0 {
		t.Error("NHI-SCOPE.1 fa=0, credential hash should produce non-zero factor")
	}
	if p.FactorB == 0 {
		t.Error("NHI-SCOPE.1 fb=0, scope hash should produce non-zero factor")
	}
}

func TestFactorParity_DPP_SOH_1(t *testing.T) {
	// Python: fa = int(92.3 * 100) = 9230, fb = 450, fc = int(48.5 * 100) = 4850
	w := newTestWitness(ClearingStandard)
	p := w.WitnessBatterySoh(92.3, 450, 48.5)
	if p.FactorA != 9230 {
		t.Errorf("DPP-SOH.1 fa=%f, want 9230 (soh_percent * 100)", p.FactorA)
	}
	if p.FactorB != 450 {
		t.Errorf("DPP-SOH.1 fb=%f, want 450 (cycle_count)", p.FactorB)
	}
	if p.FactorC != 4850 {
		t.Errorf("DPP-SOH.1 fc=%f, want 4850 (capacity_kwh * 100)", p.FactorC)
	}
}

func TestFactorParity_ADR_SETTLE_1(t *testing.T) {
	// Python: fa = int(125.5 * 100) = 12550, fb = int(45.0 * 100) = 4500, fc = 3
	w := newTestWitness(ClearingStandard)
	p := w.WitnessSettlement(125.5, 45.0, 3)
	if p.FactorA != 12550 {
		t.Errorf("ADR-SETTLE.1 fa=%f, want 12550", p.FactorA)
	}
	if p.FactorB != 4500 {
		t.Errorf("ADR-SETTLE.1 fb=%f, want 4500", p.FactorB)
	}
	if p.FactorC != 3 {
		t.Errorf("ADR-SETTLE.1 fc=%f, want 3", p.FactorC)
	}
}

func TestFactorParity_ADR_CURT_1(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessCurtailment(480, 500, 960)
	if p.FactorA != 480 || p.FactorB != 500 || p.FactorC != 960 {
		t.Errorf("ADR-CURT.1 factors = (%f,%f,%f), want (480,500,960)", p.FactorA, p.FactorB, p.FactorC)
	}
}

func TestFactorParity_HBOM_THERM_1(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	p := w.WitnessThermalProfile(22.5, 65.3, false)
	if p.FactorA != 22.5 || p.FactorB != 65.3 || p.FactorC != 0 {
		t.Errorf("HBOM-THERM.1 factors = (%f,%f,%f), want (22.5,65.3,0)", p.FactorA, p.FactorB, p.FactorC)
	}
}

// ── Clearing Level Behavior Parity ──────────────────────────────────

func TestClearingLevel_ContextPresence(t *testing.T) {
	procedures := []struct {
		name string
		call func(*Witness) WitnessPayload
	}{
		{"NHI-SCOPE.1", func(w *Witness) WitnessPayload { return w.WitnessNhiScope("c", "s", 0) }},
		{"NHI-CYCLE.1", func(w *Witness) WitnessPayload { return w.WitnessNhiLifecycle(1, "c", "i") }},
		{"NHI-PRIV.1", func(w *Witness) WitnessPayload { return w.WitnessNhiPrivilegeChange("c", "old", "new") }},
		{"NHI-ROTATE.1", func(w *Witness) WitnessPayload { return w.WitnessNhiRotation("old", "new", 1) }},
		{"NHI-AGENT.1", func(w *Witness) WitnessPayload { return w.WitnessNhiDelegation("a", "b", 1) }},
		{"NHI-REVOKE.1", func(w *Witness) WitnessPayload { return w.WitnessNhiRevocation("c", 0, false) }},
		{"HBOM-INV.1", func(w *Witness) WitnessPayload { return w.WitnessHardwareInventory(10, "hash", 0) }},
		{"HBOM-LIFE.1", func(w *Witness) WitnessPayload { return w.WitnessComponentLifecycle(1, "comp", 0) }},
		{"HBOM-THERM.1", func(w *Witness) WitnessPayload { return w.WitnessThermalProfile(20, 60, false) }},
		{"HBOM-WATER.1", func(w *Witness) WitnessPayload { return w.WitnessWaterConsumption(100, 800, 1) }},
		{"HBOM-PUE.1", func(w *Witness) WitnessPayload { return w.WitnessPowerUsage(500, 400, 1250) }},
		{"HBOM-SUPPLY.1", func(w *Witness) WitnessPayload { return w.WitnessSupplyChainProvenance("s", true, "US") }},
		{"DPP-SOH.1", func(w *Witness) WitnessPayload { return w.WitnessBatterySoh(90, 100, 50) }},
		{"DPP-CHRG.1", func(w *Witness) WitnessPayload { return w.WitnessChargeCycle(1, 10, 25) }},
		{"DPP-DEGRAD.1", func(w *Witness) WitnessPayload { return w.WitnessDegradationEvent(1, 0.5, 25) }},
		{"DPP-EOL.1", func(w *Witness) WitnessPayload { return w.WitnessEndOfLife(1, "handler", 50) }},
		{"ADR-EVENT.1", func(w *Witness) WitnessPayload { return w.WitnessDemandResponse(1, 500, "grid") }},
		{"ADR-BASE.1", func(w *Witness) WitnessPayload { return w.WitnessBaselineConsumption(1000, 1, 950) }},
		{"ADR-CURT.1", func(w *Witness) WitnessPayload { return w.WitnessCurtailment(480, 500, 960) }},
		{"ADR-SETTLE.1", func(w *Witness) WitnessPayload { return w.WitnessSettlement(100, 50, 5) }},
		{"ADR-CARBON.1", func(w *Witness) WitnessPayload { return w.WitnessCarbonCredit(1, 100, "reg") }},
		{"ADR-GRID.1", func(w *Witness) WitnessPayload { return w.WitnessGridSignal(1, 100, "PJM") }},
	}

	for _, proc := range procedures {
		t.Run(proc.name+"_level0", func(t *testing.T) {
			w := newTestWitness(ClearingAnalytics)
			p := proc.call(w)
			if p.AIContext == nil {
				t.Errorf("%s: context should be present at level 0", proc.name)
			}
			if p.AIModelID == "" {
				t.Errorf("%s: model_id should be set at level 0", proc.name)
			}
		})
		t.Run(proc.name+"_level1", func(t *testing.T) {
			w := newTestWitness(ClearingStandard)
			p := proc.call(w)
			if p.AIContext == nil {
				t.Errorf("%s: context should be present at level 1", proc.name)
			}
		})
		t.Run(proc.name+"_level2", func(t *testing.T) {
			w := newTestWitness(ClearingSensitive)
			p := proc.call(w)
			if p.AIContext != nil {
				t.Errorf("%s: context should be nil at level 2", proc.name)
			}
			if p.AIModelID != "" {
				t.Errorf("%s: model_id should be empty at level 2", proc.name)
			}
		})
		t.Run(proc.name+"_level3", func(t *testing.T) {
			w := newTestWitness(ClearingClassified)
			p := proc.call(w)
			if p.AIContext != nil {
				t.Errorf("%s: context should be nil at level 3", proc.name)
			}
		})
	}
}

// ── Fingerprint Validity ────────────────────────────────────────────

func TestAllProcedures_ValidFingerprint(t *testing.T) {
	w := newTestWitness(ClearingStandard)
	payloads := []WitnessPayload{
		w.WitnessNhiScope("c", "s", 0),
		w.WitnessNhiLifecycle(1, "c", "i"),
		w.WitnessNhiPrivilegeChange("c", "old", "new"),
		w.WitnessNhiRotation("old", "new", 1),
		w.WitnessNhiDelegation("a", "b", 1),
		w.WitnessNhiRevocation("c", 0, false),
		w.WitnessHardwareInventory(10, "hash", 0),
		w.WitnessComponentLifecycle(1, "comp", 0),
		w.WitnessThermalProfile(20, 60, false),
		w.WitnessWaterConsumption(100, 800, 1),
		w.WitnessPowerUsage(500, 400, 1250),
		w.WitnessSupplyChainProvenance("s", true, "US"),
		w.WitnessBatterySoh(90, 100, 50),
		w.WitnessChargeCycle(1, 10, 25),
		w.WitnessDegradationEvent(1, 0.5, 25),
		w.WitnessEndOfLife(1, "handler", 50),
		w.WitnessDemandResponse(1, 500, "grid"),
		w.WitnessBaselineConsumption(1000, 1, 950),
		w.WitnessCurtailment(480, 500, 960),
		w.WitnessSettlement(100, 50, 5),
		w.WitnessCarbonCredit(1, 100, "reg"),
		w.WitnessGridSignal(1, 100, "PJM"),
	}
	for _, p := range payloads {
		if len(p.AnchorFingerprint) != 12 {
			t.Errorf("%s: fingerprint length = %d, want 12", p.ProcedureID, len(p.AnchorFingerprint))
		}
		// Must be valid hex
		for _, c := range p.AnchorFingerprint {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Errorf("%s: fingerprint contains non-hex char %q", p.ProcedureID, string(c))
			}
		}
		if p.AnchorEpoch == 0 {
			t.Errorf("%s: epoch should be set", p.ProcedureID)
		}
		if p.FingerprintTimestamp == 0 {
			t.Errorf("%s: timestamp_ms should be set", p.ProcedureID)
		}
	}
}

// ── Context Key Parity ──────────────────────────────────────────────
// All SDKs must use identical context key names (snake_case) so the server
// can parse them uniformly.

func TestContextKeyParity_NHI(t *testing.T) {
	w := newTestWitness(ClearingStandard)

	p := w.WitnessNhiScope("cred", "scope", 60)
	requireContextKey(t, p, "credential_id_hash")
	requireContextKey(t, p, "scope_hash")
	requireContextKey(t, p, "ttl_seconds")
	requireContextKey(t, p, "provider")

	p = w.WitnessNhiLifecycle(1, "cred", "issuer")
	requireContextKey(t, p, "event_type")
	requireContextKey(t, p, "credential_id_hash")
	requireContextKey(t, p, "issuer_hash")

	p = w.WitnessNhiRotation("old", "new", 1)
	requireContextKey(t, p, "old_credential_hash")
	requireContextKey(t, p, "new_credential_hash")
	requireContextKey(t, p, "rotation_reason")

	p = w.WitnessNhiDelegation("a", "b", 2)
	requireContextKey(t, p, "delegator_hash")
	requireContextKey(t, p, "delegatee_hash")
	requireContextKey(t, p, "delegation_depth")

	p = w.WitnessNhiRevocation("cred", 2, true)
	requireContextKey(t, p, "revoked_credential_hash")
	requireContextKey(t, p, "reason_code")
	requireContextKey(t, p, "cascade")
}

func TestContextKeyParity_ADR(t *testing.T) {
	w := newTestWitness(ClearingStandard)

	p := w.WitnessDemandResponse(1, 500, "PJM")
	requireContextKey(t, p, "event_phase")
	requireContextKey(t, p, "committed_kw")
	requireContextKey(t, p, "signal_source_hash")

	p = w.WitnessSettlement(100, 50, 5)
	requireContextKey(t, p, "settlement_kwh")
	requireContextKey(t, p, "price_usd_per_mwh")
	requireContextKey(t, p, "event_count")

	p = w.WitnessCarbonCredit(1, 100, "M-RETS")
	requireContextKey(t, p, "credit_type")
	requireContextKey(t, p, "quantity_mwh")
	requireContextKey(t, p, "registry_hash")
}

func requireContextKey(t *testing.T, p WitnessPayload, key string) {
	t.Helper()
	if p.AIContext == nil {
		t.Errorf("%s: context is nil, expected key %q", p.ProcedureID, key)
		return
	}
	if _, ok := p.AIContext[key]; !ok {
		t.Errorf("%s: missing context key %q", p.ProcedureID, key)
	}
}

// ── Hash Determinism ────────────────────────────────────────────────

func TestHashDeterminism_CrossMethod(t *testing.T) {
	// Same credential ID must produce same hash in NHI-SCOPE.1 and NHI-CYCLE.1
	w := newTestWitness(ClearingStandard)
	p1 := w.WitnessNhiScope("test-cred-xyz", "scope", 0)
	p2 := w.WitnessNhiLifecycle(1, "test-cred-xyz", "issuer")

	h1 := p1.AIContext["credential_id_hash"].(string)
	h2 := p2.AIContext["credential_id_hash"].(string)
	if h1 != h2 {
		t.Errorf("credential hash divergence: NHI-SCOPE.1=%q vs NHI-CYCLE.1=%q", h1, h2)
	}
}
