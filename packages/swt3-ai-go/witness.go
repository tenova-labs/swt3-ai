package swt3

import (
	"strings"
	"strconv"
)

// Witness provides named witness methods for minting SWT3 anchors.
//
// Each method returns a WitnessPayload with computed factors, fingerprint,
// and optional context (stripped at clearing level >= 2). Payloads are
// accumulated in an internal buffer for batch ingestion.
type Witness struct {
	Config  WitnessConfig
	Buffer  []WitnessPayload
}

// NewWitness creates a Witness with the given configuration.
func NewWitness(config WitnessConfig) *Witness {
	if config.BufferSize == 0 {
		config.BufferSize = 100
	}
	return &Witness{
		Config: config,
		Buffer: make([]WitnessPayload, 0, config.BufferSize),
	}
}

// mint creates a WitnessPayload and enqueues it.
func (w *Witness) mint(procedureID string, fa, fb, fc float64) WitnessPayload {
	ts, epoch := TimestampMs()
	fp := MintFingerprint(w.Config.TenantID, procedureID, fa, fb, fc, ts)
	p := WitnessPayload{
		ProcedureID:          procedureID,
		FactorA:              fa,
		FactorB:              fb,
		FactorC:              fc,
		ClearingLevel:        w.Config.ClearingLevel,
		AnchorFingerprint:    fp,
		AnchorEpoch:          epoch,
		FingerprintTimestamp: ts,
	}
	if w.Config.AgentID != "" {
		p.AgentID = w.Config.AgentID
	}
	if w.Config.Jurisdiction != "" {
		p.Jurisdiction = w.Config.Jurisdiction
	}
	if w.Config.LegalBasis != "" {
		p.LegalBasis = w.Config.LegalBasis
	}
	if w.Config.PurposeClass != "" {
		p.PurposeClass = w.Config.PurposeClass
	}
	if w.Config.AuthorizationExpires != 0 {
		p.AuthorizationExpires = w.Config.AuthorizationExpires
	}
	if w.Config.AuthorizationScope != "" {
		p.AuthorizationScope = w.Config.AuthorizationScope
	}
	if w.Config.SigningKey != "" {
		p.PayloadSignature = SignPayload(w.Config.SigningKey, fp, w.Config.AgentID)
		p.SigningAlgorithm = "hmac-sha256"
	}
	return p
}

// enqueue appends a payload to the buffer.
func (w *Witness) enqueue(p WitnessPayload) {
	w.Buffer = append(w.Buffer, p)
}

// Flush returns all buffered payloads and resets the buffer.
func (w *Witness) Flush() []WitnessPayload {
	out := w.Buffer
	w.Buffer = make([]WitnessPayload, 0, w.Config.BufferSize)
	return out
}

// hashToFactor converts a hex hash string to a float64 factor value.
func hashToFactor(hexStr string) float64 {
	if len(hexStr) > 8 {
		hexStr = hexStr[:8]
	}
	v, _ := strconv.ParseUint(hexStr, 16, 64)
	return float64(v)
}

// ── NHI: Non-Human Identity Governance ──────────────────────────────

// WitnessNhiScope witnesses credential scope attestation (NHI-SCOPE.1).
func (w *Witness) WitnessNhiScope(credentialID, scope string, ttlSeconds int) WitnessPayload {
	credHash := Sha256Truncated(credentialID, 16)
	scopeHash := Sha256Truncated(strings.ToLower(scope), 16)
	fa := hashToFactor(credHash)
	fb := hashToFactor(scopeHash)
	fc := float64(ttlSeconds)
	p := w.mint("NHI-SCOPE.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "nhi-scope-" + credHash[:8]
		p.AIContext = map[string]interface{}{
			"provider":          "nhi-governance",
			"credential_id_hash": credHash,
			"scope_hash":         scopeHash,
			"ttl_seconds":        ttlSeconds,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessNhiLifecycle witnesses a credential lifecycle event (NHI-CYCLE.1).
func (w *Witness) WitnessNhiLifecycle(eventType int, credentialID, issuer string) WitnessPayload {
	credHash := Sha256Truncated(credentialID, 16)
	issuerHash := Sha256Truncated(issuer, 16)
	fa := float64(eventType)
	fb := hashToFactor(credHash)
	fc := hashToFactor(issuerHash)
	p := w.mint("NHI-CYCLE.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "nhi-lifecycle-" + strconv.Itoa(eventType)
		p.AIContext = map[string]interface{}{
			"provider":          "nhi-governance",
			"event_type":         eventType,
			"credential_id_hash": credHash,
			"issuer_hash":        issuerHash,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessNhiPrivilegeChange witnesses a privilege change (NHI-PRIV.1).
func (w *Witness) WitnessNhiPrivilegeChange(credentialID, previousScope, newScope string) WitnessPayload {
	credHash := Sha256Truncated(credentialID, 16)
	fa := hashToFactor(credHash)
	var fb float64
	if previousScope != "" {
		prevHash := Sha256Truncated(strings.ToLower(previousScope), 16)
		fb = hashToFactor(prevHash)
	}
	newHash := Sha256Truncated(strings.ToLower(newScope), 16)
	fc := hashToFactor(newHash)
	p := w.mint("NHI-PRIV.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		prevH := "0"
		if previousScope != "" {
			prevH = Sha256Truncated(strings.ToLower(previousScope), 16)
		}
		p.AIModelID = "nhi-priv-" + credHash[:8]
		p.AIContext = map[string]interface{}{
			"provider":            "nhi-governance",
			"credential_id_hash":  credHash,
			"previous_scope_hash": prevH,
			"new_scope_hash":      Sha256Truncated(strings.ToLower(newScope), 16),
		}
	}
	w.enqueue(p)
	return p
}

// WitnessNhiRotation witnesses credential rotation (NHI-ROTATE.1).
func (w *Witness) WitnessNhiRotation(oldCredentialID, newCredentialID string, reason int) WitnessPayload {
	oldHash := Sha256Truncated(oldCredentialID, 16)
	newHash := Sha256Truncated(newCredentialID, 16)
	fa := hashToFactor(oldHash)
	fb := hashToFactor(newHash)
	fc := float64(reason)
	p := w.mint("NHI-ROTATE.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "nhi-rotate-" + strconv.Itoa(reason)
		p.AIContext = map[string]interface{}{
			"provider":            "nhi-governance",
			"old_credential_hash": oldHash,
			"new_credential_hash": newHash,
			"rotation_reason":     reason,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessNhiDelegation witnesses agent-to-agent credential delegation (NHI-AGENT.1).
func (w *Witness) WitnessNhiDelegation(delegatorCredentialID, delegateeCredentialID string, delegationDepth int) WitnessPayload {
	delegatorHash := Sha256Truncated(delegatorCredentialID, 16)
	delegateeHash := Sha256Truncated(delegateeCredentialID, 16)
	fa := hashToFactor(delegatorHash)
	fb := hashToFactor(delegateeHash)
	depth := delegationDepth
	if depth < 1 {
		depth = 1
	}
	fc := float64(depth)
	p := w.mint("NHI-AGENT.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "nhi-delegation-depth" + strconv.Itoa(depth)
		p.AIContext = map[string]interface{}{
			"provider":          "nhi-governance",
			"delegator_hash":    delegatorHash,
			"delegatee_hash":    delegateeHash,
			"delegation_depth":  depth,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessNhiRevocation witnesses credential revocation (NHI-REVOKE.1).
func (w *Witness) WitnessNhiRevocation(credentialID string, reason int, cascade bool) WitnessPayload {
	credHash := Sha256Truncated(credentialID, 16)
	fa := hashToFactor(credHash)
	fb := float64(reason)
	var fc float64
	if cascade {
		fc = 1
	}
	p := w.mint("NHI-REVOKE.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "nhi-revoke-" + strconv.Itoa(reason)
		p.AIContext = map[string]interface{}{
			"provider":               "nhi-governance",
			"revoked_credential_hash": credHash,
			"reason_code":             reason,
			"cascade":                 cascade,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessNhiExpiration witnesses credential expiration event (NHI-EXPIRE.1).
func (w *Witness) WitnessNhiExpiration(credentialID string, expiresEpochMs int64, renewalPossible bool, gracePeriodSeconds int) WitnessPayload {
	credHash := Sha256Truncated(credentialID, 16)
	fa := hashToFactor(credHash)
	fb := float64(expiresEpochMs / 1000)
	renewal := 0
	if renewalPossible {
		renewal = 1
	}
	fc := float64(renewal | (gracePeriodSeconds << 8))
	p := w.mint("NHI-EXPIRE.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		label := "permanent"
		if renewalPossible {
			label = "renewable"
		}
		p.AIModelID = "nhi-expire-" + label
		p.AIContext = map[string]interface{}{
			"provider":             "nhi-governance",
			"credential_hash":     credHash,
			"expires_epoch_ms":    expiresEpochMs,
			"renewal_possible":    renewalPossible,
			"grace_period_seconds": gracePeriodSeconds,
		}
	}
	w.enqueue(p)
	return p
}

// ── MCP Tool Integrity (AI-MCP.2) ──────────────────────────────────

// WitnessToolIntegrity witnesses MCP tool integrity attestation (AI-MCP.2).
// Hashes the tool schema to detect poisoning (OWASP MCP-03) and rug pulls.
func (w *Witness) WitnessToolIntegrity(toolName, toolSchema string, invocationSeq int, previousSchemaHash string) WitnessPayload {
	schemaHash := Sha256Truncated(toolSchema, 16)
	fa := hashToFactor(schemaHash)
	fb := float64(invocationSeq)
	drift := 0
	if previousSchemaHash != "" && previousSchemaHash != schemaHash {
		drift = 1
	}
	fc := float64(drift)
	p := w.mint("AI-MCP.2", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "mcp-tool-" + toolName
		p.AIContext = map[string]interface{}{
			"provider":       "mcp-tool-integrity",
			"tool_name":      toolName,
			"schema_hash":    schemaHash,
			"invocation_seq": invocationSeq,
			"schema_drift":   drift == 1,
		}
	}
	w.enqueue(p)
	return p
}

// ── MCP Server Authentication (AI-MCP.3) ──────────────────────────

// WitnessServerAuth witnesses MCP server authentication attestation (AI-MCP.3).
// Records auth method before tool invocation. FAIL when no auth (method=0).
func (w *Witness) WitnessServerAuth(authMethod int, credentialValiditySeconds int, mutualAuth bool) WitnessPayload {
	fa := float64(authMethod)
	fb := float64(credentialValiditySeconds)
	mutual := 0
	if mutualAuth {
		mutual = 1
	}
	fc := float64(mutual)
	p := w.mint("AI-MCP.3", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		labels := map[int]string{0: "none", 1: "api_key", 2: "oauth", 3: "mtls", 4: "did"}
		label := labels[authMethod]
		if label == "" {
			label = "unknown-" + strconv.Itoa(authMethod)
		}
		p.AIModelID = "mcp-auth-" + label
		p.AIContext = map[string]interface{}{
			"provider":                     "mcp-server-auth",
			"auth_method":                  authMethod,
			"credential_validity_seconds":  credentialValiditySeconds,
			"mutual_auth":                  mutualAuth,
		}
	}
	w.enqueue(p)
	return p
}

// ── MCP Server Discovery (AI-MCP.4) ───────────────────────────────

// WitnessServerDiscovery witnesses MCP server discovery attestation (AI-MCP.4).
// Records server inventory and unauthorized server detection.
func (w *Witness) WitnessServerDiscovery(discoveryMethod int, serversFound int, unauthorizedCount int) WitnessPayload {
	fa := float64(discoveryMethod)
	fb := float64(serversFound)
	fc := float64(unauthorizedCount)
	p := w.mint("AI-MCP.4", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		labels := map[int]string{0: "manual", 1: "dns-sd", 2: "mdns", 3: "registry", 4: "network"}
		label := labels[discoveryMethod]
		if label == "" {
			label = "method-" + strconv.Itoa(discoveryMethod)
		}
		p.AIModelID = "mcp-discovery-" + label
		p.AIContext = map[string]interface{}{
			"provider":           "mcp-server-discovery",
			"discovery_method":   discoveryMethod,
			"servers_found":      serversFound,
			"unauthorized_count": unauthorizedCount,
		}
	}
	w.enqueue(p)
	return p
}

// ── HBOM: Hardware Bill of Materials ────────────────────────────────

// WitnessHardwareInventory witnesses hardware inventory attestation (HBOM-INV.1).
func (w *Witness) WitnessHardwareInventory(componentCount int, manifestHash string, deltaFromBaseline int) WitnessPayload {
	fa := float64(componentCount)
	fb := hashToFactor(manifestHash)
	fc := float64(deltaFromBaseline)
	p := w.mint("HBOM-INV.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		mh := manifestHash
		if len(mh) > 16 {
			mh = mh[:16]
		}
		p.AIModelID = "hbom-inv-" + strconv.Itoa(componentCount)
		p.AIContext = map[string]interface{}{
			"provider":            "hbom-governance",
			"component_count":     componentCount,
			"manifest_hash":       mh,
			"delta_from_baseline": deltaFromBaseline,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessComponentLifecycle witnesses a component lifecycle event (HBOM-LIFE.1).
func (w *Witness) WitnessComponentLifecycle(eventType int, componentID string, ageDays int) WitnessPayload {
	compHash := Sha256Truncated(componentID, 16)
	fa := float64(eventType)
	fb := hashToFactor(compHash)
	fc := float64(ageDays)
	p := w.mint("HBOM-LIFE.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "hbom-lifecycle-" + strconv.Itoa(eventType)
		p.AIContext = map[string]interface{}{
			"provider":       "hbom-governance",
			"event_type":     eventType,
			"component_hash": compHash,
			"age_days":       ageDays,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessThermalProfile witnesses thermal profile attestation (HBOM-THERM.1).
func (w *Witness) WitnessThermalProfile(ambientTempC, componentTempC float64, thresholdExceeded bool) WitnessPayload {
	fa := ambientTempC
	fb := componentTempC
	var fc float64
	if thresholdExceeded {
		fc = 1
	}
	p := w.mint("HBOM-THERM.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		label := "normal"
		if thresholdExceeded {
			label = "alarm"
		}
		p.AIModelID = "hbom-thermal-" + label
		p.AIContext = map[string]interface{}{
			"provider":           "hbom-governance",
			"ambient_temp_c":     ambientTempC,
			"component_temp_c":   componentTempC,
			"threshold_exceeded": thresholdExceeded,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessWaterConsumption witnesses water consumption (HBOM-WATER.1).
func (w *Witness) WitnessWaterConsumption(litersConsumed float64, wueRatioX1000 int, sourceType int) WitnessPayload {
	fa := litersConsumed
	fb := float64(wueRatioX1000)
	fc := float64(sourceType)
	p := w.mint("HBOM-WATER.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "hbom-water-" + strconv.Itoa(sourceType)
		p.AIContext = map[string]interface{}{
			"provider":        "hbom-governance",
			"liters_consumed": litersConsumed,
			"wue_ratio_x1000": wueRatioX1000,
			"source_type":     sourceType,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessPowerUsage witnesses PUE attestation (HBOM-PUE.1).
func (w *Witness) WitnessPowerUsage(totalFacilityKw, itLoadKw float64, pueX1000 int) WitnessPayload {
	fa := totalFacilityKw
	fb := itLoadKw
	fc := float64(pueX1000)
	p := w.mint("HBOM-PUE.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "hbom-pue-" + strconv.Itoa(pueX1000)
		p.AIContext = map[string]interface{}{
			"provider":         "hbom-governance",
			"total_facility_kw": totalFacilityKw,
			"it_load_kw":        itLoadKw,
			"pue_x1000":         pueX1000,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessSupplyChainProvenance witnesses hardware supply chain provenance (HBOM-SUPPLY.1).
func (w *Witness) WitnessSupplyChainProvenance(supplierID string, provenanceVerified bool, countryOfOrigin string) WitnessPayload {
	supplierHash := Sha256Truncated(supplierID, 16)
	countryHash := Sha256Truncated(strings.ToUpper(countryOfOrigin), 16)
	fa := hashToFactor(supplierHash)
	var fb float64
	if provenanceVerified {
		fb = 1
	}
	fc := hashToFactor(countryHash)
	p := w.mint("HBOM-SUPPLY.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		label := "unverified"
		if provenanceVerified {
			label = "verified"
		}
		p.AIModelID = "hbom-supply-" + label
		p.AIContext = map[string]interface{}{
			"provider":             "hbom-governance",
			"supplier_hash":        supplierHash,
			"provenance_verified":  provenanceVerified,
			"country_hash":         countryHash,
		}
	}
	w.enqueue(p)
	return p
}

// ── DPP: Digital Product Passport ───────────────────────────────────

// WitnessBatterySoh witnesses battery state of health (DPP-SOH.1).
func (w *Witness) WitnessBatterySoh(sohPercent float64, cycleCount int, capacityKwh float64) WitnessPayload {
	fa := float64(int(sohPercent * 100))
	fb := float64(cycleCount)
	fc := float64(int(capacityKwh * 100))
	p := w.mint("DPP-SOH.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "dpp-soh-" + strconv.Itoa(int(sohPercent)) + "pct"
		p.AIContext = map[string]interface{}{
			"provider":     "dpp-governance",
			"soh_percent":  sohPercent,
			"cycle_count":  cycleCount,
			"capacity_kwh": capacityKwh,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessChargeCycle witnesses a charge/discharge cycle event (DPP-CHRG.1).
func (w *Witness) WitnessChargeCycle(eventType int, energyKwh, peakTempC float64) WitnessPayload {
	fa := float64(eventType)
	fb := float64(int(energyKwh * 100))
	fc := peakTempC
	p := w.mint("DPP-CHRG.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "dpp-chrg-" + strconv.Itoa(eventType)
		p.AIContext = map[string]interface{}{
			"provider":    "dpp-governance",
			"event_type":  eventType,
			"energy_kwh":  energyKwh,
			"peak_temp_c": peakTempC,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessDegradationEvent witnesses a battery degradation event (DPP-DEGRAD.1).
func (w *Witness) WitnessDegradationEvent(degradationType int, sohDeltaPercent, ambientTempC float64) WitnessPayload {
	fa := float64(degradationType)
	fb := float64(int(sohDeltaPercent * 100))
	fc := ambientTempC
	p := w.mint("DPP-DEGRAD.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "dpp-degrad-" + strconv.Itoa(degradationType)
		p.AIContext = map[string]interface{}{
			"provider":          "dpp-governance",
			"degradation_type":  degradationType,
			"soh_delta_percent": sohDeltaPercent,
			"ambient_temp_c":    ambientTempC,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessEndOfLife witnesses end-of-life / recycling handoff (DPP-EOL.1).
func (w *Witness) WitnessEndOfLife(dispositionType int, handlerID string, finalSohPercent float64) WitnessPayload {
	handlerHash := Sha256Truncated(handlerID, 16)
	fa := float64(dispositionType)
	fb := hashToFactor(handlerHash)
	fc := float64(int(finalSohPercent * 100))
	p := w.mint("DPP-EOL.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "dpp-eol-" + strconv.Itoa(dispositionType)
		p.AIContext = map[string]interface{}{
			"provider":          "dpp-governance",
			"disposition_type":  dispositionType,
			"handler_hash":      handlerHash,
			"final_soh_percent": finalSohPercent,
		}
	}
	w.enqueue(p)
	return p
}

// ── ADR: Automated Demand Response ──────────────────────────────────

// WitnessDemandResponse witnesses a demand response event (ADR-EVENT.1).
func (w *Witness) WitnessDemandResponse(eventPhase int, committedKw float64, signalSource string) WitnessPayload {
	signalHash := Sha256Truncated(signalSource, 16)
	fa := float64(eventPhase)
	fb := committedKw
	fc := hashToFactor(signalHash)
	p := w.mint("ADR-EVENT.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "adr-event-" + strconv.Itoa(eventPhase)
		p.AIContext = map[string]interface{}{
			"provider":          "adr-governance",
			"event_phase":       eventPhase,
			"committed_kw":      committedKw,
			"signal_source_hash": signalHash,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessBaselineConsumption witnesses baseline consumption attestation (ADR-BASE.1).
func (w *Witness) WitnessBaselineConsumption(baselineKw float64, measurementMethod, confidenceX1000 int) WitnessPayload {
	fa := baselineKw
	fb := float64(measurementMethod)
	fc := float64(confidenceX1000)
	p := w.mint("ADR-BASE.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "adr-baseline-" + strconv.Itoa(measurementMethod)
		p.AIContext = map[string]interface{}{
			"provider":           "adr-governance",
			"baseline_kw":        baselineKw,
			"measurement_method": measurementMethod,
			"confidence_x1000":   confidenceX1000,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessCurtailment witnesses curtailment verification (ADR-CURT.1).
func (w *Witness) WitnessCurtailment(actualReductionKw, committedKw float64, complianceRatioX1000 int) WitnessPayload {
	fa := actualReductionKw
	fb := committedKw
	fc := float64(complianceRatioX1000)
	p := w.mint("ADR-CURT.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "adr-curtailment-" + strconv.Itoa(complianceRatioX1000)
		p.AIContext = map[string]interface{}{
			"provider":               "adr-governance",
			"actual_reduction_kw":    actualReductionKw,
			"committed_kw":           committedKw,
			"compliance_ratio_x1000": complianceRatioX1000,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessSettlement witnesses settlement data attestation (ADR-SETTLE.1).
func (w *Witness) WitnessSettlement(settlementKwh, priceUsdPerMwh float64, eventCount int) WitnessPayload {
	fa := float64(int(settlementKwh * 100))
	fb := float64(int(priceUsdPerMwh * 100))
	fc := float64(eventCount)
	p := w.mint("ADR-SETTLE.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "adr-settlement-" + strconv.Itoa(eventCount) + "events"
		p.AIContext = map[string]interface{}{
			"provider":          "adr-governance",
			"settlement_kwh":    settlementKwh,
			"price_usd_per_mwh": priceUsdPerMwh,
			"event_count":       eventCount,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessCarbonCredit witnesses carbon credit / REC attestation (ADR-CARBON.1).
func (w *Witness) WitnessCarbonCredit(creditType int, quantityMwh float64, registryID string) WitnessPayload {
	registryHash := Sha256Truncated(registryID, 16)
	fa := float64(creditType)
	fb := float64(int(quantityMwh * 100))
	fc := hashToFactor(registryHash)
	p := w.mint("ADR-CARBON.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "adr-carbon-" + strconv.Itoa(creditType)
		p.AIContext = map[string]interface{}{
			"provider":      "adr-governance",
			"credit_type":   creditType,
			"quantity_mwh":  quantityMwh,
			"registry_hash": registryHash,
		}
	}
	w.enqueue(p)
	return p
}

// ── Harness Governance (v0.7.2) ─────────────────────────────────────

// WitnessOrchestrationTopology witnesses orchestration topology selection (AI-ORCH.1).
// Records the routing pattern chosen by an agent harness. GOVERN 1.3, Art. 9.
func (w *Witness) WitnessOrchestrationTopology(topology int, agentCount int, dependencyDepth int) WitnessPayload {
	fa := float64(topology)
	fb := float64(agentCount)
	if fb < 0 {
		fb = 0
	}
	fc := float64(dependencyDepth)
	if fc < 0 {
		fc = 0
	}
	p := w.mint("AI-ORCH.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		labels := map[int]string{0: "sequential", 1: "parallel", 2: "hierarchical", 3: "hybrid", 4: "mesh"}
		label := labels[topology]
		if label == "" {
			label = "topology-" + strconv.Itoa(topology)
		}
		p.AIModelID = "orch-topology-" + label
		p.AIContext = map[string]interface{}{
			"provider":         "harness-governance",
			"topology":         label,
			"agent_count":      agentCount,
			"dependency_depth": dependencyDepth,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessAgentHandoff witnesses inter-agent handoff (AI-ORCH.2).
// Records identity linkage with permission delta. GOVERN 1.3, Art. 9.
func (w *Witness) WitnessAgentHandoff(delegatorID string, delegateID string, permissionDelta int) WitnessPayload {
	d1Hash := Sha256Truncated(delegatorID, 16)
	d2Hash := Sha256Truncated(delegateID, 16)
	fa := hashToFactor(d1Hash)
	fb := hashToFactor(d2Hash)
	delta := permissionDelta
	if delta > 1 {
		delta = 1
	}
	if delta < -1 {
		delta = -1
	}
	fc := float64(delta)
	p := w.mint("AI-ORCH.2", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		deltaLabel := "lateral"
		if delta > 0 {
			deltaLabel = "escalation"
		} else if delta < 0 {
			deltaLabel = "restriction"
		}
		p.AIModelID = "orch-handoff-" + deltaLabel
		p.AIContext = map[string]interface{}{
			"provider":         "harness-governance",
			"delegator_hash":   d1Hash,
			"delegate_hash":    d2Hash,
			"permission_delta": delta,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessContextWindow witnesses context window management (AI-CTX.1).
// Records truncation, summarization, or eviction events. MEASURE 2.6, Art. 13.
func (w *Witness) WitnessContextWindow(tokensBefore int, tokensAfter int, evictionMethod int) WitnessPayload {
	fa := float64(tokensBefore)
	if fa < 0 {
		fa = 0
	}
	fb := float64(tokensAfter)
	if fb < 0 {
		fb = 0
	}
	fc := float64(evictionMethod)
	p := w.mint("AI-CTX.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		labels := map[int]string{0: "none", 1: "truncation", 2: "summarization", 3: "sliding_window", 4: "priority_eviction"}
		label := labels[evictionMethod]
		if label == "" {
			label = "method-" + strconv.Itoa(evictionMethod)
		}
		p.AIModelID = "ctx-window-" + label
		p.AIContext = map[string]interface{}{
			"provider":        "harness-governance",
			"tokens_before":   tokensBefore,
			"tokens_after":    tokensAfter,
			"eviction_method": label,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessSandboxEnforcement witnesses sandbox enforcement attestation (AI-SAND.1).
// Records the harness's own report of tool restriction compliance. SA-11(8), Art. 15.
func (w *Witness) WitnessSandboxEnforcement(toolsDeclared int, toolsInvoked int, violations int) WitnessPayload {
	fa := float64(toolsDeclared)
	if fa < 0 {
		fa = 0
	}
	fb := float64(toolsInvoked)
	if fb < 0 {
		fb = 0
	}
	fc := float64(violations)
	if fc < 0 {
		fc = 0
	}
	p := w.mint("AI-SAND.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		label := "clean"
		if violations > 0 {
			label = "violation"
		}
		p.AIModelID = "sandbox-" + label
		p.AIContext = map[string]interface{}{
			"provider":       "harness-governance",
			"tools_declared": toolsDeclared,
			"tools_invoked":  toolsInvoked,
			"violations":     violations,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessEvalGate witnesses eval gate decision (AI-GATE.1).
// Records pass/fail deployment gating. Auto-computes gateScore when -1. MEASURE 2.5, Art. 9(7).
func (w *Witness) WitnessEvalGate(totalEvals int, evalsPassed int, gateScore int) WitnessPayload {
	fa := float64(totalEvals)
	if fa < 0 {
		fa = 0
	}
	fb := float64(evalsPassed)
	if fb < 0 {
		fb = 0
	}
	score := gateScore
	if score < 0 {
		denom := totalEvals
		if denom == 0 {
			denom = 1
		}
		score = (evalsPassed * 100) / denom
	}
	if score > 100 {
		score = 100
	}
	fc := float64(score)
	p := w.mint("AI-GATE.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		label := "fail"
		if score >= 70 {
			label = "pass"
		}
		p.AIModelID = "eval-gate-" + label
		p.AIContext = map[string]interface{}{
			"provider":     "harness-governance",
			"total_evals":  totalEvals,
			"evals_passed": evalsPassed,
			"gate_score":   score,
		}
	}
	w.enqueue(p)
	return p
}

// ── A2A: Agent-to-Agent Governance ──────────────────────────────────

// WitnessTaskLifecycle witnesses A2A task lifecycle state (AI-A2A.1).
// Records task state transitions, latency, and delegation depth.
func (w *Witness) WitnessTaskLifecycle(stateCode int, latencyMs int, depth int) WitnessPayload {
	fa := float64(stateCode)
	fb := float64(latencyMs)
	fc := float64(depth)
	p := w.mint("AI-A2A.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		labels := map[int]string{0: "submitted", 1: "working", 2: "input-required", 3: "completed", 4: "failed", 5: "canceled"}
		label := labels[stateCode]
		if label == "" {
			label = "state-" + strconv.Itoa(stateCode)
		}
		p.AIModelID = "a2a-task-" + label
		p.AIContext = map[string]interface{}{
			"provider":   "a2a-governance",
			"state_code": stateCode,
			"latency_ms": latencyMs,
			"depth":      depth,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessAgentCardDiscovery witnesses A2A agent card discovery (AI-A2A.2).
// Records discovery method, agent count, and verified agent count.
func (w *Witness) WitnessAgentCardDiscovery(discoveryMethod int, agentsDiscovered int, verifiedCount int) WitnessPayload {
	fa := float64(discoveryMethod)
	fb := float64(agentsDiscovered)
	fc := float64(verifiedCount)
	p := w.mint("AI-A2A.2", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		labels := map[int]string{0: "manual", 1: "well-known", 2: "registry", 3: "dns-sd", 4: "broadcast"}
		label := labels[discoveryMethod]
		if label == "" {
			label = "method-" + strconv.Itoa(discoveryMethod)
		}
		p.AIModelID = "a2a-discovery-" + label
		p.AIContext = map[string]interface{}{
			"provider":          "a2a-governance",
			"discovery_method":  discoveryMethod,
			"agents_discovered": agentsDiscovered,
			"verified_count":    verifiedCount,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessContextChain witnesses A2A context chain propagation (AI-A2A.3).
// Records chain length, context identity (hashed), and agent count.
func (w *Witness) WitnessContextChain(chainLength int, contextID string, agentsInChain int) WitnessPayload {
	fa := float64(chainLength)
	ctxHash := Sha256Hex(contextID, 8)
	fb := hashToFactor(ctxHash)
	fc := float64(agentsInChain)
	p := w.mint("AI-A2A.3", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "a2a-context-chain-" + strconv.Itoa(chainLength)
		p.AIContext = map[string]interface{}{
			"provider":        "a2a-governance",
			"chain_length":    chainLength,
			"context_id_hash": ctxHash,
			"agents_in_chain": agentsInChain,
		}
	}
	w.enqueue(p)
	return p
}

// ── MCP OAuth Token Binding (AI-MCP.5) ─────────────────────────────

// WitnessOauthTokenBinding witnesses MCP OAuth token binding (AI-MCP.5).
// Records token binding events, scope count, and binding strength.
func (w *Witness) WitnessOauthTokenBinding(eventType int, scopeCount int, bindingStrength int) WitnessPayload {
	fa := float64(eventType)
	fb := float64(scopeCount)
	fc := float64(bindingStrength)
	p := w.mint("AI-MCP.5", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		labels := map[int]string{0: "issued", 1: "refreshed", 2: "revoked", 3: "expired", 4: "downscoped"}
		label := labels[eventType]
		if label == "" {
			label = "event-" + strconv.Itoa(eventType)
		}
		p.AIModelID = "mcp-oauth-" + label
		p.AIContext = map[string]interface{}{
			"provider":         "mcp-oauth-binding",
			"event_type":       eventType,
			"scope_count":      scopeCount,
			"binding_strength": bindingStrength,
		}
	}
	w.enqueue(p)
	return p
}

// WitnessGridSignal witnesses grid signal correlation (ADR-GRID.1).
func (w *Witness) WitnessGridSignal(signalType int, responseLatencyMs int, gridOperator string) WitnessPayload {
	operatorHash := Sha256Truncated(gridOperator, 16)
	fa := float64(signalType)
	fb := float64(responseLatencyMs)
	fc := hashToFactor(operatorHash)
	p := w.mint("ADR-GRID.1", fa, fb, fc)
	if w.Config.ClearingLevel <= ClearingStandard {
		p.AIModelID = "adr-grid-" + strconv.Itoa(signalType)
		p.AIContext = map[string]interface{}{
			"provider":           "adr-governance",
			"signal_type":        signalType,
			"response_latency_ms": responseLatencyMs,
			"grid_operator_hash":  operatorHash,
		}
	}
	w.enqueue(p)
	return p
}
