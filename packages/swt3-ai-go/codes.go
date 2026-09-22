package swt3

// NHI credential lifecycle event codes for NHI-CYCLE.1.
const (
	NHIEventIssued    = 1
	NHIEventActivated = 2
	NHIEventSuspended = 3
	NHIEventExpired   = 4
	NHIEventRevoked   = 5
)

// NHI credential rotation reason codes for NHI-ROTATE.1.
const (
	NHIRotationScheduled  = 1
	NHIRotationCompromise = 2
	NHIRotationPolicy     = 3
	NHIRotationManual     = 4
)

// NHI credential revocation reason codes for NHI-REVOKE.1.
const (
	NHIRevocationUnspecified       = 0
	NHIRevocationModelRecall       = 1
	NHIRevocationPolicyViolation   = 2
	NHIRevocationDataContamination = 3
	NHIRevocationConsentWithdrawal = 4
	NHIRevocationRegulatoryOrder   = 5
	NHIRevocationErrorCorrection   = 6
)

// HBOM component lifecycle event codes for HBOM-LIFE.1.
const (
	HBOMEventInstalled      = 1
	HBOMEventCommissioned   = 2
	HBOMEventMaintained     = 3
	HBOMEventDegraded       = 4
	HBOMEventDecommissioned = 5
	HBOMEventRecycled       = 6
)

// HBOM water source codes for HBOM-WATER.1.
const (
	HBOMWaterMunicipal = 1
	HBOMWaterRecycled  = 2
	HBOMWaterRainwater = 3
	HBOMWaterGroundwell = 4
	HBOMWaterMixed     = 5
)

// DPP charge/discharge event codes for DPP-CHRG.1.
const (
	DPPChargeStart      = 1
	DPPChargeComplete   = 2
	DPPDischargeStart   = 3
	DPPDischargeComplete = 4
)

// DPP degradation type codes for DPP-DEGRAD.1.
const (
	DPPDegradCalendarAging = 1
	DPPDegradThermalStress = 2
	DPPDegradOvercharge    = 3
	DPPDegradDeepDischarge = 4
	DPPDegradMechanical    = 5
	DPPDegradUnknown       = 6
)

// DPP end-of-life disposition codes for DPP-EOL.1.
const (
	DPPDispositionRecycling     = 1
	DPPDispositionRepurpose     = 2
	DPPDispositionRefurbishment = 3
	DPPDispositionLandfill      = 4
	DPPDispositionHazmat        = 5
)

// ADR demand response event phase codes for ADR-EVENT.1.
const (
	ADRPhaseSignalReceived  = 1
	ADRPhaseCurtailmentStart = 2
	ADRPhaseCurtailmentEnd  = 3
	ADRPhaseRestoration     = 4
)

// ADR baseline measurement method codes for ADR-BASE.1.
const (
	ADRBaselineMetered10DayAvg = 1
	ADRBaselineRegression      = 2
	ADRBaselineRealTimeMeter   = 3
	ADRBaselineDeemedSavings   = 4
)

// ADR carbon credit type codes for ADR-CARBON.1.
const (
	ADRCreditREC               = 1
	ADRCreditCarbonOffset      = 2
	ADRCreditEAC               = 3
	ADRCreditGuaranteeOfOrigin = 4
)

// ADR grid signal type codes for ADR-GRID.1.
const (
	ADRSignalEmergency           = 1
	ADRSignalEconomic            = 2
	ADRSignalCapacity            = 3
	ADRSignalFrequencyRegulation = 4
	ADRSignalVoltageSupport      = 5
)

// Orchestration topology codes for AI-ORCH.1.
const (
	TopoSequential   = 0
	TopoParallel     = 1
	TopoHierarchical = 2
	TopoHybrid       = 3
	TopoMesh         = 4
)

// Context eviction method codes for AI-CTX.1.
const (
	EvictionNone             = 0
	EvictionTruncation       = 1
	EvictionSummarization    = 2
	EvictionSlidingWindow    = 3
	EvictionPriorityEviction = 4
)
