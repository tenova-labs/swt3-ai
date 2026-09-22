package swt3

// Version is the SDK version.
const Version = "0.7.0"

// ClearingLevel defines the data sensitivity tier for witness anchors.
type ClearingLevel int

const (
	ClearingAnalytics  ClearingLevel = 0 // Level 0: Analytics (full context)
	ClearingStandard   ClearingLevel = 1 // Level 1: Standard (operational context)
	ClearingSensitive  ClearingLevel = 2 // Level 2: Sensitive (factors only)
	ClearingClassified ClearingLevel = 3 // Level 3: Classified (fingerprint only)
)

// RevocationReason codes for AI-REV.1 anchor revocation.
type RevocationReason int

const (
	RevocationUnspecified       RevocationReason = 0
	RevocationModelRecall       RevocationReason = 1
	RevocationPolicyViolation   RevocationReason = 2
	RevocationDataContamination RevocationReason = 3
	RevocationConsentWithdrawal RevocationReason = 4
	RevocationRegulatoryOrder   RevocationReason = 5
	RevocationErrorCorrection   RevocationReason = 6
)

// WitnessPayload represents a single witness anchor payload for ingestion.
type WitnessPayload struct {
	ProcedureID          string                 `json:"procedure_id"`
	FactorA              float64                `json:"factor_a"`
	FactorB              float64                `json:"factor_b"`
	FactorC              float64                `json:"factor_c"`
	ClearingLevel        ClearingLevel          `json:"clearing_level"`
	AnchorFingerprint    string                 `json:"anchor_fingerprint"`
	AnchorEpoch          int64                  `json:"anchor_epoch"`
	FingerprintTimestamp int64                  `json:"fingerprint_timestamp_ms"`
	AIModelID            string                 `json:"ai_model_id,omitempty"`
	AgentID              string                 `json:"agent_id,omitempty"`
	PayloadSignature     string                 `json:"payload_signature,omitempty"`
	SigningAlgorithm     string                 `json:"signing_algorithm,omitempty"`
	Jurisdiction         string                 `json:"jurisdiction,omitempty"`
	LegalBasis           string                 `json:"legal_basis,omitempty"`
	PurposeClass         string                 `json:"purpose_class,omitempty"`
	AuthorizationID      string                 `json:"authorization_id,omitempty"`
	AuthorizationExpires int64                  `json:"authorization_expires,omitempty"`
	AuthorizationScope   string                 `json:"authorization_scope,omitempty"`
	AIContext            map[string]interface{} `json:"ai_context,omitempty"`
	CycleID              string                 `json:"cycle_id,omitempty"`
	LifecycleStage       int                    `json:"lifecycle_stage,omitempty"`
}

// WitnessReceipt represents the server response after ingesting a witness anchor.
type WitnessReceipt struct {
	ProcedureID     string `json:"procedure_id"`
	Verdict         string `json:"verdict"`
	SWT3Anchor      string `json:"swt3_anchor"`
	ClearingLevel   int    `json:"clearing_level"`
	WitnessedAt     string `json:"witnessed_at"`
	VerificationURL string `json:"verification_url"`
	OK              bool   `json:"ok"`
	Error           string `json:"error,omitempty"`
}

// WitnessConfig holds configuration for a Witness client.
type WitnessConfig struct {
	Endpoint      string        `json:"endpoint"`
	APIKey        string        `json:"api_key"`
	TenantID      string        `json:"tenant_id"`
	ClearingLevel ClearingLevel `json:"clearing_level"`
	BufferSize    int           `json:"buffer_size"`
	FlushInterval float64       `json:"flush_interval"` // seconds
	AgentID       string        `json:"agent_id,omitempty"`
	SigningKey    string        `json:"signing_key,omitempty"`
	Jurisdiction  string        `json:"jurisdiction,omitempty"`
	LegalBasis    string        `json:"legal_basis,omitempty"`
	PurposeClass         string        `json:"purpose_class,omitempty"`
	AuthorizationExpires int64         `json:"authorization_expires,omitempty"` // epoch ms
	AuthorizationScope   string        `json:"authorization_scope,omitempty"`
	SamplingRate         float64       `json:"sampling_rate,omitempty"` // 0.0-1.0, default 1.0
	SamplingRates map[string]float64 `json:"sampling_rates,omitempty"` // per-procedure overrides
}
