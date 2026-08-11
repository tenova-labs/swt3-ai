import Foundation

// MARK: - Witness Payload

/// A witness payload ready for transmission to the witness endpoint.
public struct WitnessPayload: Sendable, Equatable, Codable {
    public var procedureId: String
    public var factorA: Double
    public var factorB: Double
    public var factorC: Double
    public var clearingLevel: UInt8
    public var anchorFingerprint: String
    public var anchorEpoch: Int64
    public var fingerprintTimestampMs: Int64
    public var aiModelId: String?
    public var aiPromptHash: String?
    public var aiResponseHash: String?
    public var aiLatencyMs: Int64?
    public var aiInputTokens: Int64?
    public var aiOutputTokens: Int64?
    public var agentId: String?
    public var cycleId: String?
    public var payloadSignature: String?
    public var signingAlgorithm: SigningAlgorithm?
    public var signingKeyId: String?
    public var signingKeyVersion: UInt32?
    public var policyVersionHash: String?
    public var jurisdiction: String?
    public var legalBasis: String?
    public var purposeClass: String?
    public var authorizationId: String?
    public var revocationTarget: String?
    public var revocationReason: String?

    public init(
        procedureId: String,
        factorA: Double,
        factorB: Double,
        factorC: Double,
        clearingLevel: UInt8 = 1,
        anchorFingerprint: String = "",
        anchorEpoch: Int64 = 0,
        fingerprintTimestampMs: Int64 = 0,
        aiModelId: String? = nil,
        aiPromptHash: String? = nil,
        aiResponseHash: String? = nil,
        aiLatencyMs: Int64? = nil,
        aiInputTokens: Int64? = nil,
        aiOutputTokens: Int64? = nil,
        agentId: String? = nil,
        cycleId: String? = nil,
        payloadSignature: String? = nil,
        signingAlgorithm: SigningAlgorithm? = nil,
        signingKeyId: String? = nil,
        signingKeyVersion: UInt32? = nil,
        policyVersionHash: String? = nil,
        jurisdiction: String? = nil,
        legalBasis: String? = nil,
        purposeClass: String? = nil,
        authorizationId: String? = nil,
        revocationTarget: String? = nil,
        revocationReason: String? = nil
    ) {
        self.procedureId = procedureId
        self.factorA = factorA
        self.factorB = factorB
        self.factorC = factorC
        self.clearingLevel = clearingLevel
        self.anchorFingerprint = anchorFingerprint
        self.anchorEpoch = anchorEpoch
        self.fingerprintTimestampMs = fingerprintTimestampMs
        self.aiModelId = aiModelId
        self.aiPromptHash = aiPromptHash
        self.aiResponseHash = aiResponseHash
        self.aiLatencyMs = aiLatencyMs
        self.aiInputTokens = aiInputTokens
        self.aiOutputTokens = aiOutputTokens
        self.agentId = agentId
        self.cycleId = cycleId
        self.payloadSignature = payloadSignature
        self.signingAlgorithm = signingAlgorithm
        self.signingKeyId = signingKeyId
        self.signingKeyVersion = signingKeyVersion
        self.policyVersionHash = policyVersionHash
        self.jurisdiction = jurisdiction
        self.legalBasis = legalBasis
        self.purposeClass = purposeClass
        self.authorizationId = authorizationId
        self.revocationTarget = revocationTarget
        self.revocationReason = revocationReason
    }

    enum CodingKeys: String, CodingKey {
        case procedureId = "procedure_id"
        case factorA = "factor_a"
        case factorB = "factor_b"
        case factorC = "factor_c"
        case clearingLevel = "clearing_level"
        case anchorFingerprint = "anchor_fingerprint"
        case anchorEpoch = "anchor_epoch"
        case fingerprintTimestampMs = "fingerprint_timestamp_ms"
        case aiModelId = "ai_model_id"
        case aiPromptHash = "ai_prompt_hash"
        case aiResponseHash = "ai_response_hash"
        case aiLatencyMs = "ai_latency_ms"
        case aiInputTokens = "ai_input_tokens"
        case aiOutputTokens = "ai_output_tokens"
        case agentId = "agent_id"
        case cycleId = "cycle_id"
        case payloadSignature = "payload_signature"
        case signingAlgorithm = "signing_algorithm"
        case signingKeyId = "signing_key_id"
        case signingKeyVersion = "signing_key_version"
        case policyVersionHash = "policy_version_hash"
        case jurisdiction
        case legalBasis = "legal_basis"
        case purposeClass = "purpose_class"
        case authorizationId = "authorization_id"
        case revocationTarget = "revocation_target"
        case revocationReason = "revocation_reason"
    }
}

// MARK: - Witness Receipt

/// A receipt returned by the witness endpoint after successful anchoring.
public struct WitnessReceipt: Sendable, Equatable, Codable {
    public var procedureId: String
    public var verdict: String
    public var swt3Anchor: String
    public var clearingLevel: UInt8
    public var witnessedAt: String
    public var verificationUrl: String
    public var ok: Bool
    public var error: String?

    public init(
        procedureId: String,
        verdict: String,
        swt3Anchor: String,
        clearingLevel: UInt8,
        witnessedAt: String,
        verificationUrl: String,
        ok: Bool,
        error: String? = nil
    ) {
        self.procedureId = procedureId
        self.verdict = verdict
        self.swt3Anchor = swt3Anchor
        self.clearingLevel = clearingLevel
        self.witnessedAt = witnessedAt
        self.verificationUrl = verificationUrl
        self.ok = ok
        self.error = error
    }

    enum CodingKeys: String, CodingKey {
        case procedureId = "procedure_id"
        case verdict
        case swt3Anchor = "swt3_anchor"
        case clearingLevel = "clearing_level"
        case witnessedAt = "witnessed_at"
        case verificationUrl = "verification_url"
        case ok
        case error
    }
}

// MARK: - Witness Config

/// Configuration for a Witness client.
public struct WitnessConfig: Sendable, Equatable, Codable {
    public var endpoint: String
    public var apiKey: String
    public var tenantId: String
    public var clearingLevel: UInt8
    public var bufferSize: Int
    public var flushIntervalSeconds: Double
    public var timeoutMs: UInt64
    public var maxRetries: UInt32
    public var agentId: String?
    public var signingKey: String?
    public var signingAlgorithm: SigningAlgorithm?
    public var signingKeyId: String?
    public var signingKeyVersion: UInt32?
    public var cycleId: String?
    public var policyVersion: String?
    public var jurisdiction: String?
    public var legalBasis: String?
    public var purposeClass: String?

    public init(
        endpoint: String,
        apiKey: String,
        tenantId: String,
        clearingLevel: UInt8 = 1,
        bufferSize: Int = 10,
        flushIntervalSeconds: Double = 5.0,
        timeoutMs: UInt64 = 10000,
        maxRetries: UInt32 = 3,
        agentId: String? = nil,
        signingKey: String? = nil,
        signingAlgorithm: SigningAlgorithm? = nil,
        signingKeyId: String? = nil,
        signingKeyVersion: UInt32? = nil,
        cycleId: String? = nil,
        policyVersion: String? = nil,
        jurisdiction: String? = nil,
        legalBasis: String? = nil,
        purposeClass: String? = nil
    ) {
        self.endpoint = endpoint
        self.apiKey = apiKey
        self.tenantId = tenantId
        self.clearingLevel = clearingLevel
        self.bufferSize = bufferSize
        self.flushIntervalSeconds = flushIntervalSeconds
        self.timeoutMs = timeoutMs
        self.maxRetries = maxRetries
        self.agentId = agentId
        self.signingKey = signingKey
        self.signingAlgorithm = signingAlgorithm
        self.signingKeyId = signingKeyId
        self.signingKeyVersion = signingKeyVersion
        self.cycleId = cycleId
        self.policyVersion = policyVersion
        self.jurisdiction = jurisdiction
        self.legalBasis = legalBasis
        self.purposeClass = purposeClass
    }

    enum CodingKeys: String, CodingKey {
        case endpoint
        case apiKey = "api_key"
        case tenantId = "tenant_id"
        case clearingLevel = "clearing_level"
        case bufferSize = "buffer_size"
        case flushIntervalSeconds = "flush_interval_seconds"
        case timeoutMs = "timeout_ms"
        case maxRetries = "max_retries"
        case agentId = "agent_id"
        case signingKey = "signing_key"
        case signingAlgorithm = "signing_algorithm"
        case signingKeyId = "signing_key_id"
        case signingKeyVersion = "signing_key_version"
        case cycleId = "cycle_id"
        case policyVersion = "policy_version"
        case jurisdiction
        case legalBasis = "legal_basis"
        case purposeClass = "purpose_class"
    }
}

// MARK: - Enums

/// Signing algorithm for payload signatures.
public enum SigningAlgorithm: String, Sendable, Codable, CaseIterable {
    case hmacSha256 = "hmac-sha256"
    case mlDsa65 = "ml-dsa-65"
    case ecdsaP256 = "ecdsa-p256"
}

/// Revocation reason codes for AI-REV.1 anchors.
public enum RevocationReason: Int, Sendable, Codable, CaseIterable {
    case unspecified = 0
    case modelRecall = 1
    case policyViolation = 2
    case dataContamination = 3
    case consentWithdrawal = 4
    case regulatoryOrder = 5
    case errorCorrection = 6

    /// String label for the revocation reason.
    public var label: String {
        switch self {
        case .unspecified: return "unspecified"
        case .modelRecall: return "model_recall"
        case .policyViolation: return "policy_violation"
        case .dataContamination: return "data_contamination"
        case .consentWithdrawal: return "consent_withdrawal"
        case .regulatoryOrder: return "regulatory_order"
        case .errorCorrection: return "error_correction"
        }
    }
}

/// Trust levels for agent-to-agent Trust Mesh verification (AI-TRUST.1).
public enum TrustLevel: Int, Sendable, Codable, CaseIterable {
    case denied = 0
    case basic = 1
    case verified = 2
    case attested = 3
    case sovereign = 4
}

/// Denial reason codes for Trust Mesh verification.
public enum DenialReason: String, Sendable, Codable, CaseIterable {
    case anchorNotFound = "anchor_not_found"
    case anchorExpired = "anchor_expired"
    case anchorRevoked = "anchor_revoked"
    case signatureMissing = "signature_missing"
    case tenantNotTrusted = "tenant_not_trusted"
    case denyListed = "deny_listed"
    case insufficientProcedures = "insufficient_procedures"
    case signatureInvalid = "signature_invalid"
    case signatureUnverifiable = "signature_unverifiable"
    case insufficientTrustLevel = "insufficient_trust_level"
    case timestampFuture = "timestamp_future"
    case rateLimited = "rate_limited"
}

/// Key purpose for key attestation (AI-TRUST.3).
public enum KeyPurpose: String, Sendable, Codable, CaseIterable {
    case signing = "signing"
    case encryption = "encryption"
    case delegation = "delegation"
}

// MARK: - Governance Gate Types

/// A single gate procedure entry in a .swt3-gate.yml configuration.
public struct GateProcedure: Sendable, Equatable, Codable {
    public var procedure: String
    public var required: Bool
    public var maxAge: String?
    public var maxAgeSeconds: Int?
    public var ref: String?
    public var critical: Bool
    public var description: String?
    public var hint: String?
    public var mustNotExist: Bool

    public init(
        procedure: String,
        required: Bool = false,
        maxAge: String? = nil,
        maxAgeSeconds: Int? = nil,
        ref: String? = nil,
        critical: Bool = false,
        description: String? = nil,
        hint: String? = nil,
        mustNotExist: Bool = false
    ) {
        self.procedure = procedure
        self.required = required
        self.maxAge = maxAge
        self.maxAgeSeconds = maxAgeSeconds
        self.ref = ref
        self.critical = critical
        self.description = description
        self.hint = hint
        self.mustNotExist = mustNotExist
    }

    enum CodingKeys: String, CodingKey {
        case procedure, required, ref, critical, description, hint
        case maxAge = "max_age"
        case maxAgeSeconds = "max_age_seconds"
        case mustNotExist = "must_not_exist"
    }
}

/// A named group of gate procedures (e.g., "Article 9: Risk Management").
public struct GateGroup: Sendable, Equatable, Codable {
    public var group: String
    public var procedures: [GateProcedure]

    public init(group: String, procedures: [GateProcedure]) {
        self.group = group
        self.procedures = procedures
    }
}

/// Framework-specific gate configuration with risk class and grouped procedures.
public struct FrameworkGate: Sendable, Equatable, Codable {
    public var riskClass: String?
    public var crosswalkHash: String?
    public var gates: [GateGroup]

    public init(riskClass: String? = nil, crosswalkHash: String? = nil, gates: [GateGroup] = []) {
        self.riskClass = riskClass
        self.crosswalkHash = crosswalkHash
        self.gates = gates
    }

    enum CodingKeys: String, CodingKey {
        case gates
        case riskClass = "risk_class"
        case crosswalkHash = "crosswalk_hash"
    }
}

/// Parsed .swt3-gate.yml configuration. Spec version 1.0 (locked July 24, 2026).
public struct GateConfig: Sendable, Equatable, Codable {
    public var version: String
    public var name: String?
    public var strict: Bool
    public var models: [String: GateModel]
    public var defaults: GateDefaults?
    public var frameworks: [String: FrameworkGate]
    public var warnings: [String]

    public init(
        version: String,
        name: String? = nil,
        strict: Bool = false,
        models: [String: GateModel] = [:],
        defaults: GateDefaults? = nil,
        frameworks: [String: FrameworkGate] = [:],
        warnings: [String] = []
    ) {
        self.version = version
        self.name = name
        self.strict = strict
        self.models = models
        self.defaults = defaults
        self.frameworks = frameworks
        self.warnings = warnings
    }
}

/// Model risk assignment in a gate config.
public struct GateModel: Sendable, Equatable, Codable {
    public var risk: String?

    public init(risk: String? = nil) {
        self.risk = risk
    }
}

/// Default gates applied to all models.
public struct GateDefaults: Sendable, Equatable, Codable {
    public var gates: [GateProcedure]

    public init(gates: [GateProcedure] = []) {
        self.gates = gates
    }
}

// MARK: - Delegation Tree Types

/// Delegation tree grant for AI-DEL.1 witnessing.
public struct DelegationTree: Sendable, Equatable, Codable {
    public var delegatorId: String
    public var scope: String
    public var delegationDepth: Int
    public var delegates: [String]?
    public var treeHash: String?
    public var cascadeRevocation: Bool
    public var timeBoundMinutes: Int?
    public var parentGrantFingerprint: String?

    public init(
        delegatorId: String,
        scope: String,
        delegationDepth: Int = 0,
        delegates: [String]? = nil,
        treeHash: String? = nil,
        cascadeRevocation: Bool = false,
        timeBoundMinutes: Int? = nil,
        parentGrantFingerprint: String? = nil
    ) {
        self.delegatorId = delegatorId
        self.scope = scope
        self.delegationDepth = delegationDepth
        self.delegates = delegates
        self.treeHash = treeHash
        self.cascadeRevocation = cascadeRevocation
        self.timeBoundMinutes = timeBoundMinutes
        self.parentGrantFingerprint = parentGrantFingerprint
    }

    enum CodingKeys: String, CodingKey {
        case scope, delegates
        case delegatorId = "delegator_id"
        case delegationDepth = "delegation_depth"
        case treeHash = "tree_hash"
        case cascadeRevocation = "cascade_revocation"
        case timeBoundMinutes = "time_bound_minutes"
        case parentGrantFingerprint = "parent_grant_fingerprint"
    }
}

// MARK: - Resource Consumption Types

/// Resource consumption data for AI-COST.1 witnessing.
public struct ResourceConsumption: Sendable, Equatable, Codable {
    public var tokensIn: Int64
    public var tokensOut: Int64
    public var apiCalls: Int64
    public var costCents: Int64
    public var provider: String?
    public var modelId: String?
    public var computeSeconds: Double?
    public var costTableVersion: String?

    public init(
        tokensIn: Int64,
        tokensOut: Int64,
        apiCalls: Int64,
        costCents: Int64 = -1,
        provider: String? = nil,
        modelId: String? = nil,
        computeSeconds: Double? = nil,
        costTableVersion: String? = nil
    ) {
        self.tokensIn = tokensIn
        self.tokensOut = tokensOut
        self.apiCalls = apiCalls
        self.costCents = costCents
        self.provider = provider
        self.modelId = modelId
        self.computeSeconds = computeSeconds
        self.costTableVersion = costTableVersion
    }

    enum CodingKeys: String, CodingKey {
        case provider
        case tokensIn = "tokens_in"
        case tokensOut = "tokens_out"
        case apiCalls = "api_calls"
        case costCents = "cost_cents"
        case modelId = "model_id"
        case computeSeconds = "compute_seconds"
        case costTableVersion = "cost_table_version"
    }
}

// MARK: - Deployment Context

/// Deployment environment context for witness payloads.
public struct DeploymentContext: Sendable, Equatable, Codable {
    public var deviceModel: String?
    public var osVersion: String?
    public var chipType: String?
    public var runtimeVersion: String?
    public var containerImage: String?

    public init(
        deviceModel: String? = nil,
        osVersion: String? = nil,
        chipType: String? = nil,
        runtimeVersion: String? = nil,
        containerImage: String? = nil
    ) {
        self.deviceModel = deviceModel
        self.osVersion = osVersion
        self.chipType = chipType
        self.runtimeVersion = runtimeVersion
        self.containerImage = containerImage
    }

    enum CodingKeys: String, CodingKey {
        case deviceModel = "device_model"
        case osVersion = "os_version"
        case chipType = "chip_type"
        case runtimeVersion = "runtime_version"
        case containerImage = "container_image"
    }
}

// MARK: - Constants (namespaced under SWT3)

extension SWT3 {
    /// AI model lifecycle stages (NIST AI RMF MAP 1.3).
    public static let lifecycleStages: [String] = [
        "design", "development", "testing", "deployment", "monitoring", "decommission",
    ]

    /// METAGOV governance domain scope codes (AI-METAGOV.5).
    public static let metagovScopes: [String] = [
        "verdict_rules", "trust_mesh", "enforcement", "clearing", "full",
    ]

    /// METAGOV permission level codes (AI-METAGOV.5).
    public static let metagovPermissions: [String] = ["read", "modify", "approve"]

    /// METAGOV emergency override reason codes (AI-METAGOV.6).
    public static let metagovOverrideReasons: [String] = [
        "unspecified", "incident_response", "regulatory_deadline", "system_failure", "security_breach",
    ]

    /// METAGOV review status codes (AI-METAGOV.6).
    public static let metagovReviewStatuses: [String] = ["unreviewed", "attested", "revoked"]

    /// METAGOV governance divergence codes (AI-METAGOV.7).
    public static let metagovDivergenceTypes: [String] = [
        "equivalent", "version_divergent", "structural_divergent", "coverage_divergent",
    ]

    /// METAGOV attestation purity tiers (AI-METAGOV.8).
    public static let metagovPurityTiers: [String] = ["verified_pure", "unverified_purity", "impure"]

    /// GDPR lawful basis codes (AI-CONSENT.1).
    public static let consentBasisCodes: [String: Int] = [
        "consent": 0, "contract": 1, "legal_obligation": 2,
        "vital_interest": 3, "public_task": 4, "legitimate_interest": 5,
    ]

    /// Incident severity codes (AI-INCIDENT.1).
    public static let incidentSeverityCodes: [String: Int] = [
        "low": 1, "medium": 2, "high": 3, "critical": 4,
    ]

    /// Incident type codes (AI-INCIDENT.1).
    public static let incidentTypeCodes: [String: Int] = [
        "safety": 0, "rights": 1, "security": 2,
        "performance": 3, "bias": 4, "other": 5,
    ]

    /// Output filter action codes (AI-GRD.2).
    public static let filterActionCodes: [String: Int] = [
        "allowed": 0, "flagged": 1, "redacted": 2, "blocked": 3,
    ]
}

// MARK: - Consent Attestation Types

/// Data subject consent attestation for AI-CONSENT.1 witnessing.
public struct ConsentAttestation: Sendable, Equatable, Codable {
    public var subjectsCovered: Int
    public var legalBasisCode: Int
    public var withdrawalAvailable: Bool
    public var jurisdiction: String?
    public var purpose: String?
    public var consentMechanism: String?

    public init(
        subjectsCovered: Int = 1,
        legalBasisCode: Int = 0,
        withdrawalAvailable: Bool = true,
        jurisdiction: String? = nil,
        purpose: String? = nil,
        consentMechanism: String? = nil
    ) {
        self.subjectsCovered = subjectsCovered
        self.legalBasisCode = legalBasisCode
        self.withdrawalAvailable = withdrawalAvailable
        self.jurisdiction = jurisdiction
        self.purpose = purpose
        self.consentMechanism = consentMechanism
    }

    enum CodingKeys: String, CodingKey {
        case jurisdiction, purpose
        case subjectsCovered = "subjects_covered"
        case legalBasisCode = "legal_basis_code"
        case withdrawalAvailable = "withdrawal_available"
        case consentMechanism = "consent_mechanism"
    }
}

// MARK: - Output Filter Result Types

/// Output content safety classification result for AI-GRD.2 witnessing.
public struct OutputFilterResult: Sendable, Equatable, Codable {
    public var passed: Bool
    public var filterType: String
    public var confidence: Double?
    public var actionTaken: String
    public var outputHash: String?

    public init(
        passed: Bool,
        filterType: String = "content-safety",
        confidence: Double? = nil,
        actionTaken: String = "allowed",
        outputHash: String? = nil
    ) {
        self.passed = passed
        self.filterType = filterType
        self.confidence = confidence
        self.actionTaken = actionTaken
        self.outputHash = outputHash
    }

    enum CodingKeys: String, CodingKey {
        case passed, confidence
        case filterType = "filter_type"
        case actionTaken = "action_taken"
        case outputHash = "output_hash"
    }
}

// MARK: - Incident Report Types

/// Incident report for AI-INCIDENT.1 witnessing.
public struct IncidentReport: Sendable, Equatable, Codable {
    public var severityCode: Int
    public var incidentTypeCode: Int
    public var authorityNotified: Bool
    public var descriptionHash: String?
    public var detectionMethod: String?
    public var reportingDeadlineHours: Int?
    public var incidentId: String?

    public init(
        severityCode: Int = 2,
        incidentTypeCode: Int = 5,
        authorityNotified: Bool = false,
        descriptionHash: String? = nil,
        detectionMethod: String? = nil,
        reportingDeadlineHours: Int? = nil,
        incidentId: String? = nil
    ) {
        self.severityCode = severityCode
        self.incidentTypeCode = incidentTypeCode
        self.authorityNotified = authorityNotified
        self.descriptionHash = descriptionHash
        self.detectionMethod = detectionMethod
        self.reportingDeadlineHours = reportingDeadlineHours
        self.incidentId = incidentId
    }

    enum CodingKeys: String, CodingKey {
        case severityCode = "severity_code"
        case incidentTypeCode = "incident_type_code"
        case authorityNotified = "authority_notified"
        case descriptionHash = "description_hash"
        case detectionMethod = "detection_method"
        case reportingDeadlineHours = "reporting_deadline_hours"
        case incidentId = "incident_id"
    }
}

// MARK: - Data Provenance Attestation Types

/// Training data governance attestation for AI-DATA.1 witnessing.
/// Attests diligence without disclosing training data contents.
public struct DataProvenanceAttestation: Sendable, Equatable, Codable {
    public var governanceReviewed: Bool
    public var documentationHash: String?
    public var licenseVerified: Bool
    public var demographicFeaturesExcluded: Bool
    public var dataSourcesCount: Int?

    public init(
        governanceReviewed: Bool = true,
        documentationHash: String? = nil,
        licenseVerified: Bool = false,
        demographicFeaturesExcluded: Bool = false,
        dataSourcesCount: Int? = nil
    ) {
        self.governanceReviewed = governanceReviewed
        self.documentationHash = documentationHash
        self.licenseVerified = licenseVerified
        self.demographicFeaturesExcluded = demographicFeaturesExcluded
        self.dataSourcesCount = dataSourcesCount
    }

    enum CodingKeys: String, CodingKey {
        case governanceReviewed = "governance_reviewed"
        case documentationHash = "documentation_hash"
        case licenseVerified = "license_verified"
        case demographicFeaturesExcluded = "demographic_features_excluded"
        case dataSourcesCount = "data_sources_count"
    }
}

// MARK: - Trajectory Decision Types

/// Safety classification codes for AI-MOB.6 trajectory decision attestation.
public enum SafetyClassification: Int, Codable, Sendable, CaseIterable {
    case reserved = 0
    case nominal = 1
    case cautionary = 2
    case degraded = 3
    case emergency = 4
    case abort = 5
}

/// Trajectory decision attestation for AI-MOB.6 witnessing.
/// Records safety-critical path planning decisions from VLA or autonomous
/// planning models. Model-agnostic.
public struct TrajectoryAttestation: Sendable, Equatable, Codable {
    public var safetyValidated: Bool
    public var waypointCount: Int?
    public var trajectoryHash: String?
    public var cocTraceHash: String?
    public var cocNodeCount: Int?
    public var actionClass: String?
    public var safetyClassification: SafetyClassification
    public var sensorSources: [String]?

    public init(
        safetyValidated: Bool,
        waypointCount: Int? = nil,
        trajectoryHash: String? = nil,
        cocTraceHash: String? = nil,
        cocNodeCount: Int? = nil,
        actionClass: String? = nil,
        safetyClassification: SafetyClassification = .nominal,
        sensorSources: [String]? = nil
    ) {
        self.safetyValidated = safetyValidated
        self.waypointCount = waypointCount
        self.trajectoryHash = trajectoryHash
        self.cocTraceHash = cocTraceHash
        self.cocNodeCount = cocNodeCount
        self.actionClass = actionClass
        self.safetyClassification = safetyClassification
        self.sensorSources = sensorSources
    }

    enum CodingKeys: String, CodingKey {
        case safetyValidated = "safety_validated"
        case waypointCount = "waypoint_count"
        case trajectoryHash = "trajectory_hash"
        case cocTraceHash = "coc_trace_hash"
        case cocNodeCount = "coc_node_count"
        case actionClass = "action_class"
        case safetyClassification = "safety_classification"
        case sensorSources = "sensor_sources"
    }
}

/// VLA inference result for AI-MOB.7 witnessing.
/// Captures timing and success/failure of VLA model inference calls.
public struct VlaInferenceResult: Sendable, Equatable, Codable {
    public var modelId: String
    public var latencyMs: Int
    public var succeeded: Bool
    public var inputFrameHashes: [String]?

    public init(
        modelId: String,
        latencyMs: Int,
        succeeded: Bool = true,
        inputFrameHashes: [String]? = nil
    ) {
        self.modelId = modelId
        self.latencyMs = latencyMs
        self.succeeded = succeeded
        self.inputFrameHashes = inputFrameHashes
    }

    enum CodingKeys: String, CodingKey {
        case modelId = "model_id"
        case latencyMs = "latency_ms"
        case succeeded
        case inputFrameHashes = "input_frame_hashes"
    }
}
