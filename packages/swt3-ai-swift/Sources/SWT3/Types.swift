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
}
