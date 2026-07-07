namespace Swt3Ai;

/// <summary>
/// A witness payload ready for transmission to the witness endpoint.
/// </summary>
public class WitnessPayload
{
    public string ProcedureId { get; set; } = "";
    public double FactorA { get; set; }
    public double FactorB { get; set; }
    public double FactorC { get; set; }
    public int ClearingLevel { get; set; }
    public string AnchorFingerprint { get; set; } = "";
    public long AnchorEpoch { get; set; }
    public long FingerprintTimestampMs { get; set; }
    public string? AiModelId { get; set; }
    public string? AiPromptHash { get; set; }
    public string? AiResponseHash { get; set; }
    public long? AiLatencyMs { get; set; }
    public long? AiInputTokens { get; set; }
    public long? AiOutputTokens { get; set; }
    public string? AgentId { get; set; }
    public string? CycleId { get; set; }
    public string? PayloadSignature { get; set; }
    public string? SigningAlgorithm { get; set; }
    public string? SigningKeyId { get; set; }
    public int? SigningKeyVersion { get; set; }
    public string? PolicyVersionHash { get; set; }
    public string? Jurisdiction { get; set; }
    public string? LegalBasis { get; set; }
    public string? PurposeClass { get; set; }
    public string? AuthorizationId { get; set; }
    public string? RevocationTarget { get; set; }
    public string? RevocationReason { get; set; }
}

/// <summary>
/// A receipt returned by the witness endpoint after successful anchoring.
/// </summary>
public class WitnessReceipt
{
    public string ProcedureId { get; set; } = "";
    public string Verdict { get; set; } = "";
    public string Swt3Anchor { get; set; } = "";
    public int ClearingLevel { get; set; }
    public string WitnessedAt { get; set; } = "";
    public string VerificationUrl { get; set; } = "";
    public bool Ok { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// Configuration for a Witness client.
/// </summary>
public class WitnessConfig
{
    public string Endpoint { get; set; } = "";
    public string ApiKey { get; set; } = "";
    public string TenantId { get; set; } = "";
    public int ClearingLevel { get; set; } = 1;
    public int BufferSize { get; set; } = 10;
    public double FlushIntervalSeconds { get; set; } = 5.0;
    public int TimeoutMs { get; set; } = 10000;
    public int MaxRetries { get; set; } = 3;
    public string? AgentId { get; set; }
    public string? SigningKey { get; set; }
    public string? SigningAlgorithm { get; set; }
    public string? SigningKeyId { get; set; }
    public int? SigningKeyVersion { get; set; }
    public string? CycleId { get; set; }
    public string? PolicyVersion { get; set; }
    public string? Jurisdiction { get; set; }
    public string? LegalBasis { get; set; }
    public string? PurposeClass { get; set; }
}

/// <summary>
/// Revocation reason codes for AI-REV.1 anchors.
/// </summary>
public static class RevocationReasons
{
    public const int Unspecified = 0;
    public const int ModelRecall = 1;
    public const int PolicyViolation = 2;
    public const int DataContamination = 3;
    public const int ConsentWithdrawal = 4;
    public const int RegulatoryOrder = 5;
    public const int ErrorCorrection = 6;
}

/// <summary>
/// Trust levels for agent-to-agent Trust Mesh verification (AI-TRUST.1).
/// </summary>
public static class TrustLevels
{
    public const int Denied = 0;
    public const int Basic = 1;
    public const int Verified = 2;
    public const int Attested = 3;
    public const int Sovereign = 4;
}

/// <summary>
/// Denial reason codes for Trust Mesh verification.
/// </summary>
public static class DenialReasons
{
    public const string AnchorNotFound = "anchor_not_found";
    public const string AnchorExpired = "anchor_expired";
    public const string AnchorRevoked = "anchor_revoked";
    public const string SignatureMissing = "signature_missing";
    public const string TenantNotTrusted = "tenant_not_trusted";
    public const string DenyListed = "deny_listed";
    public const string InsufficientProcedures = "insufficient_procedures";
    public const string SignatureInvalid = "signature_invalid";
    public const string SignatureUnverifiable = "signature_unverifiable";
    public const string InsufficientTrustLevel = "insufficient_trust_level";
    public const string TimestampFuture = "timestamp_future";
    public const string RateLimited = "rate_limited";
}

/// <summary>
/// Key purpose for key attestation (AI-TRUST.3).
/// </summary>
public static class KeyPurposes
{
    public const string Signing = "signing";
    public const string Encryption = "encryption";
    public const string Delegation = "delegation";
}

/// <summary>
/// AI model lifecycle stages (NIST AI RMF MAP 1.3).
/// </summary>
public static class LifecycleStages
{
    public const string Design = "design";
    public const string Development = "development";
    public const string Testing = "testing";
    public const string Deployment = "deployment";
    public const string Monitoring = "monitoring";
    public const string Decommission = "decommission";
}

/// <summary>
/// METAGOV governance domain scope codes (AI-METAGOV.5).
/// </summary>
public static class MetagovScopes
{
    public const string VerdictRules = "verdict_rules";
    public const string TrustMesh = "trust_mesh";
    public const string Enforcement = "enforcement";
    public const string Clearing = "clearing";
    public const string Full = "full";
}

/// <summary>
/// METAGOV permission level codes (AI-METAGOV.5).
/// </summary>
public static class MetagovPermissions
{
    public const string Read = "read";
    public const string Modify = "modify";
    public const string Approve = "approve";
}

/// <summary>
/// METAGOV emergency override reason codes (AI-METAGOV.6).
/// </summary>
public static class MetagovOverrideReasons
{
    public const string Unspecified = "unspecified";
    public const string IncidentResponse = "incident_response";
    public const string RegulatoryDeadline = "regulatory_deadline";
    public const string SystemFailure = "system_failure";
    public const string SecurityBreach = "security_breach";
}

/// <summary>
/// METAGOV review status codes (AI-METAGOV.6).
/// </summary>
public static class MetagovReviewStatuses
{
    public const string Unreviewed = "unreviewed";
    public const string Attested = "attested";
    public const string Revoked = "revoked";
}

/// <summary>
/// METAGOV governance divergence codes (AI-METAGOV.7).
/// </summary>
public static class MetagovDivergenceTypes
{
    public const string Equivalent = "equivalent";
    public const string VersionDivergent = "version_divergent";
    public const string StructuralDivergent = "structural_divergent";
    public const string CoverageDivergent = "coverage_divergent";
}

/// <summary>
/// METAGOV attestation purity tiers (AI-METAGOV.8).
/// </summary>
public static class MetagovPurityTiers
{
    public const string VerifiedPure = "verified_pure";
    public const string UnverifiedPurity = "unverified_purity";
    public const string Impure = "impure";
}