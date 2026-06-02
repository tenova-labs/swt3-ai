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
