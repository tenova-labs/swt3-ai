using System.Security.Cryptography;
using System.Text;

namespace Swt3Ai;

/// <summary>
/// HMAC-SHA256 payload signing for non-repudiation.
/// </summary>
public static class Signing
{
    /// <summary>
    /// Sign a payload with HMAC-SHA256.
    /// If agentId is provided, the message is "{fingerprint}:{agentId}".
    /// Otherwise, the message is just the fingerprint.
    /// Returns a 64-character lowercase hex string.
    /// </summary>
    public static string SignPayload(
        string signingKey,
        string anchorFingerprint,
        string? agentId = null)
    {
        var message = agentId != null
            ? $"{anchorFingerprint}:{agentId}"
            : anchorFingerprint;

        var keyBytes = Encoding.UTF8.GetBytes(signingKey);
        var messageBytes = Encoding.UTF8.GetBytes(message);

        var hash = HMACSHA256.HashData(keyBytes, messageBytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
