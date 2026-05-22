using System.Security.Cryptography;
using System.Text;

namespace Swt3Ai;

/// <summary>
/// SWT3 fingerprint minting and SHA-256 hashing utilities.
/// All methods produce output identical to the Python and TypeScript SDKs.
/// </summary>
public static class Fingerprint
{
    /// <summary>
    /// Mint an SWT3 fingerprint from the canonical formula.
    /// Returns the first 12 hex characters of SHA-256 applied to the canonical input string.
    /// </summary>
    public static string MintFingerprint(
        string tenantId,
        string procedureId,
        double factorA,
        double factorB,
        double factorC,
        long timestampMs)
    {
        var input = $"WITNESS:{tenantId}:{procedureId}:{NumStr(factorA)}:{NumStr(factorB)}:{NumStr(factorC)}:{timestampMs}";
        return Sha256Hex(input, 12);
    }

    /// <summary>
    /// Compute a truncated SHA-256 hash. Default length is 16 hex characters.
    /// Used for prompt/response hashing (16), fingerprints (12), and full digests (64).
    /// </summary>
    public static string Sha256Truncated(string data, int length = 16)
    {
        return Sha256Hex(data, length);
    }

    /// <summary>
    /// Compute SHA-256 and return the first N hex characters.
    /// </summary>
    public static string Sha256Hex(string data, int length = 64)
    {
        var bytes = Encoding.UTF8.GetBytes(data);
        var hash = SHA256.HashData(bytes);
        var hex = Convert.ToHexString(hash).ToLowerInvariant();
        return hex[..Math.Min(length, 64)];
    }

    /// <summary>
    /// Format a numeric factor as a string matching the canonical formula.
    /// Integer-valued doubles are formatted without decimals: 1.0 -> "1"
    /// </summary>
    private static string NumStr(double v)
    {
        if (double.IsFinite(v) && v == Math.Floor(v))
        {
            return ((long)v).ToString();
        }
        return v.ToString();
    }
}
