#if canImport(simd) && (os(iOS) || os(macOS) || os(visionOS))
import simd
import Foundation

extension SWT3 {

    /// Witness an AI decision with spatial context.
    ///
    /// Captures the 4x4 world transform matrix and hashes it into the
    /// witness payload. For AI systems making decisions in physical space
    /// (navigation, object recognition, spatial reasoning), this proves
    /// WHERE the decision was made, not just WHAT was decided.
    ///
    /// The transform matrix is typically obtained from ARKit, RealityKit,
    /// or any spatial framework that provides world-space coordinates.
    /// This function does not access sensors, cameras, or AR sessions.
    ///
    /// - Parameters:
    ///   - procedure: UCT procedure ID (e.g. "AI-INF.1")
    ///   - factorA: Numeric factor A
    ///   - factorB: Numeric factor B
    ///   - factorC: Numeric factor C
    ///   - worldTransform: The 4x4 world transform matrix
    ///   - tenant: Tenant identifier
    ///   - clearingLevel: Clearing level (0=Analytics, 1=Standard, 2=Sensitive, 3=Classified)
    ///   - agentId: Optional agent identity
    /// - Returns: A populated `WitnessPayload` with spatial context in the prompt hash
    public static func witnessSpatialInference(
        procedure: String,
        factorA: Double,
        factorB: Double,
        factorC: Double,
        worldTransform: simd_float4x4,
        tenant: String,
        clearingLevel: UInt8 = 1,
        agentId: String? = nil
    ) -> WitnessPayload {
        let ts = timestampMs()

        let spatialHash = hashTransform(worldTransform)

        let fp = mintFingerprint(
            tenant: tenant,
            procedure: procedure,
            factorA: factorA,
            factorB: factorB,
            factorC: factorC,
            timestampMs: ts.ms
        )

        return WitnessPayload(
            procedureId: procedure,
            factorA: factorA,
            factorB: factorB,
            factorC: factorC,
            clearingLevel: clearingLevel,
            anchorFingerprint: fp,
            anchorEpoch: ts.epoch,
            fingerprintTimestampMs: ts.ms,
            aiPromptHash: spatialHash,
            agentId: agentId
        )
    }

    /// Hash a 4x4 transform matrix into a stable 16-character hex digest.
    ///
    /// The matrix is serialized column-major (matching simd memory layout)
    /// with 6 decimal places of precision per element.
    private static func hashTransform(_ transform: simd_float4x4) -> String {
        let columns = [transform.columns.0, transform.columns.1,
                       transform.columns.2, transform.columns.3]
        let serialized = columns.flatMap { col in
            [col.x, col.y, col.z, col.w].map { String(format: "%.6f", $0) }
        }.joined(separator: ",")
        return sha256Truncated(serialized)
    }
}
#endif
