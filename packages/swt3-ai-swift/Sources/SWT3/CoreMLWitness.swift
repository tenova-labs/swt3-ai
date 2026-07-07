#if canImport(CoreML)
import CoreML
import Foundation

extension SWT3 {

    /// Witness a Core ML prediction (AI-INF.1).
    ///
    /// Extracts model metadata, hashes input/output feature descriptions,
    /// computes latency, and mints a fingerprint using the canonical formula.
    /// Raw inference data never leaves the device.
    ///
    /// - Parameters:
    ///   - model: The Core ML model that produced the prediction
    ///   - input: The input feature provider passed to the model
    ///   - output: The output feature provider returned by the model
    ///   - latencyMs: Inference latency in milliseconds
    ///   - tenant: Tenant identifier
    ///   - clearingLevel: Clearing level (0=Analytics, 1=Standard, 2=Sensitive, 3=Classified)
    ///   - agentId: Optional agent identity
    /// - Returns: A populated `WitnessPayload` with fingerprint and metadata
    public static func witnessPrediction(
        model: MLModel,
        input: MLFeatureProvider,
        output: MLFeatureProvider,
        latencyMs: Int64,
        tenant: String,
        clearingLevel: UInt8 = 1,
        agentId: String? = nil
    ) -> WitnessPayload {
        let ts = timestampMs()

        let modelId = extractModelId(from: model)
        let inputHash = hashFeatureProvider(input)
        let outputHash = hashFeatureProvider(output)

        let fp = mintFingerprint(
            tenant: tenant,
            procedure: "AI-INF.1",
            factorA: 1,
            factorB: Double(latencyMs),
            factorC: 0,
            timestampMs: ts.ms
        )

        return WitnessPayload(
            procedureId: "AI-INF.1",
            factorA: 1,
            factorB: Double(latencyMs),
            factorC: 0,
            clearingLevel: clearingLevel,
            anchorFingerprint: fp,
            anchorEpoch: ts.epoch,
            fingerprintTimestampMs: ts.ms,
            aiModelId: clearingLevel < 3 ? modelId : sha256Truncated(modelId),
            aiPromptHash: inputHash,
            aiResponseHash: outputHash,
            aiLatencyMs: latencyMs,
            agentId: agentId
        )
    }

    /// Witness Core ML model integrity (AI-MDL.1).
    ///
    /// Hashes the compiled .mlmodelc bundle and records the model
    /// description hash for integrity verification.
    ///
    /// - Parameters:
    ///   - model: The loaded Core ML model
    ///   - bundleURL: URL to the .mlmodelc compiled model bundle
    ///   - tenant: Tenant identifier
    ///   - clearingLevel: Clearing level
    /// - Returns: A populated `WitnessPayload` for AI-MDL.1
    public static func witnessModelIntegrity(
        model: MLModel,
        bundleURL: URL,
        tenant: String,
        clearingLevel: UInt8 = 1
    ) throws -> WitnessPayload {
        let ts = timestampMs()
        let bundleHash = try hashDirectory(at: bundleURL)
        let modelId = extractModelId(from: model)
        let descriptionHash = sha256Truncated(modelId)

        let hashMatch: Double = 1
        let fp = mintFingerprint(
            tenant: tenant,
            procedure: "AI-MDL.1",
            factorA: hashMatch,
            factorB: 0,
            factorC: 0,
            timestampMs: ts.ms
        )

        return WitnessPayload(
            procedureId: "AI-MDL.1",
            factorA: hashMatch,
            factorB: 0,
            factorC: 0,
            clearingLevel: clearingLevel,
            anchorFingerprint: fp,
            anchorEpoch: ts.epoch,
            fingerprintTimestampMs: ts.ms,
            aiModelId: clearingLevel < 3 ? modelId : sha256Truncated(modelId),
            aiPromptHash: descriptionHash,
            aiResponseHash: bundleHash
        )
    }

    // MARK: - Private Helpers

    /// Extract a stable model identifier from an MLModel.
    private static func extractModelId(from model: MLModel) -> String {
        let description = model.modelDescription
        if let metadata = description.metadata[.description] as? String, !metadata.isEmpty {
            return metadata
        }
        if let author = description.metadata[.author] as? String, !author.isEmpty {
            return author
        }
        return "coreml-model"
    }

    /// Hash an MLFeatureProvider's feature names and types into a stable digest.
    private static func hashFeatureProvider(_ provider: MLFeatureProvider) -> String {
        let names = provider.featureNames.sorted()
        let description = names.map { name -> String in
            if let value = provider.featureValue(for: name) {
                return "\(name):\(value.type.rawValue)"
            }
            return "\(name):nil"
        }.joined(separator: ",")
        return sha256Truncated(description)
    }
}
#endif
