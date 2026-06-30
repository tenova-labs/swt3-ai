import XCTest
@testable import SWT3

final class FingerprintTests: XCTestCase {

    // MARK: - Fingerprint Vectors (47 total, from test-vectors.json)

    func testVector01_INF1_BasicPass() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-INF.1", factorA: 1, factorB: 1, factorC: 0, timestampMs: 1774800000000),
            "2e16e2fe92dd"
        )
    }

    func testVector02_INF2_LatencyFail() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "AWS_NITRO_ENCLAVE", procedure: "AI-INF.2", factorA: 5000, factorB: 8000, factorC: 1, timestampMs: 1774800001000),
            "4ed784765e6c"
        )
    }

    func testVector03_GRD1_GuardrailPass() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-GRD.1", factorA: 2, factorB: 3, factorC: 0, timestampMs: 1774800002000),
            "a0aa7669ae6f"
        )
    }

    func testVector04_MDL1_IntegrityFail() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "AZURE_TRUSTED_EXEC", procedure: "AI-MDL.1", factorA: 1, factorB: 0, factorC: 1, timestampMs: 1774800003000),
            "c36d477b3c2d"
        )
    }

    func testVector05_FAIR1_BiasPass() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ACME_DEFENSE", procedure: "AI-FAIR.1", factorA: 15, factorB: 15, factorC: 0, timestampMs: 1774800004000),
            "53180f5ae221"
        )
    }

    func testVector06_MDL2_SaasTenant() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "SAAS_TENANT_42", procedure: "AI-MDL.2", factorA: 1, factorB: 1, factorC: 0, timestampMs: 1774800005000),
            "c7e61c16ee94"
        )
    }

    func testVector07_EXPL2_LargeFactors() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "AWS_NITRO_ENCLAVE", procedure: "AI-EXPL.2", factorA: 85, factorB: 92, factorC: 0, timestampMs: 1774800006000),
            "2f2b989bb5c6"
        )
    }

    func testVector08_HITL1_AttestationPass() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-HITL.1", factorA: 1, factorB: 1, factorC: 0, timestampMs: 1774800007000),
            "afbab8c9e098"
        )
    }

    func testVector09_INF3_LargeFactorValues() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "DEMO_ENCLAVE", procedure: "AI-INF.3", factorA: 10000, factorB: 9500, factorC: 0, timestampMs: 1774800008000),
            "05010820e5a4"
        )
    }

    func testVector10_DATA1_AllZeros() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "AZURE_TRUSTED_EXEC", procedure: "AI-DATA.1", factorA: 0, factorB: 0, factorC: 0, timestampMs: 1774800009000),
            "289eb7452237"
        )
    }

    func testVector11_TOOL1_ToolSucceeded() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-TOOL.1", factorA: 1, factorB: 42, factorC: 1, timestampMs: 1774800010000),
            "019eaf85fcba"
        )
    }

    func testVector12_ID1_IdentityPresent() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-ID.1", factorA: 1, factorB: 1, factorC: 0, timestampMs: 1774800011000),
            "7966c8f7fbb6"
        )
    }

    func testVector13_GRD3_GatekeeperBlocked() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ACME_DEFENSE", procedure: "AI-GRD.3", factorA: 2, factorB: 0, factorC: 0, timestampMs: 1774800012000),
            "62251b4cf593"
        )
    }

    func testVector14_RAG1_ContextRetrieval() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-RAG.1", factorA: 5, factorB: 1, factorC: 0, timestampMs: 1774800010000),
            "66209137510b"
        )
    }

    func testVector15_RAG2_ContextRelevance() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-RAG.2", factorA: 750, factorB: 820, factorC: 1, timestampMs: 1774800011000),
            "f714436c06cf"
        )
    }

    func testVector16_MDL5_WeightIntegrity() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-MDL.5", factorA: 1, factorB: 1, factorC: 0, timestampMs: 1774800020000),
            "eb95216c3841"
        )
    }

    func testVector17_MDL6_AdapterStack() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-MDL.6", factorA: 3, factorB: 1, factorC: 0, timestampMs: 1774800021000),
            "8cdb254d3b0f"
        )
    }

    func testVector18_MDL7_Quantization() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-MDL.7", factorA: 1, factorB: 1, factorC: 5, timestampMs: 1774800022000),
            "e41a794af2b7"
        )
    }

    func testVector19_SKILL1_SkillManifest() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-SKILL.1", factorA: 4, factorB: 1, factorC: 0, timestampMs: 1774800023000),
            "99e67c3870ab"
        )
    }

    func testVector20_SKILL2_MemoryContext() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-SKILL.2", factorA: 2, factorB: 1, factorC: 0, timestampMs: 1774800024000),
            "3b7054cb045a"
        )
    }

    func testVector21_SKILL3_RewardModel() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-SKILL.3", factorA: 1, factorB: 1, factorC: 0, timestampMs: 1774800025000),
            "737d5adb8f69"
        )
    }

    func testVector22_CHAIN1_MultiAgent() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-CHAIN.1", factorA: 3, factorB: 1, factorC: 1, timestampMs: 1774800030000),
            "c7210714030a"
        )
    }

    func testVector23_VIO1_ViolationReport() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ACME_DEFENSE", procedure: "AI-VIO.1", factorA: 3, factorB: 1, factorC: 4, timestampMs: 1774800031000),
            "2cf52653ff8a"
        )
    }

    func testVector24_CHR1_AgentCharter() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-CHR.1", factorA: 1, factorB: 1, factorC: 0, timestampMs: 1774800032000),
            "0fe7713c8954"
        )
    }

    func testVector25_MDL8_ModelRegistry() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-MDL.8", factorA: 1, factorB: 1, factorC: 0, timestampMs: 1774800033000),
            "c21161b481d1"
        )
    }

    func testVector26_HITL3_ReviewerIdentity() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ACME_DEFENSE", procedure: "AI-HITL.3", factorA: 2, factorB: 2, factorC: 2, timestampMs: 1774800034000),
            "d7e3a52bd012"
        )
    }

    func testVector27_SAFE1_SafeState() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-SAFE.1", factorA: 1, factorB: 1, factorC: 1, timestampMs: 1774800035000),
            "44cc01ade479"
        )
    }

    func testVector28_DATA3_TrainingStats() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-DATA.3", factorA: 50000, factorB: 128, factorC: 850, timestampMs: 1774800036000),
            "f9ce447c6e19"
        )
    }

    func testVector29_DATA4_PIILifecycle() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-DATA.4", factorA: 10000, factorB: 1, factorC: 1, timestampMs: 1774800037000),
            "39407008633d"
        )
    }

    func testVector30_ENV1_ThermalIntegrity() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-ENV.1", factorA: 42, factorB: 85, factorC: 1, timestampMs: 1774800037000),
            "64c031701878"
        )
    }

    func testVector31_ENV2_PowerIntegrity() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-ENV.2", factorA: 1200, factorB: 1200, factorC: 0, timestampMs: 1774800037000),
            "0b31660c296f"
        )
    }

    func testVector32_MARK1_ContentProvenance() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-MARK.1", factorA: 3, factorB: 1, factorC: 0, timestampMs: 1774800031000),
            "8ec75a21838f"
        )
    }

    func testVector33_BASE1_BehavioralBaseline() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-BASE.1", factorA: 12, factorB: 1, factorC: 1, timestampMs: 1774800032000),
            "e66df4bbdedb"
        )
    }

    func testVector34_METAGOV1_RuleAttestation() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-METAGOV.1", factorA: 5, factorB: 123456, factorC: 1, timestampMs: 1774800000000),
            "1c94756db9c1"
        )
    }

    func testVector35_METAGOV2_RegLayer() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-METAGOV.2", factorA: 1, factorB: 789012, factorC: 0, timestampMs: 1774800000000),
            "aadb6f87dcee"
        )
    }

    func testVector36_METAGOV3_PolicyDowngrade() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-METAGOV.3", factorA: 2, factorB: 345678, factorC: 1, timestampMs: 1774800000000),
            "32a6bd5ad5c9"
        )
    }

    func testVector37_METAGOV4_ConflictResolution() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-METAGOV.4", factorA: 10, factorB: 0, factorC: 3, timestampMs: 1774800000000),
            "0b503341c3c4"
        )
    }

    func testVector38_METAGOV5_ScopeBoundary() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-METAGOV.5", factorA: 0, factorB: 1, factorC: 567890, timestampMs: 1774800000000),
            "dd4fe9576cd2"
        )
    }

    func testVector39_METAGOV6_EmergencyOverride() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-METAGOV.6", factorA: 1, factorB: 48, factorC: 0, timestampMs: 1774800000000),
            "270738c276fc"
        )
    }

    func testVector40_METAGOV7_SyncDivergence() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-METAGOV.7", factorA: 1, factorB: 234567, factorC: 876543, timestampMs: 1774800000000),
            "66601df8b6d7"
        )
    }

    func testVector41_METAGOV8_RuleProvenance() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "ENCLAVE_PROD", procedure: "AI-METAGOV.8", factorA: 4, factorB: 654321, factorC: 1, timestampMs: 1774800000000),
            "1500a3dcab94"
        )
    }

    func testVector42_ENG1_DesignGeneration() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "DESIGN_ENCLAVE", procedure: "AI-ENG.1", factorA: 12, factorB: 500, factorC: 0, timestampMs: 1774800042000),
            "3a9ad53541de"
        )
    }

    func testVector43_ENG2_SimulationValidation() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "DESIGN_ENCLAVE", procedure: "AI-ENG.2", factorA: 1000, factorB: 1000, factorC: 0, timestampMs: 1774800043000),
            "bd1bb0a1554b"
        )
    }

    func testVector44_ENG3_SafetyCriticalReview() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "DESIGN_ENCLAVE", procedure: "AI-ENG.3", factorA: 3, factorB: 3, factorC: 1, timestampMs: 1774800044000),
            "0f7d9d58352d"
        )
    }

    func testVector45_ENG4_MaterialCompliance() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "DESIGN_ENCLAVE", procedure: "AI-ENG.4", factorA: 15, factorB: 15, factorC: 0, timestampMs: 1774800045000),
            "34bfd6594dff"
        )
    }

    func testVector46_ENG5_DesignRevisionChain() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "DESIGN_ENCLAVE", procedure: "AI-ENG.5", factorA: 10, factorB: 7, factorC: 1, timestampMs: 1774800046000),
            "26ae638d2064"
        )
    }

    func testVector47_ENG6_FabricationRelease() {
        XCTAssertEqual(
            SWT3.mintFingerprint(tenant: "DESIGN_ENCLAVE", procedure: "AI-ENG.6", factorA: 1, factorB: 5, factorC: 2, timestampMs: 1774800047000),
            "4ff83090bfc4"
        )
    }

    // MARK: - numStr Parity

    func testNumStr_IntegerValued() {
        XCTAssertEqual(SWT3.numStr(1.0), "1")
        XCTAssertEqual(SWT3.numStr(0.0), "0")
        XCTAssertEqual(SWT3.numStr(42.0), "42")
        XCTAssertEqual(SWT3.numStr(10000.0), "10000")
        XCTAssertEqual(SWT3.numStr(-5.0), "-5")
    }

    func testNumStr_FractionalValues() {
        XCTAssertEqual(SWT3.numStr(1.5), "1.5")
        XCTAssertEqual(SWT3.numStr(0.75), "0.75")
    }

    func testTimestampMs_ReturnsReasonableValues() {
        let ts = SWT3.timestampMs()
        XCTAssertGreaterThan(ts.ms, 1700000000000)
        XCTAssertEqual(ts.epoch, ts.ms / 1000)
    }
}

final class SigningTests: XCTestCase {

    // MARK: - Signing Vectors

    func testSigningWithAgentId() {
        XCTAssertEqual(
            SWT3.signPayload(key: "test-signing-key", fingerprint: "019eaf85fcba", agentId: "agent-007"),
            "00ff82da1659e2e6a7fa875c781ed4635976c8136b8dc2c24672adb8673cb112"
        )
    }

    func testSigningWithoutAgentId() {
        XCTAssertEqual(
            SWT3.signPayload(key: "test-signing-key", fingerprint: "019eaf85fcba"),
            "d844102f40fb5dad449a2f57922f5b23f73ffb3a026b5bd5fd537ebe5c6c44d0"
        )
    }

    // MARK: - Profile Signing Vector

    func testProfileSigningCanonicalMessage() {
        let message = "PROFILE:gpt-4o:abc123:1700000000000:1700086400000:AI-GRD.1,AI-INF.1,AI-MDL.1:0.667"
        let signature = SWT3.signPayload(key: "test-key-123", fingerprint: message)
        XCTAssertEqual(signature, "bdce7111c3a6e9968a5de1973f3a977aadb42c2d7327f38de79729019c7baa42")
    }
}

final class HashTests: XCTestCase {

    // MARK: - Hash Vectors

    func testHashHelloWorld() {
        XCTAssertEqual(SWT3.sha256Truncated("Hello, world!"), "315f5bdb76d078c4")
    }

    func testHashEmptyString() {
        XCTAssertEqual(SWT3.sha256Truncated(""), "e3b0c44298fc1c14")
    }

    func testHashQuestion() {
        XCTAssertEqual(SWT3.sha256Truncated("What is the meaning of life?"), "318f903a83b4d30d")
    }

    func testHashModelFingerprint() {
        XCTAssertEqual(SWT3.sha256Truncated("gpt-4o-2024-11-20:fp_abc123"), "0f6b04241d237297")
    }

    func testHashSystemPrompt() {
        XCTAssertEqual(
            SWT3.sha256Truncated("You are a helpful fraud detection assistant. Flag any transaction over $10,000."),
            "479eaa1ee804f844"
        )
    }

    // MARK: - Full Digest

    func testSha256Hex_FullLength() {
        let full = SWT3.sha256Hex("test", length: 64)
        XCTAssertEqual(full.count, 64)
    }

    func testSha256Hex_TruncatedTo12() {
        let short = SWT3.sha256Hex("test", length: 12)
        XCTAssertEqual(short.count, 12)
    }
}

final class TypesTests: XCTestCase {

    func testVersion() {
        XCTAssertEqual(SWT3.version, "0.5.8")
    }

    func testSigningAlgorithmRawValues() {
        XCTAssertEqual(SigningAlgorithm.hmacSha256.rawValue, "hmac-sha256")
        XCTAssertEqual(SigningAlgorithm.mlDsa65.rawValue, "ml-dsa-65")
        XCTAssertEqual(SigningAlgorithm.ecdsaP256.rawValue, "ecdsa-p256")
    }

    func testRevocationReasonCodes() {
        XCTAssertEqual(RevocationReason.unspecified.rawValue, 0)
        XCTAssertEqual(RevocationReason.modelRecall.rawValue, 1)
        XCTAssertEqual(RevocationReason.policyViolation.rawValue, 2)
        XCTAssertEqual(RevocationReason.dataContamination.rawValue, 3)
        XCTAssertEqual(RevocationReason.consentWithdrawal.rawValue, 4)
        XCTAssertEqual(RevocationReason.regulatoryOrder.rawValue, 5)
        XCTAssertEqual(RevocationReason.errorCorrection.rawValue, 6)
    }

    func testRevocationReasonLabels() {
        XCTAssertEqual(RevocationReason.unspecified.label, "unspecified")
        XCTAssertEqual(RevocationReason.modelRecall.label, "model_recall")
        XCTAssertEqual(RevocationReason.policyViolation.label, "policy_violation")
        XCTAssertEqual(RevocationReason.dataContamination.label, "data_contamination")
        XCTAssertEqual(RevocationReason.consentWithdrawal.label, "consent_withdrawal")
        XCTAssertEqual(RevocationReason.regulatoryOrder.label, "regulatory_order")
        XCTAssertEqual(RevocationReason.errorCorrection.label, "error_correction")
    }

    func testTrustLevels() {
        XCTAssertEqual(TrustLevel.denied.rawValue, 0)
        XCTAssertEqual(TrustLevel.basic.rawValue, 1)
        XCTAssertEqual(TrustLevel.verified.rawValue, 2)
        XCTAssertEqual(TrustLevel.attested.rawValue, 3)
        XCTAssertEqual(TrustLevel.sovereign.rawValue, 4)
    }

    func testDenialReasons() {
        XCTAssertEqual(DenialReason.anchorNotFound.rawValue, "anchor_not_found")
        XCTAssertEqual(DenialReason.anchorExpired.rawValue, "anchor_expired")
        XCTAssertEqual(DenialReason.anchorRevoked.rawValue, "anchor_revoked")
        XCTAssertEqual(DenialReason.signatureMissing.rawValue, "signature_missing")
        XCTAssertEqual(DenialReason.tenantNotTrusted.rawValue, "tenant_not_trusted")
        XCTAssertEqual(DenialReason.denyListed.rawValue, "deny_listed")
        XCTAssertEqual(DenialReason.insufficientProcedures.rawValue, "insufficient_procedures")
        XCTAssertEqual(DenialReason.signatureInvalid.rawValue, "signature_invalid")
        XCTAssertEqual(DenialReason.signatureUnverifiable.rawValue, "signature_unverifiable")
        XCTAssertEqual(DenialReason.insufficientTrustLevel.rawValue, "insufficient_trust_level")
        XCTAssertEqual(DenialReason.timestampFuture.rawValue, "timestamp_future")
        XCTAssertEqual(DenialReason.rateLimited.rawValue, "rate_limited")
    }

    func testKeyPurpose() {
        XCTAssertEqual(KeyPurpose.signing.rawValue, "signing")
        XCTAssertEqual(KeyPurpose.encryption.rawValue, "encryption")
        XCTAssertEqual(KeyPurpose.delegation.rawValue, "delegation")
    }

    func testLifecycleStages() {
        XCTAssertEqual(SWT3.lifecycleStages.count, 6)
        XCTAssertEqual(SWT3.lifecycleStages[0], "design")
        XCTAssertEqual(SWT3.lifecycleStages[5], "decommission")
    }

    func testMetagovScopes() {
        XCTAssertEqual(SWT3.metagovScopes.count, 5)
        XCTAssertTrue(SWT3.metagovScopes.contains("verdict_rules"))
        XCTAssertTrue(SWT3.metagovScopes.contains("full"))
    }

    // MARK: - Codable

    func testWitnessPayloadCodable() throws {
        let payload = WitnessPayload(
            procedureId: "AI-INF.1",
            factorA: 1,
            factorB: 1,
            factorC: 0,
            anchorFingerprint: "2e16e2fe92dd"
        )
        let encoder = JSONEncoder()
        let data = try encoder.encode(payload)
        let json = String(data: data, encoding: .utf8)!
        XCTAssertTrue(json.contains("\"procedure_id\":\"AI-INF.1\""))
        XCTAssertTrue(json.contains("\"anchor_fingerprint\":\"2e16e2fe92dd\""))
        XCTAssertTrue(json.contains("\"factor_a\":1"))

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(WitnessPayload.self, from: data)
        XCTAssertEqual(decoded, payload)
    }

    func testWitnessReceiptCodable() throws {
        let receipt = WitnessReceipt(
            procedureId: "AI-INF.1",
            verdict: "PASS",
            swt3Anchor: "SWT3-E-VULTR-AI-INF1-PASS-1774800000-2e16e2fe92dd",
            clearingLevel: 1,
            witnessedAt: "2026-06-19T00:00:00Z",
            verificationUrl: "https://sovereign.tenova.io/verify/2e16e2fe92dd",
            ok: true
        )
        let encoder = JSONEncoder()
        let data = try encoder.encode(receipt)
        let json = String(data: data, encoding: .utf8)!
        XCTAssertTrue(json.contains("\"swt3_anchor\""))
        XCTAssertTrue(json.contains("\"verification_url\""))

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(WitnessReceipt.self, from: data)
        XCTAssertEqual(decoded, receipt)
    }

    // MARK: - Equatable

    func testWitnessPayloadEquatable() {
        let a = WitnessPayload(procedureId: "AI-INF.1", factorA: 1, factorB: 1, factorC: 0)
        let b = WitnessPayload(procedureId: "AI-INF.1", factorA: 1, factorB: 1, factorC: 0)
        let c = WitnessPayload(procedureId: "AI-GRD.1", factorA: 2, factorB: 3, factorC: 0)
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    func testWitnessPayloadInit() {
        let payload = WitnessPayload(
            procedureId: "AI-INF.1",
            factorA: 1,
            factorB: 1,
            factorC: 0
        )
        XCTAssertEqual(payload.procedureId, "AI-INF.1")
        XCTAssertEqual(payload.clearingLevel, 1)
        XCTAssertNil(payload.agentId)
        XCTAssertNil(payload.jurisdiction)
    }

    func testWitnessConfigDefaults() {
        let config = WitnessConfig(
            endpoint: "https://sovereign.tenova.io/api/v1/witness",
            apiKey: "axm_test",
            tenantId: "TEST"
        )
        XCTAssertEqual(config.clearingLevel, 1)
        XCTAssertEqual(config.bufferSize, 10)
        XCTAssertEqual(config.flushIntervalSeconds, 5.0)
        XCTAssertEqual(config.timeoutMs, 10000)
        XCTAssertEqual(config.maxRetries, 3)
    }
}
