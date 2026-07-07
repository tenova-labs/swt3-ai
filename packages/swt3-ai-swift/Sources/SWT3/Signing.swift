#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

import Foundation

extension SWT3 {

    /// Sign a payload with HMAC-SHA256 for non-repudiation.
    ///
    /// If `agentId` is provided, the message is `"{fingerprint}:{agentId}"`.
    /// Otherwise, the message is just the fingerprint.
    ///
    /// - Parameters:
    ///   - key: The signing key string
    ///   - fingerprint: The anchor fingerprint to sign
    ///   - agentId: Optional agent identity for binding
    /// - Returns: 64-character lowercase hex HMAC signature
    public static func signPayload(
        key: String,
        fingerprint: String,
        agentId: String? = nil
    ) -> String {
        let message: String
        if let agentId = agentId {
            message = "\(fingerprint):\(agentId)"
        } else {
            message = fingerprint
        }

        let symmetricKey = SymmetricKey(data: Data(key.utf8))
        let signature = HMAC<SHA256>.authenticationCode(
            for: Data(message.utf8),
            using: symmetricKey
        )
        return Data(signature).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Secure Enclave Signing (Apple platforms with hardware security module)

#if canImport(Security) && (os(iOS) || os(macOS) || os(watchOS) || os(tvOS) || os(visionOS))
import Security

extension SWT3 {

    /// Error type for Secure Enclave operations.
    public enum EnclaveError: Error {
        case keyCreationFailed(OSStatus)
        case keyNotFound(String)
        case signingFailed(OSStatus)
        case enclaveNotAvailable
        case dataConversionFailed
    }

    /// Create a signing key in the Secure Enclave.
    ///
    /// The private key is born in hardware and never leaves the Secure Enclave.
    /// Only P-256 (ECDSA) is supported by the hardware constraint.
    ///
    /// - Parameter tag: A unique identifier for the key (e.g. "io.tenova.swt3.signing")
    /// - Returns: The public key reference (private key stays in Secure Enclave)
    /// - Throws: `EnclaveError` if key creation fails or Secure Enclave is unavailable
    public static func createEnclaveKey(tag: String) throws -> SecKey {
        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil
        )

        guard let accessControl = access else {
            throw EnclaveError.enclaveNotAvailable
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String: accessControl,
            ],
        ]

        var cfError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) else {
            if let err = cfError?.takeRetainedValue() {
                let status = CFErrorGetCode(err)
                throw EnclaveError.keyCreationFailed(OSStatus(status))
            }
            throw EnclaveError.keyCreationFailed(-1)
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw EnclaveError.keyCreationFailed(-2)
        }

        return publicKey
    }

    /// Sign a fingerprint using a Secure Enclave key (ECDSA P-256).
    ///
    /// The private key never leaves hardware. The signature proves the
    /// attestation was created on a specific physical device.
    ///
    /// - Parameters:
    ///   - fingerprint: The anchor fingerprint to sign
    ///   - keyTag: The tag used when creating the Secure Enclave key
    ///   - agentId: Optional agent identity for binding
    /// - Returns: Hex-encoded ECDSA P-256 signature
    /// - Throws: `EnclaveError` if key lookup or signing fails
    public static func signWithEnclave(
        fingerprint: String,
        keyTag: String,
        agentId: String? = nil
    ) throws -> String {
        let message: String
        if let agentId = agentId {
            message = "\(fingerprint):\(agentId)"
        } else {
            message = fingerprint
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(keyTag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw EnclaveError.keyNotFound(keyTag)
        }
        guard let keyRef = item, CFGetTypeID(keyRef) == SecKeyGetTypeID() else {
            throw EnclaveError.keyNotFound(keyTag)
        }
        let privateKey = keyRef as! SecKey

        let messageData = Data(message.utf8)
        var cfError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            messageData as CFData,
            &cfError
        ) else {
            if let err = cfError?.takeRetainedValue() {
                let code = CFErrorGetCode(err)
                throw EnclaveError.signingFailed(OSStatus(code))
            }
            throw EnclaveError.signingFailed(-1)
        }

        return (signature as Data).map { String(format: "%02x", $0) }.joined()
    }
}
#endif
