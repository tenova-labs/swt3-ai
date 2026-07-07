#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

import Foundation

extension SWT3 {

    /// Hash a file's contents for integrity verification (AI-MDL.1 / AI-MDL.5).
    ///
    /// Reads the file at the given URL and returns a 16-character
    /// truncated SHA-256 hex digest.
    ///
    /// - Parameter url: File URL to hash
    /// - Returns: 16-character hex digest
    /// - Throws: If the file cannot be read
    public static func hashFile(at url: URL) throws -> String {
        let data = try Data(contentsOf: url)
        var hasher = SHA256()
        hasher.update(data: data)
        let digest = hasher.finalize()
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return String(hex.prefix(16))
    }

    /// Hash a directory's contents in deterministic sorted order.
    ///
    /// Walks the directory recursively, sorts all file paths alphabetically,
    /// and produces a single SHA-256 digest of all file contents concatenated
    /// in sorted order. Used for .mlmodelc bundles, adapter stacks, and
    /// any directory-based model artifact.
    ///
    /// - Parameter url: Directory URL to hash
    /// - Returns: 16-character hex digest
    /// - Throws: If the directory cannot be read or enumerated
    public static func hashDirectory(at url: URL) throws -> String {
        let fileManager = FileManager.default
        guard let enumerator = fileManager.enumerator(
            at: url,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            throw ModelIntegrityError.directoryNotReadable(url.path)
        }

        var filePaths: [URL] = []
        for case let fileURL as URL in enumerator {
            let resourceValues = try fileURL.resourceValues(forKeys: [.isRegularFileKey])
            if resourceValues.isRegularFile == true {
                filePaths.append(fileURL)
            }
        }

        filePaths.sort { $0.path < $1.path }

        var hasher = SHA256()
        for fileURL in filePaths {
            let relativePath = fileURL.path.replacingOccurrences(of: url.path, with: "")
            hasher.update(data: Data(relativePath.utf8))
            let fileData = try Data(contentsOf: fileURL)
            hasher.update(data: fileData)
        }

        let digest = hasher.finalize()
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return String(hex.prefix(16))
    }

    /// Errors for model integrity operations.
    public enum ModelIntegrityError: Error {
        case directoryNotReadable(String)
    }
}
