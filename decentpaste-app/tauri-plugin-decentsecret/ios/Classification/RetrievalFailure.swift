import Foundation
import Security

// MARK: - Retrieval Failure Classification

/// Turns a failed keychain retrieval into the rejection string the Rust side
/// parses in `src/mobile.rs`.
///
/// This lives in its own module, depending on nothing but Foundation and
/// Security, so that the classification can be unit tested without Tauri,
/// UIKit or a device. Everything that touches `Invoke` stays in
/// `DecentsecretPlugin.swift`.
///
/// The `ERROR_CODE:` prefixes are load-bearing: `map_plugin_error` matches on
/// them, so they must come first in the string and keep their spelling.
public enum RetrievalFailure {

    /// Classify a non-success `OSStatus` from `SecItemCopyMatching`.
    public static func classify(status: OSStatus) -> String {
        switch status {
        case errSecItemNotFound:
            return "NOT_FOUND: No secret stored"

        case errSecUserCanceled:
            return "USER_CANCELLED: User cancelled authentication"

        case errSecAuthFailed:
            return "AUTH_FAILED: Authentication failed"

        case -25293: // errSecInvalidKeychain - often indicates biometric change
            return "BIOMETRIC_CHANGED: Key invalidated due to biometric enrollment change"

        default:
            // Check if it's a biometric invalidation error
            let errorMsg = securityErrorMessage(status)
            if errorMsg.contains("invalidat") || errorMsg.contains("LAError") {
                return "BIOMETRIC_CHANGED: \(errorMsg)"
            } else {
                return "Failed to retrieve secret: \(errorMsg)"
            }
        }
    }
}

// MARK: - Status Messages

/// The system's description of an `OSStatus`, or a last-resort rendering of the
/// raw number when the system has no message for it.
public func securityErrorMessage(_ status: OSStatus) -> String {
    if let errorMessage = SecCopyErrorMessageString(status, nil) as String? {
        return errorMessage
    }
    return "Security error: \(status)"
}
