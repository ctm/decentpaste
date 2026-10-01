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
    ///
    /// `storedDomainState` is the biometric enrollment fingerprint recorded
    /// when the secret was stored and `currentDomainState` is the device's
    /// fingerprint now; both are `LAContext.evaluatedPolicyDomainState`
    /// values.
    ///
    /// Two fingerprints that are present and differ mean the enrollment
    /// changed, which invalidated the item, because it is stored with
    /// `[.biometryCurrentSet]`. That comparison is made ahead of the status
    /// deliberately: iOS reports the invalidation with no distinguishable
    /// status, so no status -- `errSecItemNotFound` included -- is evidence
    /// against a changed enrollment.
    ///
    /// A fingerprint absent on either side, however, is not evidence *of* a
    /// change, and must never yield `BIOMETRIC_CHANGED`. Installs made before
    /// the fingerprint was recorded have a secret and no stored value, and
    /// `evaluatedPolicyDomainState` is nil whenever biometry cannot be
    /// evaluated at all. Claiming a reset in those cases would tell the caller
    /// to write over a vault it had never read.
    public static func classify(
        status: OSStatus,
        storedDomainState: Data?,
        currentDomainState: Data?
    ) -> String {
        if let stored = storedDomainState, let current = currentDomainState, stored != current {
            return failureMessage(
                "BIOMETRIC_CHANGED: Key invalidated due to biometric enrollment change",
                status: status)
        }
        return statusFailure(status)
    }

    private static func statusFailure(_ status: OSStatus) -> String {
        switch status {
        case errSecItemNotFound:
            return failureMessage("NOT_FOUND: No secret stored", status: status)

        case errSecUserCanceled:
            return failureMessage("USER_CANCELLED: User cancelled authentication", status: status)

        case errSecAuthFailed:
            return failureMessage("AUTH_FAILED: Authentication failed", status: status)

        default:
            return failureMessage(
                "Failed to retrieve secret: \(securityErrorMessage(status))", status: status)
        }
    }
}

// MARK: - Status Messages

/// A failure message with the raw status appended.
///
/// The number is what makes a field report unambiguous: iOS has no status that
/// means "invalidated", so which status it does return for any given failure is
/// only knowable by measuring it on a device. It goes at the end so that the
/// `ERROR_CODE:` prefix stays first, where `map_plugin_error` looks for it.
public func failureMessage(_ reason: String, status: OSStatus) -> String {
    "\(reason) (OSStatus \(status))"
}

/// The system's description of an `OSStatus`, or a last-resort rendering of the
/// raw number when the system has no message for it.
public func securityErrorMessage(_ status: OSStatus) -> String {
    if let errorMessage = SecCopyErrorMessageString(status, nil) as String? {
        return errorMessage
    }
    return "Security error: \(status)"
}
