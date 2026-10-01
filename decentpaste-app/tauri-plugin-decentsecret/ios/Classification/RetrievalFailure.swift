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
    /// `storedEnrollment` is the raw record found beside the secret, as
    /// written by `BiometricEnrollment.encoded()`, and `currentEnrollment` is
    /// the enrollment this device is on now.
    ///
    /// Two fingerprints that are present, were read on the same major OS
    /// version and differ mean the enrollment changed, which invalidated the
    /// item, because it is stored with `[.biometryCurrentSet]`. That
    /// comparison is made ahead of the status deliberately: iOS reports the
    /// invalidation with no distinguishable status, so no status --
    /// `errSecItemNotFound` included -- is evidence against a changed
    /// enrollment.
    ///
    /// Anything short of that, however, is not evidence *of* a change, and
    /// must never yield `BIOMETRIC_CHANGED`:
    ///
    /// - No stored record. Installs made before the fingerprint was recorded
    ///   have a secret and nothing beside it.
    /// - A stored record that does not decode: the bare fingerprint earlier
    ///   builds wrote, or a format from a later one.
    /// - No current enrollment. `evaluatedPolicyDomainState` is nil whenever
    ///   biometry cannot be evaluated at all, and an empty fingerprint builds
    ///   no `BiometricEnrollment`.
    /// - A stored major OS version that is not the current one. Apple warns
    ///   that the fingerprint "can change exceptionally between major OS
    ///   versions even if the state of biometry has not changed", so across
    ///   majors a difference says nothing.
    ///
    /// Each of those falls through to the status, because claiming a reset
    /// would tell the caller to write over a vault it had never read.
    public static func classify(
        status: OSStatus,
        storedEnrollment: Data?,
        currentEnrollment: BiometricEnrollment?
    ) -> String {
        if let stored = storedEnrollment.flatMap(BiometricEnrollment.init(encoded:)),
            let current = currentEnrollment,
            stored.osMajorVersion == current.osMajorVersion,
            stored.domainState != current.domainState
        {
            return failureMessage(
                "BIOMETRIC_CHANGED: Key invalidated due to biometric enrollment change",
                status: status)
        }
        return statusFailure(status)
    }

    /// The failure the status alone names.
    ///
    /// The two unavailable-keychain arms are `KeychainMutation`'s, word for
    /// word: an unusable keychain is a property of the keychain rather than of
    /// the operation attempted on it, so both sides name the same statuses and
    /// a test holds the messages equal. `NOT_AVAILABLE` is what either one
    /// means to the embedding app -- neither status says anything about this
    /// device's secret, and `NOT_FOUND` would have the app overwrite a vault
    /// it never read.
    private static func statusFailure(_ status: OSStatus) -> String {
        switch status {
        case errSecItemNotFound:
            return failureMessage("NOT_FOUND: No secret stored", status: status)

        case errSecUserCanceled:
            return failureMessage("USER_CANCELLED: User cancelled authentication", status: status)

        case errSecAuthFailed:
            return failureMessage("AUTH_FAILED: Authentication failed", status: status)

        case errSecNotAvailable:
            return failureMessage("NOT_AVAILABLE: No keychain is available", status: status)

        case errSecMissingEntitlement:
            return failureMessage(
                "NOT_AVAILABLE: This build has no keychain entitlement", status: status)

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
