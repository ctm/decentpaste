import Foundation
import Security

// MARK: - Keychain Mutation Failures

/// Turns a failed keychain mutation -- storing the secret, or deleting it --
/// into the rejection string the Rust side parses in `src/mobile.rs`.
///
/// This lives beside `RetrievalFailure`, in the same dependency-free module,
/// for the same reason: the decision is a pure function of an `OSStatus` and
/// can be unit tested without Tauri, UIKit or a device.
///
/// The `ERROR_CODE:` prefixes are load-bearing: `map_plugin_error` matches on
/// them, so they must come first in the string and keep their spelling. It
/// matches with `contains`, in a fixed order that tries `NOT_AVAILABLE` first
/// and `AUTH_FAILED` ahead of `BIOMETRIC_CHANGED`, so a message carrying two
/// codes would be read as whichever came first in that order rather than
/// whichever the mutation meant. No message here carries more than one.
///
/// What is deliberately absent is `BIOMETRIC_CHANGED`. A store writes a new
/// item, bound by `[.biometryCurrentSet]` to the enrollment the device is on
/// at that moment, so there is no older enrollment for a change to have
/// invalidated: on iOS a failure to store can never mean the biometrics
/// changed. Android's `storeSecret` does report it, because it reuses a
/// KeyStore key an enrollment change permanently invalidates, and that
/// asymmetry is in the platforms rather than in these two implementations.
/// Only a retrieval has a stored enrollment to measure against, which is why
/// `RetrievalFailure` is the only place that comparison is made.
public enum KeychainMutation {

    /// Classify a non-success `OSStatus` from the `SecItemAdd` that stores the
    /// secret.
    ///
    /// `errSecDuplicateItem` -- a previous secret that the delete before the
    /// add did not remove -- deliberately falls through to the unprefixed arm.
    /// None of the codes `map_plugin_error` knows means "the secret already
    /// there could not be replaced", and inventing the nearest one would tell
    /// the embedding app something untrue; the system's own description of the
    /// status names the condition exactly.
    public static func storeFailure(status: OSStatus) -> String {
        classify(status: status, failedTo: "store")
    }

    /// Whether an `OSStatus` from the `SecItemDelete` that removes the secret
    /// leaves the item gone.
    ///
    /// `errSecItemNotFound` is a successful delete: the item is absent, which
    /// is the whole of what was asked for. Saying so is what keeps the delete
    /// idempotent, and `storeSecret` depends on that -- it deletes before it
    /// writes, so a not-found counted as a failure would fail the first store
    /// on every device.
    public static func deleteSucceeded(_ status: OSStatus) -> Bool {
        status == errSecSuccess || status == errSecItemNotFound
    }

    /// Classify a status `deleteSucceeded` rejects, i.e. one that left the
    /// item where it was.
    public static func deleteFailure(status: OSStatus) -> String {
        classify(status: status, failedTo: "delete")
    }

    /// The arms shared by every mutation. `verb` completes "Failed to ...
    /// secret", which is the unprefixed fallback: no code in
    /// `map_plugin_error`'s vocabulary fits, so the Rust side keeps the whole
    /// message as a plugin-level failure, which is what it is.
    private static func classify(status: OSStatus, failedTo verb: String) -> String {
        switch status {
        case errSecAuthFailed:
            return failureMessage("AUTH_FAILED: Authentication failed", status: status)

        case errSecUserCanceled:
            return failureMessage("USER_CANCELLED: User cancelled authentication", status: status)

        case errSecNotAvailable:
            return failureMessage("NOT_AVAILABLE: No keychain is available", status: status)

        case errSecMissingEntitlement:
            return failureMessage(
                "MISCONFIGURED: This build has no keychain entitlement", status: status)

        default:
            return failureMessage(
                "Failed to \(verb) secret: \(securityErrorMessage(status))", status: status)
        }
    }
}
