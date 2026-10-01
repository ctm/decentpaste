import SwiftRs
import Tauri
import UIKit
import LocalAuthentication
import Security
import DecentsecretClassification

// MARK: - Argument Types

class StoreSecretArgs: Decodable {
    let secret: [Int]
}

// MARK: - Constants

private let kServiceName = "com.decentpaste.vault"
private let kAccountName = "vault-key"
/// Sibling of `kAccountName` under the same service, holding the record of
/// the biometric enrollment the secret was stored under: the fingerprint
/// together with the major OS version it was read on, as
/// `BiometricEnrollment.encoded()` writes it.
///
/// The account string still says "domain-state", from when the item held the
/// bare fingerprint, and has to: renaming it would hide the items older
/// builds wrote, which a successful read re-anchors in the current format.
private let kDomainStateAccountName = "vault-key-domain-state"

// MARK: - Plugin Implementation

class DecentsecretPlugin: Plugin {

    // MARK: - Check Availability

    @objc public func checkAvailability(_ invoke: Invoke) throws {
        let context = LAContext()
        var error: NSError?

        // Check if biometric authentication is available
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            invoke.resolve([
                "available": true,
                "method": "iOSBiometric",
                "unavailableReason": NSNull()
            ])
        } else {
            var reason = "Biometric authentication not available"

            if let err = error {
                switch err.code {
                case LAError.biometryNotAvailable.rawValue:
                    reason = "NOT_AVAILABLE: No biometric hardware on this device"
                case LAError.biometryNotEnrolled.rawValue:
                    reason = "NO_BIOMETRICS: No biometrics enrolled on this device"
                case LAError.biometryLockout.rawValue:
                    reason = "ACCESS_DENIED: Biometry is locked out due to too many failed attempts"
                case LAError.passcodeNotSet.rawValue:
                    reason = "NOT_AVAILABLE: Device passcode not set"
                default:
                    reason = "NOT_AVAILABLE: \(err.localizedDescription)"
                }
            }

            invoke.resolve([
                "available": false,
                "method": NSNull(),
                "unavailableReason": reason
            ])
        }
    }

    // MARK: - Store Secret

    @objc public func storeSecret(_ invoke: Invoke) throws {
        do {
            let args = try invoke.parseArgs(StoreSecretArgs.self)
            let secretData = Data(args.secret.map { UInt8($0 & 0xFF) })

            // Delete any existing item first
            deleteFromKeychain()

            // Create access control with biometric protection
            var accessControlError: Unmanaged<CFError>?
            guard let accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                [.biometryCurrentSet], // CRITICAL: Invalidate on biometric change
                &accessControlError
            ) else {
                let errorMsg = accessControlError?.takeRetainedValue().localizedDescription ?? "Unknown error"
                invoke.reject("NOT_AVAILABLE: Failed to create access control: \(errorMsg)")
                return
            }

            // Build the keychain query
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: kServiceName,
                kSecAttrAccount as String: kAccountName,
                kSecValueData as String: secretData,
                kSecAttrAccessControl as String: accessControl,
                kSecUseAuthenticationContext as String: LAContext()
            ]

            // Add to keychain
            let status = SecItemAdd(query as CFDictionary, nil)

            if status == errSecSuccess {
                // Only once the secret is really there: a fingerprint without
                // a secret would make the next retrieval's errSecItemNotFound
                // look like a changed enrollment.
                storeBiometricEnrollment()
                invoke.resolve([:])
            } else {
                let errorMsg = securityErrorMessage(status)
                invoke.reject(
                    failureMessage("Failed to store secret: \(errorMsg)", status: status))
            }

        } catch {
            invoke.reject("Failed to parse arguments: \(error.localizedDescription)")
        }
    }

    // MARK: - Retrieve Secret

    @objc public func retrieveSecret(_ invoke: Invoke) throws {
        let context = LAContext()
        context.localizedReason = "Access your vault"

        // Build the keychain query
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kServiceName,
            kSecAttrAccount as String: kAccountName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            if let data = result as? Data {
                // The secret was just read under the current enrollment, so
                // that enrollment is exactly the one a later change has to be
                // measured against. Recording it here is what covers the
                // installs that already hold a secret and have no fingerprint
                // beside it, and what re-anchors a record the OS changed
                // under us by its own major upgrade. Without it, such an
                // install stays inconclusive until the user happens to store
                // a new secret, which for a vault key may be never.
                storeBiometricEnrollment()

                let secretArray = data.map { Int($0) }
                invoke.resolve(["secret": secretArray])
            } else {
                invoke.reject("NOT_FOUND: Secret data is corrupted")
            }

        default:
            invoke.reject(RetrievalFailure.classify(
                status: status,
                storedEnrollment: storedBiometricEnrollment(),
                currentEnrollment: currentBiometricEnrollment()
            ))
        }
    }

    // MARK: - Delete Secret

    @objc public func deleteSecret(_ invoke: Invoke) throws {
        deleteFromKeychain()
        invoke.resolve([:])
    }

    // MARK: - Biometric Enrollment Fingerprint

    /// The device's current biometric enrollment fingerprint.
    ///
    /// `evaluatedPolicyDomainState` is only populated once the policy has been
    /// found evaluable, and is nil otherwise.
    private func currentBiometricDomainState() -> Data? {
        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return nil
        }
        return context.evaluatedPolicyDomainState
    }

    /// The device's current enrollment: its fingerprint, paired with the major
    /// OS version that fingerprint was read on.
    ///
    /// The version is recorded because Apple warns that the fingerprint "can
    /// change exceptionally between major OS versions even if the state of
    /// biometry has not changed", so only fingerprints read on the same major
    /// can be compared.
    ///
    /// Nil too when the fingerprint read is empty, which is no fingerprint:
    /// `BiometricEnrollment` refuses to hold one, so that an empty current
    /// fingerprint cannot be compared against a real stored one.
    private func currentBiometricEnrollment() -> BiometricEnrollment? {
        guard let domainState = currentBiometricDomainState() else { return nil }
        return BiometricEnrollment.current(domainState: domainState)
    }

    /// Record the current enrollment beside the secret, so that a later
    /// failure to retrieve it can be told apart from a changed enrollment.
    /// Called when a secret is stored, and again whenever one is read, which
    /// is a no-op once the record is the current enrollment's.
    ///
    /// The item deliberately carries no access control: it must be readable
    /// with no prompt, right after an authentication that just failed, and it
    /// must stay readable once the secret itself has been invalidated. That is
    /// why the fingerprint is a sibling item and not an attribute on the
    /// secret -- an attribute cannot desynchronize, but reading it needs the
    /// very authentication that failed, so it is unavailable exactly when it
    /// is wanted. It is not in UserDefaults either, whose lifetime and
    /// backup/restore semantics differ from those of the keychain item it
    /// describes, so a restore could resurrect a stale fingerprint.
    ///
    /// The write overwrites whatever is there. `storeSecret` deletes the pair
    /// before storing, but a delete that failed leaves the old record in
    /// place, where a bare `SecItemAdd` reports `errSecDuplicateItem` and
    /// leaves it: the next retrieval would then measure a brand new secret
    /// against a previous enrollment and announce a change that never
    /// happened. If the update fails as well, delete the record rather than
    /// let it stand, since an absent record is merely inconclusive while a
    /// stale one is a false `BIOMETRIC_CHANGED`.
    private func storeBiometricEnrollment() {
        guard let enrollment = currentBiometricEnrollment() else { return }
        let encoded = enrollment.encoded()

        // Every successful retrieval calls this, so the usual case is that
        // the record is already the current enrollment's; reading it back
        // takes no authentication and saves a pointless write.
        guard storedBiometricEnrollment() != encoded else { return }

        let item: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kServiceName,
            kSecAttrAccount as String: kDomainStateAccountName
        ]
        var addQuery = item
        addQuery[kSecValueData as String] = encoded
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly

        guard SecItemAdd(addQuery as CFDictionary, nil) == errSecDuplicateItem else { return }

        let attributes: [String: Any] = [kSecValueData as String: encoded]
        if SecItemUpdate(item as CFDictionary, attributes as CFDictionary) != errSecSuccess {
            SecItemDelete(item as CFDictionary)
        }
    }

    /// The enrollment record stored beside the secret, if there is one, in the
    /// form it was written in. Earlier builds wrote the bare fingerprint, with
    /// no OS version, which `RetrievalFailure.classify` treats as
    /// inconclusive.
    private func storedBiometricEnrollment() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kServiceName,
            kSecAttrAccount as String: kDomainStateAccountName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else {
            return nil
        }
        return result as? Data
    }

    // MARK: - Private Helpers

    /// Delete the secret and its fingerprint together, so that the two have
    /// exactly the same lifetime.
    private func deleteFromKeychain() {
        for account in [kAccountName, kDomainStateAccountName] {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: kServiceName,
                kSecAttrAccount as String: account
            ]
            SecItemDelete(query as CFDictionary)
        }
    }
}

// MARK: - Plugin Initialization

@_cdecl("init_plugin_decentsecret")
func initPlugin() -> Plugin {
    return DecentsecretPlugin()
}
