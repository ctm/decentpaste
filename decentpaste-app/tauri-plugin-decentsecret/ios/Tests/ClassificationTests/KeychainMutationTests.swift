import Foundation
import Security
import XCTest

import DecentsecretClassification

// MARK: - Keychain Mutation Failures

/// What a failed keychain mutation tells the Rust side, and the two
/// properties that make it worth telling: at most one code prefix per
/// message, in first place, and the numeric status always there to name the
/// condition the prefix generalizes.
final class KeychainMutationTests: XCTestCase {

    // MARK: - Fixtures

    /// Every status a keychain write plausibly comes back with -- the four
    /// named arms, the duplicate a failed pre-delete leaves, a lookup failure
    /// that means nothing to a write, three the system describes but this code
    /// does not name, and one the system can only echo back as a number.
    private let failureStatuses: [OSStatus] = [
        errSecAuthFailed,
        errSecUserCanceled,
        errSecNotAvailable,
        errSecMissingEntitlement,
        errSecDuplicateItem,
        errSecItemNotFound,
        errSecInteractionNotAllowed,
        errSecInvalidItemRef,
        errSecParam,
        OSStatus(-1),
    ]

    /// Both mutations, so that the properties below are stated of the pair
    /// rather than of whichever one was written first.
    private let mutations: [(String, (OSStatus) -> String)] = [
        ("store", { KeychainMutation.storeFailure(status: $0) }),
        ("delete", { KeychainMutation.deleteFailure(status: $0) }),
    ]

    // MARK: - Status Arms

    /// The named arms, whole. Two statuses share `NOT_AVAILABLE` and keep
    /// their own wording, because "no keychain at all" and "this build may not
    /// use the keychain" are the same thing to the embedding app and nothing
    /// alike to whoever has to fix it.
    func testTheNamedStoreArms() {
        XCTAssertEqual(
            KeychainMutation.storeFailure(status: errSecAuthFailed),
            "AUTH_FAILED: Authentication failed (OSStatus -25293)")
        XCTAssertEqual(
            KeychainMutation.storeFailure(status: errSecUserCanceled),
            "USER_CANCELLED: User cancelled authentication (OSStatus -128)")
        XCTAssertEqual(
            KeychainMutation.storeFailure(status: errSecNotAvailable),
            "NOT_AVAILABLE: No keychain is available (OSStatus -25291)")
        XCTAssertEqual(
            KeychainMutation.storeFailure(status: errSecMissingEntitlement),
            "NOT_AVAILABLE: This build has no keychain entitlement (OSStatus -34018)")
    }

    /// The unprefixed arm quotes the system's description of the status, which
    /// is the system's wording to change, so only the shape around it is
    /// pinned. `errSecDuplicateItem` is the arm's most interesting input: the
    /// secret is still the old one, and no code says that.
    func testTheUnprefixedStoreArm() {
        let message = KeychainMutation.storeFailure(status: errSecDuplicateItem)

        XCTAssertTrue(message.hasPrefix("Failed to store secret: "), message)
        XCTAssertTrue(message.hasSuffix(" (OSStatus -25299)"), message)
        XCTAssertFalse(securityErrorMessage(errSecDuplicateItem).isEmpty)
    }

    /// A delete takes the same named arms and says what it was that failed,
    /// which is the whole of the difference between the two mutations.
    func testADeleteSaysItWasADelete() {
        XCTAssertEqual(
            KeychainMutation.deleteFailure(status: errSecAuthFailed),
            "AUTH_FAILED: Authentication failed (OSStatus -25293)")
        XCTAssertTrue(
            KeychainMutation.deleteFailure(status: errSecInvalidItemRef)
                .hasPrefix("Failed to delete secret: "),
            KeychainMutation.deleteFailure(status: errSecInvalidItemRef))
    }

    /// Pin the numbers a field report names, for the same reason the retrieval
    /// tests pin theirs: which status a given failure really returns is only
    /// knowable by measuring it on a device.
    func testTheStatusNumbersAFieldReportNames() {
        XCTAssertEqual(errSecNotAvailable, -25291)
        XCTAssertEqual(errSecMissingEntitlement, -34018)
        XCTAssertEqual(errSecDuplicateItem, -25299)
    }

    // MARK: - What Counts As A Deleted Item

    /// Two statuses leave the item gone, and nothing else does.
    ///
    /// `errSecItemNotFound` among them is what keeps the delete idempotent:
    /// `storeSecret` deletes the pair before it writes, so counting a
    /// not-found as a failure would fail the first store on every device, and
    /// counting anything else as success is the dishonesty this classification
    /// exists to end -- a delete that failed would report an empty vault.
    func testOnlyAGoneItemCountsAsDeleted() {
        XCTAssertTrue(KeychainMutation.deleteSucceeded(errSecSuccess))
        XCTAssertTrue(KeychainMutation.deleteSucceeded(errSecItemNotFound))

        for status in failureStatuses where status != errSecItemNotFound {
            XCTAssertFalse(KeychainMutation.deleteSucceeded(status), "\(status)")
        }
    }

    // MARK: - The Properties Every Arm Keeps

    /// The number is appended, never substituted, so every report carries the
    /// raw status whichever arm it took.
    func testEveryMutationFailureCarriesItsNumericStatus() {
        for (mutation, classify) in mutations {
            for status in failureStatuses {
                XCTAssertTrue(
                    classify(status).hasSuffix(" (OSStatus \(status))"),
                    "\(mutation) \(status): \(classify(status))")
            }
        }
    }

    /// At most one recognized code per message, and in first place.
    ///
    /// `map_plugin_error` matches with `contains`, in a fixed order, so a
    /// second code anywhere in a message -- including one that wandered in
    /// from a system description -- would be read instead of the one the
    /// mutation meant. One code, first, is what makes that order irrelevant.
    func testEachMessageCarriesAtMostOneRecognizedCodeAndCarriesItFirst() {
        for (mutation, classify) in mutations {
            for status in failureStatuses {
                let message = classify(status)
                let carried = recognizedCodes.filter { message.contains($0) }

                XCTAssertLessThanOrEqual(carried.count, 1, "\(mutation) \(status): \(message)")
                if let code = carried.first {
                    XCTAssertTrue(
                        message.hasPrefix("\(code): "), "\(mutation) \(status): \(message)")
                }
            }
        }
    }

    // MARK: - What A Mutation Must Never Claim

    /// No mutation failure reports a changed enrollment. A store binds the new
    /// item to the enrollment the device is on as it writes it, so there is no
    /// older enrollment for a change to have invalidated, and a delete needs
    /// no authentication to remove an item that one did invalidate: neither
    /// has the stored enrollment `RetrievalFailure` compares against. Android
    /// reports it from its `storeSecret` because its KeyStore key outlives the
    /// write and a change invalidates it permanently; this item does not.
    func testNoMutationFailureReportsABiometricChange() {
        for (mutation, classify) in mutations {
            for status in failureStatuses {
                XCTAssertFalse(
                    classify(status).contains("BIOMETRIC_CHANGED"), "\(mutation) \(status)")
            }
        }
    }

    /// No mutation failure reports a missing secret either,
    /// `errSecItemNotFound` included: a write looks nothing up, and to a
    /// delete a missing item is success, so `NOT_FOUND` from either would have
    /// the embedding app conclude the vault is empty when the mutation is the
    /// only thing that went wrong.
    func testNoMutationFailureReportsAMissingSecret() {
        for (mutation, classify) in mutations {
            for status in failureStatuses {
                XCTAssertFalse(classify(status).contains("NOT_FOUND"), "\(mutation) \(status)")
            }
        }
    }
}
