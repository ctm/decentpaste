import Foundation
import Security
import XCTest

import DecentsecretClassification

// MARK: - Retrieval Failure Classification

/// The rejection strings `src/mobile.rs` parses, and the one property the
/// whole mechanism turns on: nothing short of two present fingerprints, read
/// on the same major OS version, that differ may ever yield
/// `BIOMETRIC_CHANGED`.
///
/// The asymmetry is deliberate and is what most of this file pins. A missed
/// `BIOMETRIC_CHANGED` leaves the user re-enrolling a vault they can no
/// longer read; a false one tells the embedding app the vault holds nothing
/// readable, and the app writes over a vault it never read. Only the second
/// destroys data, so every inconclusive input must fall through to the
/// status.
final class RetrievalFailureTests: XCTestCase {

    // MARK: - Fixtures

    private let fingerprint = Data([0x01, 0x02, 0x03])
    private let otherFingerprint = Data([0x01, 0x02, 0x04])

    /// Every status worth passing: the five the classification names, two
    /// that fall to the default arm, and one the system has no message for.
    private let statuses: [OSStatus] = [
        errSecItemNotFound,
        errSecUserCanceled,
        errSecAuthFailed,
        errSecNotAvailable,
        errSecMissingEntitlement,
        errSecInvalidKeychain,
        errSecInteractionNotAllowed,
        OSStatus(-1),
    ]

    private func classify(
        _ status: OSStatus,
        stored: Data? = nil,
        current: BiometricEnrollment? = nil
    ) -> String {
        RetrievalFailure.classify(
            status: status, storedEnrollment: stored, currentEnrollment: current)
    }

    private func enrollment(_ major: Int, _ domainState: Data) throws -> BiometricEnrollment {
        try XCTUnwrap(BiometricEnrollment(osMajorVersion: major, domainState: domainState))
    }

    // MARK: - Status Arms

    /// Three of the named arms, whole: `map_plugin_error` matches on the prefix,
    /// so it stays first, and the number stays last.
    func testTheNamedStatusArms() {
        XCTAssertEqual(
            classify(errSecItemNotFound),
            "NOT_FOUND: No secret stored (OSStatus -25300)")
        XCTAssertEqual(
            classify(errSecUserCanceled),
            "USER_CANCELLED: User cancelled authentication (OSStatus -128)")
        XCTAssertEqual(
            classify(errSecAuthFailed),
            "AUTH_FAILED: Authentication failed (OSStatus -25293)")
    }

    /// The two statuses that mean the keychain itself is unusable, whole.
    /// Both are `NOT_AVAILABLE` and keep their own wording, because "no
    /// keychain at all" and "this build may not use the keychain" are the same
    /// thing to the embedding app and nothing alike to whoever has to fix it.
    func testTheUnavailableKeychainArms() {
        XCTAssertEqual(
            classify(errSecNotAvailable),
            "NOT_AVAILABLE: No keychain is available (OSStatus -25291)")
        XCTAssertEqual(
            classify(errSecMissingEntitlement),
            "NOT_AVAILABLE: This build has no keychain entitlement (OSStatus -34018)")
    }

    /// A retrieval and a mutation answer an unusable keychain identically.
    /// Naming those statuses on the mutation side only is what left a
    /// retrieval reporting them as an unprefixed plugin failure, and holding
    /// the messages equal is what keeps the two sides from parting again.
    func testBothSidesNameTheSameUnavailableStatuses() {
        for status in [errSecNotAvailable, errSecMissingEntitlement] {
            XCTAssertEqual(
                classify(status), KeychainMutation.storeFailure(status: status), "\(status)")
            XCTAssertEqual(
                classify(status), KeychainMutation.deleteFailure(status: status), "\(status)")
        }
    }

    /// The default arm quotes the system's description of the status, which is
    /// the system's wording to change, so only the shape around it is pinned:
    /// no code prefix, the fallback wording first, the number last.
    func testTheDefaultStatusArm() {
        let message = classify(errSecInvalidKeychain)

        XCTAssertTrue(message.hasPrefix("Failed to retrieve secret: "), message)
        XCTAssertTrue(message.hasSuffix(" (OSStatus -25295)"), message)
        XCTAssertFalse(message.contains("BIOMETRIC_CHANGED"), message)
    }

    /// iOS has no status that means "the item was invalidated", so which
    /// status a given failure really returns is only knowable by measuring it
    /// on a device, and the raw number is what makes such a report
    /// unambiguous. Pin the numbers the reports turn on.
    func testTheStatusNumbersAFieldReportNames() {
        XCTAssertEqual(errSecItemNotFound, -25300)
        XCTAssertEqual(errSecUserCanceled, -128)
        XCTAssertEqual(errSecAuthFailed, -25293)
        XCTAssertEqual(errSecInvalidKeychain, -25295)
    }

    /// The number is appended, never substituted, so a prefix the Rust side
    /// matches on cannot be pushed out of first place.
    func testTheStatusIsAppendedToWhateverTheReasonIs() {
        XCTAssertEqual(
            failureMessage("NOT_AVAILABLE: no biometric hardware", status: errSecAuthFailed),
            "NOT_AVAILABLE: no biometric hardware (OSStatus -25293)")
    }

    /// The default arm's description comes from the system, but it must be
    /// something: a bare "Failed to retrieve secret: " names no cause at all.
    func testEveryStatusHasADescription() {
        for status in statuses {
            XCTAssertFalse(securityErrorMessage(status).isEmpty, "\(status)")
        }
    }

    // MARK: - The Three Fingerprint Rows

    /// Two present, same-major, differing fingerprints: a changed enrollment,
    /// whatever the status says. The comparison comes ahead of the status
    /// deliberately, because iOS reports the invalidation with no
    /// distinguishable status -- `errSecItemNotFound` included, which is the
    /// status an invalidated item is most likely to come back as.
    func testDifferingSameMajorFingerprintsReportAChange() throws {
        let stored = try enrollment(18, fingerprint).encoded()
        let current = try enrollment(18, otherFingerprint)

        for status in statuses {
            let message = classify(status, stored: stored, current: current)
            XCTAssertTrue(
                message.hasPrefix(
                    "BIOMETRIC_CHANGED: Key invalidated due to biometric enrollment change"),
                "\(status): \(message)")
            XCTAssertTrue(message.hasSuffix(" (OSStatus \(status))"), "\(status): \(message)")
        }
    }

    /// Two present, same-major, equal fingerprints: the enrollment is the one
    /// the secret was stored under, so the failure is whatever the status
    /// says it is.
    func testEqualFingerprintsFallThroughToTheStatus() throws {
        let stored = try enrollment(18, fingerprint).encoded()
        let current = try enrollment(18, fingerprint)

        for status in statuses {
            XCTAssertEqual(
                classify(status, stored: stored, current: current), classify(status), "\(status)")
        }
    }

    /// Either side missing: no evidence of a change, so the status again.
    /// A missing stored record is every install made before the fingerprint
    /// was recorded; a missing current one is every device where biometry
    /// cannot be evaluated at all.
    func testEitherSideMissingFallsThroughToTheStatus() throws {
        let stored = try enrollment(18, fingerprint).encoded()
        let current = try enrollment(18, otherFingerprint)

        XCTAssertEqual(
            classify(errSecAuthFailed, stored: stored, current: nil),
            "AUTH_FAILED: Authentication failed (OSStatus -25293)")
        XCTAssertEqual(
            classify(errSecAuthFailed, stored: nil, current: current),
            "AUTH_FAILED: Authentication failed (OSStatus -25293)")
        XCTAssertEqual(
            classify(errSecAuthFailed, stored: nil, current: nil),
            "AUTH_FAILED: Authentication failed (OSStatus -25293)")
    }

    // MARK: - Never BIOMETRIC_CHANGED

    /// The census: every inconclusive input, against every status, answers
    /// exactly as it would with no fingerprints at all. Absent evidence is
    /// never evidence of a change.
    func testNoInconclusiveInputEverReportsAChange() throws {
        let hostMajor = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        let current = try enrollment(18, fingerprint)
        let genuine = try enrollment(18, otherFingerprint).encoded()

        let inconclusive: [(String, Data?, BiometricEnrollment?)] = [
            ("nothing stored and no current enrollment", nil, nil),
            ("nothing stored", nil, current),
            ("no current enrollment", genuine, nil),
            ("the bare fingerprint older builds wrote", otherFingerprint, current),
            ("an empty stored record", Data(), current),
            ("a format version this build does not know",
                Data("decentsecret.enrollment.2:18:ff".utf8), current),
            ("a record cut inside the magic", Data("decentsecret.enroll".utf8), current),
            ("a non-numeric major version", Data("decentsecret.enrollment.1:18a:ff".utf8), current),
            ("a negative major version", Data("decentsecret.enrollment.1:-18:ff".utf8), current),
            ("an explicitly signed major version",
                Data("decentsecret.enrollment.1:+18:ff".utf8), current),
            ("a major version too large for Int",
                Data("decentsecret.enrollment.1:99999999999999999999:ff".utf8), current),
            ("an empty stored fingerprint", Data("decentsecret.enrollment.1:18:".utf8), current),
            ("a fingerprint read on another major version",
                try enrollment(19, otherFingerprint).encoded(), current),
            // An empty current fingerprint builds no enrollment, so the
            // comparison is handed nil -- even here, beside a genuine record
            // of this very major version, which is the input a false
            // BIOMETRIC_CHANGED would otherwise come from.
            ("an empty current fingerprint",
                try enrollment(hostMajor, otherFingerprint).encoded(),
                BiometricEnrollment.current(domainState: Data())),
        ]

        for (name, stored, currentEnrollment) in inconclusive {
            for status in statuses {
                let message = classify(status, stored: stored, current: currentEnrollment)
                XCTAssertFalse(
                    message.contains("BIOMETRIC_CHANGED"), "\(name), \(status): \(message)")
                XCTAssertEqual(message, classify(status), "\(name), \(status)")
            }
        }
    }

    /// An empty current fingerprint, stated on its own because it is the one
    /// input that still reported a change once the stored side was closed: a
    /// genuine record of this device's major version, measured against a
    /// fingerprint of no bytes, is not a changed enrollment.
    func testAnEmptyCurrentFingerprintIsInconclusive() throws {
        let hostMajor = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        let stored = try enrollment(hostMajor, fingerprint).encoded()

        XCTAssertEqual(
            classify(
                errSecItemNotFound,
                stored: stored,
                current: BiometricEnrollment.current(domainState: Data())),
            "NOT_FOUND: No secret stored (OSStatus -25300)")
    }

    /// Fingerprints read on different major OS versions, stated on its own
    /// for the same reason: Apple warns the fingerprint "can change
    /// exceptionally between major OS versions even if the state of biometry
    /// has not changed", so across majors a difference says nothing, and an
    /// OS upgrade must not be able to announce a biometric change.
    func testADifferingFingerprintFromAnotherMajorVersionIsInconclusive() throws {
        let stored = try enrollment(18, fingerprint).encoded()
        let current = try enrollment(19, otherFingerprint)

        XCTAssertEqual(
            classify(errSecAuthFailed, stored: stored, current: current),
            "AUTH_FAILED: Authentication failed (OSStatus -25293)")
    }
}
