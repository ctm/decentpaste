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

    /// Every shape the enrollment pair comes in, with the one shape that is
    /// evidence of a change marked as such.
    ///
    /// On this side the message is a function of the pair as well as the
    /// status, so a property stated of one pair says nothing about the rest.
    /// The properties below are swept over all of them.
    private func enrollmentRows() throws -> [(String, Data?, BiometricEnrollment?, Bool)] {
        [
            ("no fingerprints at all", nil, nil, false),
            ("nothing stored", nil, try enrollment(18, fingerprint), false),
            ("no current enrollment", try enrollment(18, fingerprint).encoded(), nil, false),
            (
                "equal fingerprints", try enrollment(18, fingerprint).encoded(),
                try enrollment(18, fingerprint), false
            ),
            (
                "the bare fingerprint older builds wrote", fingerprint,
                try enrollment(18, otherFingerprint), false
            ),
            (
                "fingerprints read on different majors", try enrollment(19, fingerprint).encoded(),
                try enrollment(18, otherFingerprint), false
            ),
            (
                "differing same-major fingerprints", try enrollment(18, fingerprint).encoded(),
                try enrollment(18, otherFingerprint), true
            ),
        ]
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

    /// The two statuses that mean no retrieval can read this keychain, whole.
    /// They carry different codes because the embedding app acts on the
    /// difference: "no keychain at all" is a device to degrade quietly on, and
    /// "this build may not use the keychain" is a defect whoever installed the
    /// build needs told about.
    func testTheArmsNoRetrievalCanGetPast() {
        XCTAssertEqual(
            classify(errSecNotAvailable),
            "NOT_AVAILABLE: No keychain is available (OSStatus -25291)")
        XCTAssertEqual(
            classify(errSecMissingEntitlement),
            "MISCONFIGURED: This build has no keychain entitlement (OSStatus -34018)")
    }

    /// A retrieval and a mutation agree, status by status, on which statuses
    /// mean the keychain itself is unusable, and answer those identically.
    func testBothSidesAgreeOnWhichStatusesLeaveTheKeychainUnavailable() {
        assertBothSidesAgree(onPrefix: "NOT_AVAILABLE: ")
    }

    /// The same of the build's own defect. A missing entitlement belongs to
    /// the build whichever operation ran into it, so a side answering it with
    /// any other code -- `NOT_AVAILABLE`, as both sides did before the two
    /// were told apart -- fails here.
    func testBothSidesAgreeOnWhichStatusesMeanTheBuildIsMisconfigured() {
        assertBothSidesAgree(onPrefix: "MISCONFIGURED: ")
    }

    /// The shared-set property, stated of one code prefix.
    ///
    /// Naming a status on the mutation side only is what left a retrieval
    /// reporting it as an unprefixed plugin failure, so what has to be held is
    /// the *set*: an arm added to or dropped from one side alone is the defect,
    /// and pinning the messages of the statuses both sides already name cannot
    /// see it. Sweep every status either side might be handed and compare the
    /// two answers for the prefix, which fails on a one-sided arm for any
    /// status in the list; where both carry it, hold the whole message equal,
    /// which fails on wording that drifts apart.
    ///
    /// The two codes with a set to agree about are the two that name the
    /// environment -- a keychain this device cannot offer, and a build
    /// forbidden from using the one it has -- because neither is a property of
    /// the operation attempted. Nothing else is shared: `NOT_FOUND` is the
    /// retrieval's alone, and so is the enrollment comparison.
    private func assertBothSidesAgree(onPrefix prefix: String) {
        let carries = { (message: String) in message.hasPrefix(prefix) }

        for status in keychainStatuses {
            let retrieval = classify(status)

            for (mutation, message) in [
                ("store", KeychainMutation.storeFailure(status: status)),
                ("delete", KeychainMutation.deleteFailure(status: status)),
            ] {
                XCTAssertEqual(
                    carries(retrieval), carries(message),
                    "\(prefix) \(mutation) \(status): \(retrieval) / \(message)")
                if carries(retrieval) && carries(message) {
                    XCTAssertEqual(retrieval, message, "\(prefix) \(mutation) \(status)")
                }
            }
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
    /// status a device measurement shows an invalidated item comes back as,
    /// and which the test below pins on its own.
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

    /// The measured field case, pinned whole: `errSecItemNotFound` beside a
    /// differing same-major fingerprint.
    ///
    /// Measured on an iPhone -- secret stored, Face ID auto-login working, a
    /// Face ID alternative appearance added, the app relaunched -- the
    /// retrieval came back `errSecItemNotFound` rather than a refused
    /// authentication, because iOS deletes an enrollment-invalidated item
    /// instead of failing authentication on it. Of the statuses the sweep
    /// above passes, this is the one a real enrollment change arrives on, so
    /// a regression that let the status win here would answer a credential
    /// iOS had already wiped with `NOT_FOUND`, and the embedding app would
    /// set up a new vault over one it never read.
    func testTheMeasuredFieldCaseReportsAChange() throws {
        let stored = try enrollment(18, fingerprint).encoded()
        let current = try enrollment(18, otherFingerprint)

        XCTAssertEqual(
            classify(errSecItemNotFound, stored: stored, current: current),
            "BIOMETRIC_CHANGED: Key invalidated due to biometric enrollment change"
                + " (OSStatus -25300)")
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

    // MARK: - A Read That Returned Something Other Than Data

    /// A successful read whose result is not `Data`, whole: the fallback
    /// wording the Rust side keeps as a plugin failure, and the status that
    /// says the lookup itself succeeded.
    func testAnUnreadableSecretIsReportedWithTheStatusOfTheReadThatFoundIt() {
        XCTAssertEqual(
            RetrievalFailure.unreadableSecret(status: errSecSuccess),
            "Failed to retrieve secret: Secret data is corrupted (OSStatus 0)")
    }

    /// And it reports neither a missing secret nor a changed enrollment,
    /// whatever status the read came back with.
    ///
    /// Those are the two answers that authorise a write: `NOT_FOUND` says the
    /// vault is empty, which is writable, and `BIOMETRIC_CHANGED` says it can
    /// never be read again. An item whose payload will not read is neither --
    /// it is a vault nothing has read -- so this arm must keep clear of both.
    /// The sweep is over the statuses rather than `errSecSuccess` alone
    /// because the properties are of the arm, not of the one status that
    /// reaches it today.
    func testAnUnreadableSecretReportsNeitherAMissingSecretNorAChange() {
        for status in [errSecSuccess] + keychainStatuses {
            let message = RetrievalFailure.unreadableSecret(status: status)

            XCTAssertFalse(message.contains("NOT_FOUND"), "\(status): \(message)")
            XCTAssertFalse(message.contains("BIOMETRIC_CHANGED"), "\(status): \(message)")
            XCTAssertEqual(
                recognizedCodes.filter { message.contains($0) }, [], "\(status): \(message)")
            XCTAssertTrue(message.hasSuffix(" (OSStatus \(status))"), "\(status): \(message)")
        }
    }

    // MARK: - The Properties Every Message Keeps

    /// The number is appended, never substituted, so every report carries the
    /// raw status whichever arm it took -- the enrollment arm included, which
    /// is the one arm that names a cause the status does not.
    func testEveryRetrievalFailureCarriesItsNumericStatus() throws {
        for (row, stored, current, _) in try enrollmentRows() {
            for status in keychainStatuses {
                let message = classify(status, stored: stored, current: current)
                XCTAssertTrue(
                    message.hasSuffix(" (OSStatus \(status))"), "\(row), \(status): \(message)")
            }
        }
    }

    /// At most one recognized code per message, and in first place.
    ///
    /// `map_plugin_error` matches with `contains`, in a fixed order, so a
    /// second code anywhere in a message -- including one that wandered in
    /// from a system description, or one arm quoting another -- would be read
    /// instead of the one the retrieval meant. One code, first, is what makes
    /// that order irrelevant.
    func testEachRetrievalMessageCarriesAtMostOneRecognizedCodeAndCarriesItFirst() throws {
        for (row, stored, current, _) in try enrollmentRows() {
            for status in keychainStatuses {
                let message = classify(status, stored: stored, current: current)
                let carried = recognizedCodes.filter { message.contains($0) }

                XCTAssertLessThanOrEqual(carried.count, 1, "\(row), \(status): \(message)")
                if let code = carried.first {
                    XCTAssertTrue(message.hasPrefix("\(code): "), "\(row), \(status): \(message)")
                }
            }
        }
    }

    /// `errSecItemNotFound` and nothing else reports a missing secret.
    ///
    /// `NOT_FOUND` tells the embedding app the vault holds nothing readable,
    /// and the app then sets up a new one over a vault it never read, so an
    /// unreachable keychain, a refused authentication and a status this code
    /// does not name must all keep clear of it. That is why the arm takes one
    /// status, and why a new arm may not reach for the nearest code.
    func testOnlyItemNotFoundReportsAMissingSecret() throws {
        XCTAssertTrue(classify(errSecItemNotFound).hasPrefix("NOT_FOUND: "))

        for (row, stored, current, _) in try enrollmentRows() {
            for status in keychainStatuses where status != errSecItemNotFound {
                let message = classify(status, stored: stored, current: current)
                XCTAssertFalse(message.contains("NOT_FOUND"), "\(row), \(status): \(message)")
            }
        }
    }

    /// `errSecMissingEntitlement` and nothing else reports a misconfigured
    /// build, and the enrollment comparison still outranks it.
    ///
    /// `MISCONFIGURED` is the one code whose remedy is somebody rebuilding the
    /// app, so an arm reaching for it on another status reports a defect that
    /// is not there and sends whoever reads it looking for a provisioning
    /// mistake. The changed-enrollment row is the exception the grid carries:
    /// that row answers every status with `BIOMETRIC_CHANGED`, this one
    /// included, because an invalidation iOS reports under no status of its
    /// own is what the caller can act on, and a build with no entitlement
    /// could not have read the stored record to compare in the first place.
    func testOnlyAMissingEntitlementReportsAMisconfiguredBuild() throws {
        for (row, stored, current, isChange) in try enrollmentRows() {
            for status in keychainStatuses {
                let message = classify(status, stored: stored, current: current)
                XCTAssertEqual(
                    message.contains("MISCONFIGURED"),
                    status == errSecMissingEntitlement && !isChange,
                    "\(row), \(status): \(message)")
            }
        }
    }

    /// The enrollment pair decides whether a change is reported, and the
    /// status never does: across every status, each row answers the same way.
    ///
    /// The rows above pin the two cases that matter one at a time; this states
    /// the whole grid at once, which is the form the mutation side's "no
    /// failure reports a change" takes on a side that sometimes may. A status
    /// admitted as evidence either way -- an `errSecItemNotFound` taken for an
    /// invalidation, or taken as proof against one -- fails here.
    func testOnlyTheChangedEnrollmentRowReportsAChange() throws {
        for (row, stored, current, isChange) in try enrollmentRows() {
            for status in keychainStatuses {
                let message = classify(status, stored: stored, current: current)
                XCTAssertEqual(
                    message.contains("BIOMETRIC_CHANGED"), isChange,
                    "\(row), \(status): \(message)")
            }
        }
    }
}
