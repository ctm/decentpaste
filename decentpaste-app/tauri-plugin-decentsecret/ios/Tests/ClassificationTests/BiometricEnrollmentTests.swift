import Foundation
import XCTest

import DecentsecretClassification

// MARK: - Biometric Enrollment Record

/// What the stored record encodes to, and what it refuses to decode.
///
/// Every refusal is load-bearing: `nil` is what tells the classification that
/// nothing can be concluded, which is what makes it fall through to the
/// keychain status. A record that decodes when it should not is how a false
/// `BIOMETRIC_CHANGED` gets made, and a false `BIOMETRIC_CHANGED` tells the
/// embedding app to write over a vault it never read.
final class BiometricEnrollmentTests: XCTestCase {

    /// The stored format, pinned: the magic, the major version in decimal, a
    /// colon, then the raw fingerprint and nothing else.
    func testTheStoredFormatIsMagicThenMajorThenFingerprint() throws {
        let fingerprint = Data([0xDE, 0xAD])
        let enrollment = try XCTUnwrap(
            BiometricEnrollment(osMajorVersion: 18, domainState: fingerprint))

        var expected = Data("decentsecret.enrollment.1:18:".utf8)
        expected.append(fingerprint)
        XCTAssertEqual(enrollment.encoded(), expected)
    }

    /// The fingerprint is opaque bytes, so the encoding has to survive bytes
    /// that look like the format's own punctuation.
    func testEveryFingerprintRoundTrips() throws {
        let fingerprints: [(String, Data)] = [
            ("a single zero byte", Data([0x00])),
            ("arbitrary bytes", Data([0xFF, 0x00, 0xFF])),
            // The record is split on the first colon after the magic, so a
            // fingerprint made of delimiters must come back whole.
            ("nothing but delimiters", Data(":::".utf8)),
            ("something that reads like a version", Data("18:not a version".utf8)),
            // A fingerprint that opens with the magic must not be mistaken
            // for the start of the record.
            ("the magic itself", Data("decentsecret.enrollment.1:19:inner".utf8)),
            ("every byte value", Data((0...255).map { UInt8($0) })),
        ]

        for major in [0, 1, 18, 19, Int.max] {
            for (name, fingerprint) in fingerprints {
                let enrollment = try XCTUnwrap(
                    BiometricEnrollment(osMajorVersion: major, domainState: fingerprint))
                XCTAssertEqual(
                    BiometricEnrollment(encoded: enrollment.encoded()), enrollment,
                    "\(major), \(name)")
            }
        }
    }

    /// An empty fingerprint is no fingerprint: it cannot be built at all, so
    /// neither side of the comparison can be holding one. The record that
    /// carries one is in the undecodable census below.
    func testAnEmptyFingerprintBuildsNoEnrollment() {
        XCTAssertNil(BiometricEnrollment(osMajorVersion: 18, domainState: Data()))
        XCTAssertNil(BiometricEnrollment.current(domainState: Data()))
    }

    /// `current` is the one place the running OS version is read, which is
    /// what leaves everything downstream a pure function of its arguments.
    func testCurrentRecordsTheRunningMajorVersion() throws {
        let fingerprint = Data([0x01])
        let enrollment = try XCTUnwrap(BiometricEnrollment.current(domainState: fingerprint))

        XCTAssertEqual(
            enrollment.osMajorVersion,
            ProcessInfo.processInfo.operatingSystemVersion.majorVersion)
        XCTAssertEqual(enrollment.domainState, fingerprint)
    }

    /// Everything that is not a record of this format, each of which the
    /// caller must read as inconclusive.
    func testWhatDoesNotDecode() {
        let refused: [(String, Data)] = [
            ("nothing at all", Data()),
            ("the bare fingerprint older builds wrote", Data([0xDE, 0xAD])),
            ("a bare fingerprint that happens to be text", Data("just-a-fingerprint".utf8)),
            ("a format version this build does not know", Data("decentsecret.enrollment.2:18:ff".utf8)),
            ("a record cut inside the magic", Data("decentsecret.enroll".utf8)),
            ("the magic and nothing else", Data("decentsecret.enrollment.1:".utf8)),
            ("a record cut before the version's colon", Data("decentsecret.enrollment.1:18".utf8)),
            ("an absent major version", Data("decentsecret.enrollment.1::ff".utf8)),
            ("a non-numeric major version", Data("decentsecret.enrollment.1:18a:ff".utf8)),
            ("a hexadecimal major version", Data("decentsecret.enrollment.1:0x12:ff".utf8)),
            ("a negative major version", Data("decentsecret.enrollment.1:-18:ff".utf8)),
            ("an explicitly signed major version", Data("decentsecret.enrollment.1:+18:ff".utf8)),
            ("a major version padded with a space", Data("decentsecret.enrollment.1: 18:ff".utf8)),
            ("a major version too large for Int",
                Data("decentsecret.enrollment.1:99999999999999999999:ff".utf8)),
            ("an empty fingerprint", Data("decentsecret.enrollment.1:18:".utf8)),
            ("a magic that differs in case", Data("Decentsecret.enrollment.1:18:ff".utf8)),
            ("junk ahead of the magic", Data("x decentsecret.enrollment.1:18:ff".utf8)),
        ]

        for (name, bytes) in refused {
            XCTAssertNil(BiometricEnrollment(encoded: bytes), "decoded \(name)")
        }
    }

    /// Both fields are part of the comparison: two fingerprints are the same
    /// enrollment only if they were read on the same major version.
    func testBothFieldsCount() throws {
        let eighteen = try XCTUnwrap(BiometricEnrollment(osMajorVersion: 18, domainState: Data([0x01])))
        let sameAgain = try XCTUnwrap(BiometricEnrollment(osMajorVersion: 18, domainState: Data([0x01])))
        let nineteen = try XCTUnwrap(BiometricEnrollment(osMajorVersion: 19, domainState: Data([0x01])))
        let other = try XCTUnwrap(BiometricEnrollment(osMajorVersion: 18, domainState: Data([0x02])))

        XCTAssertEqual(eighteen, sameAgain)
        XCTAssertNotEqual(eighteen, nineteen)
        XCTAssertNotEqual(eighteen, other)
    }
}
