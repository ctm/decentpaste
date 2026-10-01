import Foundation

// MARK: - Biometric Enrollment Record

/// The biometric enrollment a secret was stored under: `LAContext`'s
/// `evaluatedPolicyDomainState` fingerprint, together with the major OS version
/// the fingerprint was read on.
///
/// The OS version is part of the record because the fingerprint is only
/// comparable within one. `LAContext.h` warns of
/// `evaluatedPolicyDomainState`:
///
/// > Please note that the value returned by this property can change
/// > exceptionally between major OS versions even if the state of biometry has
/// > not changed.
///
/// So a major OS upgrade alone can change the fingerprint, and comparing
/// across majors would report a biometric change that never happened. The
/// iOS 18 replacement, `domainState.biometry.stateHash`, carries the same
/// warning verbatim, so this is a property of the mechanism rather than of the
/// chosen API, and recording the version is the fix regardless of which one is
/// read.
public struct BiometricEnrollment: Equatable {

    /// The major OS version the fingerprint was read on, e.g. 18 for iOS 18.2.
    public let osMajorVersion: Int

    /// The `evaluatedPolicyDomainState` fingerprint itself.
    public let domainState: Data

    public init(osMajorVersion: Int, domainState: Data) {
        self.osMajorVersion = osMajorVersion
        self.domainState = domainState
    }

    /// The enrollment as it stands on this device now, given the fingerprint
    /// just read from an `LAContext`.
    ///
    /// This is the one place the running OS version is read, so that
    /// everything downstream of it is a pure function of its arguments and can
    /// be tested on the host.
    public static func current(domainState: Data) -> BiometricEnrollment {
        BiometricEnrollment(
            osMajorVersion: ProcessInfo.processInfo.operatingSystemVersion.majorVersion,
            domainState: domainState)
    }

    // MARK: - Stored Encoding

    /// `magic` + the major version in decimal + `":"` + the raw fingerprint.
    ///
    /// The trailing `1` is the format version. A later format bumps it, which
    /// makes the record undecodable to this version of the code -- and an
    /// undecodable record is inconclusive, which is the safe direction.
    private static let magic = Array("decentsecret.enrollment.1:".utf8)

    private static let separator = UInt8(ascii: ":")

    /// The record as it is stored in the keychain.
    public func encoded() -> Data {
        var encoded = Data(Self.magic)
        encoded.append(Data("\(osMajorVersion):".utf8))
        encoded.append(domainState)
        return encoded
    }

    /// Decode a stored record, or `nil` if the bytes are not one.
    ///
    /// Returning `nil` is what makes the older form safe: builds before this
    /// one stored the bare fingerprint, with no version recorded, and those
    /// bytes do not decode. The caller must treat every `nil` as inconclusive
    /// -- an unknown OS version is exactly as uncomparable as a missing
    /// fingerprint -- and the same goes for a future format, a truncated
    /// record, or a major version too large for `Int`.
    public init?(encoded: Data) {
        let bytes = Array(encoded)
        guard bytes.starts(with: Self.magic) else { return nil }

        let versioned = bytes[Self.magic.count...]
        guard let separatorIndex = versioned.firstIndex(of: Self.separator) else { return nil }

        let digits = versioned[..<separatorIndex]
        guard digits.allSatisfy({ UInt8(ascii: "0") <= $0 && $0 <= UInt8(ascii: "9") }),
            let osMajorVersion = Int(String(decoding: digits, as: UTF8.self))
        else { return nil }

        // An empty fingerprint is no fingerprint: nothing can be concluded by
        // comparing it, so it must not decode either.
        let domainState = Data(versioned[versioned.index(after: separatorIndex)...])
        guard !domainState.isEmpty else { return nil }

        self.osMajorVersion = osMajorVersion
        self.domainState = domainState
    }
}
