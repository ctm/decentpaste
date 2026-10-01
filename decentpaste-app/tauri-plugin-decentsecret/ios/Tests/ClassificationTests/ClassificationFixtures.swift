import Foundation
import Security

// MARK: - Fixtures Shared By Both Classifications

/// The codes `map_plugin_error` matches on in `src/mobile.rs`, in the order it
/// tries them.
///
/// Declared once because both classification test files state the same
/// property of it -- at most one of these per message, in first place -- and
/// that property is only as strong as the list is complete. A copy per file
/// goes stale per file, and the stale copy stops checking for whichever code
/// the Rust side learned last.
let recognizedCodes = [
    "NOT_AVAILABLE",
    "MISCONFIGURED",
    "AUTH_FAILED",
    "BIOMETRIC_CHANGED",
    "NO_BIOMETRICS",
    "NOT_FOUND",
    "ACCESS_DENIED",
    "USER_CANCELLED",
]

/// Every status either classification might be handed: the arms they name, the
/// duplicate only a write sees, the not-found only a lookup means anything by,
/// several the system describes but neither side names, and one the system has
/// no message for at all.
///
/// The width is the point. Swept over the statuses a side already names, a
/// property can only say its named arms still read as they did; swept over
/// statuses neither names, it also says that an arm added for one of them
/// keeps the same rules -- or, stated across the two sides, that the arm was
/// not added to one side alone.
let keychainStatuses: [OSStatus] = [
    errSecItemNotFound,
    errSecUserCanceled,
    errSecAuthFailed,
    errSecNotAvailable,
    errSecMissingEntitlement,
    errSecInteractionNotAllowed,
    errSecDuplicateItem,
    errSecInvalidKeychain,
    errSecInvalidItemRef,
    errSecDecode,
    errSecParam,
    errSecAllocate,
    errSecIO,
    OSStatus(-1),
]
