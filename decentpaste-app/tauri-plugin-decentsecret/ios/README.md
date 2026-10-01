# tauri-plugin-decentsecret (iOS)

The Swift package the iOS side of the plugin is built from. The plugin's own
API, permissions and cross-platform behaviour are in [../README.md](../README.md).

The plugin keeps two keychain items, both generic passwords under the service
`com.decentpaste.vault`: the secret itself, under the account `vault-key`,
written with `[.biometryCurrentSet]` so that a change to the device's biometric
enrollment invalidates it; and beside it a record of the enrollment the secret
was stored under, under the account `vault-key-domain-state`. The record
deliberately carries no access control, because a failed read has to be able to
consult it without the authentication that just failed -- which is what lets a
failure to retrieve the secret say whether the enrollment changed or the secret
was merely never there.

## Targets

- `tauri-plugin-decentsecret` (`Sources/`) is the `Plugin` subclass: everything
  that touches `Invoke`, `LAContext` or the keychain. It depends on Tauri,
  which is `../.tauri/tauri-api`, which only a `tauri ios` build generates, so
  this target does not build from a bare checkout.
- `DecentsecretClassification` (`Classification/`) holds the pure decisions:
  the enrollment record's encoding, and the classification of a keychain
  failure into the rejection string `src/mobile.rs` parses. It is deliberately
  dependency-free -- Foundation and Security, nothing else -- so that those
  decisions can be tested without Tauri, UIKit or a device.
- `DecentsecretClassificationTests` (`Tests/ClassificationTests/`) tests the
  classification and nothing else. It needs no simulator and no generated
  `tauri-api`, so `swift test` runs it on a host as soon as the package
  resolves.
