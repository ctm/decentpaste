# AGENTS.md

Compact guidance for OpenCode sessions in this repo. Prefer executable config and scripts over older prose.

## Repo Shape

- Main app: `decentpaste-app/` is a Tauri v2 app with vanilla TypeScript/Tailwind frontend and Rust backend.
- Rust workspace root `Cargo.toml` only includes `decentpaste-app/src-tauri`; local plugins are path dependencies, not workspace members.
- Website: `website/` is a separate static site package with its own `yarn.lock`, build script, and `.prettierrc`.
- Generated Tauri platform projects live under `decentpaste-app/src-tauri/gen/`; prefer editing Tauri/plugin source or config and regenerating.

## Commands

- App setup/dev: `cd decentpaste-app && yarn install && yarn tauri dev`.
- App frontend check/build: `cd decentpaste-app && yarn build` (`tsc && vite build`).
- App Rust check: `cd decentpaste-app/src-tauri && cargo check`.
- App Rust tests: `cd decentpaste-app/src-tauri && cargo test`; focused test: `cargo test <name>`.
- App Rust lints: `cd decentpaste-app/src-tauri && cargo clippy`.
- App formatting: `cd decentpaste-app && yarn format:fix`.
- Mobile dev/build: `cd decentpaste-app && yarn tauri android dev|build` or `yarn tauri ios dev|build`.
- Plugin JS bindings after `guest-js/` changes: `cd decentpaste-app/tauri-plugin-decentshare && yarn build`; same for `tauri-plugin-decentsecret`.
- Website: `cd website && yarn install && yarn build`; dev server: `yarn dev` on port 3000; format: `yarn format:fix`.
- No JS test script exists. Rust unit tests exist in backend modules; pairing/mobile/network behavior still needs manual multi-device testing.

## Entrypoints

- Frontend boot: `decentpaste-app/src/main.ts` initializes platform detection, app UI, share-intent handling, visibility changes, update checks.
- UI: `decentpaste-app/src/app.ts` is a single delegated-event-rendered `App` class; state lives in `src/state/store.ts`.
- IPC wrappers: `src/api/commands.ts` mirrors Rust commands; `src/api/events.ts` mirrors Rust-emitted event names.
- Backend boot: `src-tauri/src/lib.rs` registers Tauri plugins/commands, lifecycle handlers, network task, clipboard monitor, and event routing.
- Backend IPC: `src-tauri/src/commands.rs`; shared mutable state and vault flush helpers: `src-tauri/src/state.rs`.
- P2P behavior: `src-tauri/src/network/`; clipboard paths: `src-tauri/src/clipboard/`; crypto/pairing: `src-tauri/src/security/`; encrypted persistence: `src-tauri/src/vault/`.

## Tauri Patterns

- New command requires all three: Rust `#[tauri::command]` in `commands.rs`, registration in `lib.rs` `generate_handler!`, TS wrapper in `src/api/commands.ts`.
- New event requires Rust `app_handle.emit("event-name", payload)` and a typed listener entry in `src/api/events.ts`.
- Frontend user-facing Tauri calls should catch errors and format with `getErrorMessage()`.
- Keep command DTO casing intentional: Rust often uses snake_case internally; some DTOs use `#[serde(rename_all = "camelCase")]` for TS.

## Security And Sync Invariants

- Flush-on-write is mandatory for vault data. After mutating paired peers, clipboard history, or device identity, call the relevant `state.flush_*().await`; lifecycle flushes are only a safety net.
- Clipboard content is encrypted separately per paired peer with that peer's `shared_secret`; never reuse one ciphertext for multiple peers.
- Echo prevention depends on `ClipboardMonitor::set_last_hash()` after applying remote clipboard content.
- `ready_peers` means protocol readiness for receiving clipboard messages, currently gossipsub subscription readiness, not just an open TCP connection.
- For user-triggered sharing/refresh, prefer awaitable `ensure_connected()` paths over fire-and-forget `reconnect_peers()` so UI messages reflect delivery state.
- Offline sync is intentionally latest-only: `SYNC_MAX_BUFFER_SIZE = 1`, `SYNC_TTL_SECONDS = 5 minutes`, buffer is per recipient.
- Reject or double-check unpaired peers in sync/request handlers; security review should look for missing paired checks.

## Platform Gotchas

- Desktop close hides to tray instead of quitting; desktop also has auto-start, updater, single-instance, and `CommandOrControl+Shift+D` focus shortcut wiring.
- Mobile outgoing clipboard uses the system share sheet via `tauri-plugin-decentshare`; clipboard auto-monitoring is desktop-oriented.
- Mobile backgrounding drops connections. Visibility changes call `set_app_visibility`, flush vault data, reconnect peers, and process pending clipboard/share content on resume.
- If shared content arrives while the vault is locked, frontend stores it as `pendingShare` and sends after unlock.
- After `yarn tauri ios init`, rerun `cd decentpaste-app && ./tauri-plugin-decentshare/scripts/setup-ios-share-extension.sh`; it requires `xcodegen` and rewrites generated Apple project files.
- iOS share extension testing needs a physical device; Simulator is not reliable for share extension behavior.

## Releases And Versions

- Keep version values synchronized across `decentpaste-app/package.json`, `decentpaste-app/src-tauri/Cargo.toml`, `decentpaste-app/src-tauri/tauri.conf.json`, and `website/downloads.json`.
- CI release builds run from pushed tags `v*` using `.github/workflows/release.yml`; website deploys on `main`/`dev` changes under `website/**`.
- For iOS App Store/TestFlight archives, do not use `yarn tauri ios dev`; use `yarn tauri ios build`/Xcode archive or `yarn tauri ios build --export-method app-store-connect`.
- Repo-local Claude-format checklists in `.claude/skills/` contain useful release gotchas (`bump-version`, `android-release`, `ios-release`, `github-release`, iOS icon/screenshot helpers). Read them for release work, but adapt commands for OpenCode.

## Style And Commits

- App and website Prettier configs are identical: single quotes, 120 width, trailing commas.
- Use `store.set`, `store.update`, and `store.subscribe` instead of ad hoc frontend globals.
- Use Conventional Commits when asked to commit: `feat|fix|refactor|docs|chore|style(<scope>): <description>`.
- Architecture changes belong in `ARCHITECTURE.md`; security/threat-model changes belong in `SECURITY.md`; minor fixes usually need no docs.
