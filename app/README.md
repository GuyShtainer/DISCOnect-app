# disconect-app — the DISCOnect desktop shell (macOS first)

Tauri 2 window over the Python core. Rust holds no business logic: it supervises one
`hearthbeat serve` child (the sidecar, ADR 0008) and relays JSON requests; the webview draws
what the core answers. Protocol: `../hearthbeat/docs/serve-protocol.md`.

## Layout
- `src-tauri/src/sidecar.rs` — spawn with an env allowlist, request ids, per-method timeouts,
  one restart after a crash, stderr kept in a bounded buffer, child killed on exit, passphrase
  carried only as `Zeroizing` bytes.
- `src-tauri/src/lib.rs` — Tauri commands `core_call`, `core_unlock`, `core_stderr`,
  `launch_args` (+ `debug_unlock_from_file` in debug builds only).
- `src/app.ts` — hash router and the four screens: Today, Trends, Data health, Your key.
  `src/charts.ts` — ECharts with tokens read at paint time; a missing day is `null`, never
  bridged; not-covered runs are hatched. `src/identity.ts` — the product name and the
  non-affiliation notice (the only place they live on the UI side). `src/tokens.css` — written
  by `../hearthbeat/docs/design/gen_tokens.py`; `src/app.css` — layout, token-only.

## Build and run
```sh
tools/build-app.sh                 # PyInstaller sidecar -> tauri build -> .app -> ad-hoc sign
open src-tauri/target/release/bundle/macos/disconect-app.app
open ...disconect-app.app --args --db /path/to/copy.db --screen trend   # a scratch copy, never the live DB
```
Dev loop without the bundle: `npm run tauri dev` finds `../hearthbeat/.venv/bin/hearthbeat-serve`
(debug builds only) or `DISCONECT_CORE=/path/to/hearthbeat-serve`.

Encryption: the app never shows recovery words or runs `key init`; do that in a terminal
(`hearthbeat key init`). The app unlocks with your passphrase, or from the keychain if you turn
the switch on. Keychain items are per code identity: the app and the terminal each keep their
own, and an app update forgets the app's copy (cache again).

Tests: `cargo test` in `src-tauri` (bridge against a fake sidecar), and
`cargo test --test real_core -- --ignored` with `DISCONECT_CORE`, `DISCONECT_TEST_DB` (a scratch
encrypted copy) and `DISCONECT_TEST_PASSPHRASE_FILE` set. Python-side lint for this app lives in
`../hearthbeat/tests/test_lint_app.py` (no devtools, strict CSP, no colour literals).

Evidence captures: `tools/app-shot.sh` with `APP_ARGS`; PNGs go to `~/garmin-data/evidence/`.

Gatekeeper: the bundle is ad-hoc signed (no paid Apple account). A locally built .app opens
directly. A copy that arrived with a quarantine flag needs System Settings → Privacy & Security →
"Open Anyway" once (Sequoia removed the right-click bypass).

Not affiliated with or endorsed by any watch manufacturer.
