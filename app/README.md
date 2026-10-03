# disconect-app — the DISCOnect desktop shell (macOS first)

Tauri 2 window over the core. Rust (the shell) holds no business logic: it supervises one `serve`
child (the sidecar, ADR 0008) and relays JSON requests; the webview draws what the core answers.
The release bundle carries two cores: `disconect-core` (the Rust port, `../disconect-core`, the
default since Bet 11d) and `hearthbeat-core` (the PyInstaller Python core, kept as the rollback
and as the MCP server for Claude Desktop). Protocol: `../hearthbeat/docs/serve-protocol.md`.

## Layout
- `src-tauri/src/sidecar.rs` — spawn with an env allowlist, request ids, per-method timeouts,
  one restart after a crash, stderr kept in a bounded buffer, child killed on exit, passphrase
  carried only as `Zeroizing` bytes.
  `locate_core`: release order `disconect-core` then `hearthbeat-core`; the app's own argv
  `--core disconect|hearthbeat` (parsed like `--db`) picks exactly one bundled core, an unknown
  name or a missing core is an error, never a fallback. No environment variable and no path can
  choose the executable in a release build (debug builds keep `DISCONECT_CORE` when no `--core`).
- `src-tauri/src/lib.rs` — Tauri commands `core_call`, `core_unlock`, `core_stderr`,
  `launch_args` (+ `debug_unlock_from_file` in debug builds only).
- `src/app.ts` — hash router and the four screens: Today, Trends, Data health, Your key.
  `src/charts.ts` — ECharts with tokens read at paint time; a missing day is `null`, never
  bridged; not-covered runs are hatched. `src/identity.ts` — the product name and the
  non-affiliation notice (the only place they live on the UI side). `src/tokens.css` — written
  by `../hearthbeat/docs/design/gen_tokens.py`; `src/app.css` — layout, token-only.

## Build and run
```sh
tools/build-app.sh                 # Rust + PyInstaller sidecars -> tauri build -> .app -> ad-hoc sign
tools/build-app.sh --rust-sidecar  # only the Rust sidecar (reuses the staged Python one)
open src-tauri/target/release/bundle/macos/disconect-app.app
open ...disconect-app.app --args --db /path/to/copy.db --screen trend   # a scratch copy, never the live DB
open -n ...disconect-app.app --args --core hearthbeat                   # rollback for one launch: the Python core
```
Rollback caveats: argv reaches the app only from a terminal launch (`open -n`, or quit first) —
Dock and Finder launches carry none, and `--args` sent to a running app is ignored. The Python
core reads the keychain with the macOS prompt allowed on every screen change, so after a
`hearthbeat key cache` from the venv it will prompt. The durable rollback is to remove
`Contents/Resources/disconect-core` from the bundle and re-sign (`codesign --force --deep -s -`):
the app then runs `hearthbeat-core` from Finder as before.
`build-app.sh` builds `disconect-core` with `cargo build --release --locked`, paths remapped
(`--remap-path-prefix` for `$HOME` and the repo root, passed as `RUSTFLAGS` because a committed
`.cargo/config.toml` cannot name one machine's absolute paths and Cargo's `trim-paths` is nightly-only;
it therefore does not apply to `cargo test --release`, which ships nothing), in
`/tmp/disconect-core-build` (OpenSSL's C code bakes its build directory into the binary, which the remap
cannot reach, so the build must not live under the repo). A `strings -a` guard fails the build if the binary
still holds `/Users/` or the repo folder's name. A missing binary or a failed build fails the script; there
is no silent fallback to Python. `app.info` is smoke-tested on the staged and on the bundled copies, and
`Contents/Resources/THIRD-PARTY.txt` carries fitparser's MIT licence (the crates.io package ships none; the
text is `third-party/fitparser-LICENSE.txt`), ADR 0007's Profile sentence and the dependency licences.

Both sidecars are **arm64-only** (built on this Apple-silicon Mac; no universal build, no Intel Mac).
Bundle size (`du -sh`): 60 MiB with the Python core alone, 72 MiB with both (Rust sidecar 11 MiB, Python
sidecar 56 MiB); `tools/core-timing.py` prints the same in MB (1e6 bytes).
Timing and size harness: `tools/core-timing.py`.
Dev loop without the bundle: `npm run tauri dev` uses `DISCONECT_CORE=/path/to/disconect-core` (debug
builds only), else `../hearthbeat/.venv/bin/hearthbeat-serve`.

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
