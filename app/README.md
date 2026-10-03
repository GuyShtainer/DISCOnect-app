# disconect-app — the DISCOnect desktop shell (macOS first)

Tauri 2 window over the core. Rust (the shell) is thin, except the `coach` module (Bet 15, ADR 0010; the only internet egress): it reaches one `serve`
core and relays JSON requests; the webview draws what the core answers. The core is either a
supervised child (the sidecar, ADR 0008) or `disconect-core` **in-process** on a thread of the app
(Bet 12a):

| build | default core | why |
|---|---|---|
| debug (`cargo run`, `tauri dev`, `tauri build --debug`) | in-process | no bundle to locate; the same code a phone runs |
| macOS release | sidecar (`disconect-core`, then `hearthbeat-core`) | the keychain item the app shares with `disconect-core mcp` is bound to the program that made it; an in-process release app would own a different item (kb/23 class 5) |
| iOS / Android (later) | in-process, the only choice | a phone cannot spawn a sidecar |

`--core inproc` (argv) selects in-process in any desktop build; `DISCONECT_CORE=inproc` does in a
debug build (a path there still names a sidecar executable). In-process the About card reads
`core disconect-core/<v> (in-process)`. In-process the core sees the app's own environment (the
sidecar gets an allowlist); the passphrase variable is still never read (`serve.rs` has no path to
it; a core test scans for one), and `DISCONECT_NOW` / `DISCONECT_KEYCHAIN` are test switches a
release `--core inproc` would honour. The release profile is `panic = "unwind"` so a panic in the
FIT parser on a malformed file becomes a failed file (`catch_unwind` in `fit.rs` and
`serve.rs::import_worker`), not a crashed app; `tests/inproc.rs` pins that.
The release bundle carries two cores: `disconect-core` (the Rust port, `../disconect-core`, the
default since Bet 11d) and `hearthbeat-core` (the PyInstaller Python core, kept as the rollback
and as the MCP server for Claude Desktop). Protocol: `../disconect/docs/serve-protocol.md`.

## Layout
- `src-tauri/src/sidecar.rs` — spawn with an env allowlist, request ids, per-method timeouts,
  one restart after a crash, stderr kept in a bounded buffer, child killed on exit, passphrase
  carried only as `Zeroizing` bytes.
  `locate_core`: release order `disconect-core` then `hearthbeat-core`; the app's own argv
  `--core disconect|hearthbeat` (parsed like `--db`) picks exactly one bundled core, an unknown
  name or a missing core is an error, never a fallback. No environment variable and no path can
  choose the executable in a release build (debug builds keep `DISCONECT_CORE` when no `--core`).
- `src-tauri/src/inproc.rs` — the in-process core: a thread running `serve::Session`, request lines in
  through `serve::serve_lines`, whole protocol lines out to the same router the child's stdout feeds.
  The database path is passed in (desktop: `--db`, else `home::resolve_default_db`; a phone:
  `app_data_dir()/disconect.db`). Never `isolate_stdout`, never `scrub_env_secrets`.
  `examples/inproc_serve.rs` runs it over stdio for `tools/serve_diff.py --inproc`.
- `src-tauri/tauri.ios.conf.json` — merged over `tauri.conf.json` on iOS only (JSON Merge Patch): no
  bundled core (`"resources": []` replaces the map), display name `DISCOnect`, dev identifier
  `org.disconect.app.dev`. Read by Tauri's own parser in `tests/mobile_config.rs`; never compiled
  for iOS here (no toolchain).
- `src-tauri/src/lib.rs` — Tauri commands `core_call`, `core_unlock`, `core_stderr`,
  `launch_args` (+ `debug_unlock_from_file` in debug builds only).
- `src/app.ts` — hash router and the four screens: Today, Trends, Data health, Your key.
  `src/charts.ts` — ECharts with tokens read at paint time; a missing day is `null`, never
  bridged; not-covered runs are hatched. `src/identity.ts` — the product name and the
  non-affiliation notice (the only place they live on the UI side). `src/tokens.css` — written
  by `../disconect/docs/design/gen_tokens.py`; `src/app.css` — layout, token-only.

## Coach projection

What the in-app coach may send to a model is decided in `src-tauri/src/coach/`, by three pure functions: `views::project`
(an allowlist: days, counts, numbers and a few closed vocabularies; no time of day, no free text, no file, device or
account identifier), `schema::validate` (a fail-closed positive schema: an unlisted key or an unknown string is an
error that never repeats the value) and `caps::fit` (a byte budget per tool, with the cuts named in the answer).
The contract answer is never sent. The table of kept and dropped fields, tool by tool, is the module doc of
`src-tauri/src/coach/views.rs`; the drawer that shows the user what the model can see cites it.

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
`disconect key cache` from the venv it will prompt. The durable rollback is to remove
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
Dev loop without the bundle: `npm run tauri dev` runs the core in-process (debug default). To test a
sidecar instead, `DISCONECT_CORE=/path/to/disconect-core` (debug builds only; a path, not `inproc`),
else `--core hearthbeat` finds `../disconect/.venv/bin/disconect-serve`.

Encryption: the app never shows recovery words or runs `key init`; do that in a terminal
(`disconect key init`). The app unlocks with your passphrase, or from the keychain if you turn
the switch on. Keychain items are per code identity: the app and the terminal each keep their
own, and an app update forgets the app's copy (cache again).

Debug evidence capture (in-process, scratch store): `npx tauri build --debug --bundles app`, then
`APP_ENV="DISCONECT_DEBUG_PASSPHRASE_FILE=<file>" APP_ARGS="--db <scratch> --core inproc --screen key"
tools/app-shot.sh <out.png> src-tauri/target/debug/bundle/macos/disconect-app.app` (the debug build
unlocks from that file at start; the release bundle is never rebuilt for this).

Tests: `cargo test` in `src-tauri` (bridge against a fake sidecar; `tests/inproc.rs`: in-process lines
byte-equal to the sidecar's, a malformed `.fit`, a core-thread panic, the passphrase variable;
`tests/mobile_config.rs`), `python tools/serve_diff.py --inproc --db <store>` after `cargo build
--example inproc_serve`, and
`cargo test --test real_core -- --ignored` with `DISCONECT_CORE`, `DISCONECT_TEST_DB` (a scratch
encrypted copy) and `DISCONECT_TEST_PASSPHRASE_FILE` set. Python-side lint for this app lives in
`../disconect/tests/test_lint_app.py` (no devtools, strict CSP, no colour literals).

Evidence captures: `tools/app-shot.sh` with `APP_ARGS`; PNGs go to `~/garmin-data/evidence/`.

Gatekeeper: the bundle is ad-hoc signed (no paid Apple account). A locally built .app opens
directly. A copy that arrived with a quarantine flag needs System Settings → Privacy & Security →
"Open Anyway" once (Sequoia removed the right-click bypass).

Not affiliated with or endorsed by any watch manufacturer.
