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

## Coach egress

The coach is **off by default**, and while it is off no network client exists. When it is on, every byte that leaves
goes through one function, `egress::send` in `src-tauri/src/coach/egress.rs` (source and dependency guards in
`tests/egress_guards.rs` fail the build if anything else names a network type). The rules: `https://` to any host;
plain `http://` only to `localhost` or a literal loopback or private IP (127/8, ::1, 10/8, 172.16/12, 192.168/16,
fc00::/7, fe80::/10), so a DNS name over plain http is refused, which closes DNS rebinding without pinning an
address; **local** mode is held to those same hosts over either scheme (any other host is refused as
`local_needs_local_address`, so the "stays on your network" sentence is true and no cloud host skips the key rule); a
URL with a user name or password is refused; no proxy (`HTTP_PROXY` is never read); no redirects (a
3xx is an error); 10 s to connect, 120 s overall; requests up to 1 MiB, answers up to 4 MiB; the request carries
`Content-Type`, the bearer key when there is one, and ureq's `Host`, `User-Agent` (`disconect-coach/<version>`) and
`Accept`, nothing else (`tests/coach_egress.rs` reads them off a real loopback socket). TLS is `rustls` with the
operating system's trust store. Errors are a closed set with fixed messages: a status number at most, never the
provider's text, the address or the key. **The key** is in the macOS keychain under the service `disconect-coach`
(a quiet read, never a dialog; after a rebuild the old item reads as stale and the key is asked for again) or
only in memory for the session; it is never in a file. **The settings file** is `coach.json` in the app config folder
(never the data folder): mode, address, model name, whether a key is in the keychain, whether data points may be
shared; nothing secret.

## Coach loop

`coach_ask(text)` in `src-tauri/src/coach/commands.rs` runs one question through `chat_loop::Coach::ask` (`coach/loop.rs`).
It first reads the settings: **off returns before anything else** (no egress is built, the key is not read, nothing is
sent). A turn is: push the user's words; send the request (the system prompt, the windowed turns and the five tools
of `mcp.json`, `tool_choice: auto`, no streaming) to `<base>/chat/completions`; read the answer. If the model asks for
tools (at most 4 per answer and 6 rounds per question, else the question fails), each call must name one of the five
tools and carry a JSON object; the arguments are forced inside the coach defaults, the core runs the tool through
`tools.call`, and the answer passes `views::project_with`, `caps::fit` and `schema::validated`. Only that validated
value, as compact JSON, becomes a tool message (the type system allows nothing else), so what leaves is the projected
day-level answer plus the user's own words. The model's reply is run through the vendor-name scrub before it is
shown or kept.

What the model hears about a call that did not run is one of a few fixed strings, never the core's message or a raw
answer: `{"error":"unknown tool"}` (a name outside the five), `{"error":"bad arguments"}` (not a JSON object),
`{"error":"withheld"}` (the projection or schema refused the answer), and the core's own code
(`{"error":"locked"}`, `tool_error`, `invalid_params`, `unknown_tool`, `not_configured`). A locked store is
therefore not a failed question: the model is told and answers in words.

**The window.** Each request is kept under a byte budget (96 KiB of JSON by default): tool results from earlier
questions become `{"omitted":"earlier tool result"}` (the call/answer pairing stays valid, which providers require); if
the request is still too big the oldest whole questions are dropped, never the last two messages. An error ends the
question and rolls the conversation back to where it was (a provider status, an unreadable answer, too many tool calls,
a tool answer too large to send); every message of these errors is fixed text.

**Nothing is persisted.** The conversation lives in memory for the session and `coach_reset` clears it; the trace
returned with a reply (each tool call with the exact JSON that left, for the "what the model can see" drawer) replaces
itself on the next question. `tests/coach_loop.rs` proves the bytes: a scripted provider over the serve oracle's
answers, five evals, and one scenario replayed through the real egress against a `127.0.0.1` listener.

## Coach probe and screens

`coach_probe` (`src-tauri/src/coach/probe.rs`) asks the saved endpoint two made-up questions and runs no tool and no core
call, so it works on a locked store. Round 1 offers the five tools and reads whether the model calls one; round 2 sends a
filler of 12 000 tokens (4 bytes each, `max_tokens: 1`) and compares the endpoint's `usage.prompt_tokens` with it: under 85 %
means the server cut the prompt (Ollama reads 4k tokens unless `num_ctx` is raised). The screens are **Coach** (conversation,
the "what the model can see" drawer, first-use card, the disclaimer line on every visit) and **Coach settings** (mode,
address, model, key, test). Launch them with `--screen coach` or `--screen coach-settings`. Model text is drawn with
`textContent` only, after `neutralText()` in `src/identity.ts`; `tests/test_lint_app.py` bans markup-parsing APIs, and every
`invoke` call lives in `src/core.ts`. Layout notes: `../disconect/docs/design/coach-panel.md`.

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
