# app — the DISCOnect shell for macOS and iPhone

A Tauri 2 window over the Rust core in `../core`. The Rust side of the shell is thin, except the `coach` module (the
only internet egress): it reaches one core speaking the serve protocol and relays JSON requests; the webview draws what
the core answers. The core is either a supervised child process (the sidecar) or the `disconect-core` library
**in-process** on a thread of the app:

| build | default core | why |
|---|---|---|
| debug (`npx tauri dev`, `npx tauri build --debug`) | in-process | no bundle to locate; the same code a phone runs |
| macOS release | sidecar (`resources/disconect-core/disconect-core` in the bundle) | a keychain item is bound to the program that made it, so the app shares one with `disconect-core mcp` only when the same binary runs both |
| iOS | in-process, the only choice | a phone cannot spawn a sidecar |

`--core inproc` (argv) selects in-process in any desktop build; `DISCONECT_CORE=inproc` does in a debug build (a path
there names a sidecar executable). A release build looks for `disconect-core` in its resources, then for an optional
`hearthbeat-core` (a packaged Python core, not built from this repository); `--core disconect|hearthbeat` picks exactly
one, and a missing core is an error, never a fallback. No environment variable and no path can choose the executable
in a release build. The release profile is `panic = "unwind"` so that a panic in the FIT parser on a malformed file
becomes a failed file (`catch_unwind` in the core's `fit.rs` and `serve.rs::import_worker`), not a crashed app;
`src-tauri/tests/inproc.rs` pins that.

## Layout
- `src-tauri/src/sidecar.rs` — spawn with an environment allowlist, request ids, per-method timeouts, one restart after
  a crash, stderr kept in a bounded buffer, the child killed on exit, the passphrase carried only as zeroised bytes.
- `src-tauri/src/inproc.rs` — the in-process core: a thread running `serve::Session`, request lines in through
  `serve::serve_lines`, whole protocol lines out to the same router the child's stdout feeds. The database path is
  passed in (desktop: `--db`, else the default `~/.disconect/disconect.db`; a phone: `app_data_dir()/disconect.db`).
  `examples/inproc_serve.rs` runs it over stdio.
- `src-tauri/src/ios.rs` — the iPhone start-up hook: the data folder and every file in it excluded from backups, the
  key file under `NSFileProtectionComplete`, keychain items left by an earlier install removed.
- `src-tauri/src/live.rs`, `live_phone.rs` — the Watch screen. Importing finished live-session files (`live-*.jsonl`)
  is the core's job; starting a Bluetooth session needs a separate client that is not published, so a release build
  answers `live_unavailable`.
- `src-tauri/tauri.ios.conf.json` — merged over `tauri.conf.json` on iOS only: no bundled core, display name
  `DISCOnect`, the placeholder identifier `org.disconect.app.dev` (replace it with your own). `src-tauri/Info.ios.plist`
  holds the iPhone's purpose strings (local network, camera for the pairing QR code) and `NSAllowsLocalNetworking`.
- `src-tauri/gen/apple/` — the Xcode project Tauri generated, with no signing team.
- `src/app.ts` — hash router and the screens; `src/charts.ts` — ECharts with tokens read at paint time (a missing day
  is `null`, never bridged; not-covered runs are hatched); `src/identity.ts` — the product name, the
  non-affiliation notice and the coach's fixed sentences (the only place they live on the UI side); `src/tokens.css`
  — design tokens (generated; do not edit by hand); `src/app.css` — layout, token-only.

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
address; **local** mode is held to those same hosts over either scheme; a URL with a user name or password is
refused; no proxy (`HTTP_PROXY` is never read); no redirects (a 3xx is an error); 10 s to connect, 120 s overall;
requests up to 1 MiB, answers up to 4 MiB; the request carries `Content-Type`, the bearer key when there is one, and
ureq's `Host`, `User-Agent` (`disconect-coach/<version>`) and `Accept`, nothing else (`tests/coach_egress.rs` reads
them off a real loopback socket). TLS is `rustls` with the operating system's trust store. Errors are a closed set
with fixed messages: a status number at most, never the provider's text, the address or the key. **The key** is in
the macOS keychain under the service `disconect-coach` or only in memory for the session; it is never in a file.
**The settings file** is `coach.json` in the app config folder: mode, address, model name, whether a key is in the
keychain, whether data points may be shared; nothing secret.

## Coach loop

`coach_ask(text)` in `src-tauri/src/coach/commands.rs` runs one question through `coach/loop.rs`. It first reads the
settings: **off returns before anything else** (no egress is built, the key is not read, nothing is sent). A turn
pushes the user's words and sends the request (the system prompt, the windowed turns and the tools of
`../core/mcp.json`, `tool_choice: auto`, no streaming) to `<base>/chat/completions`. If the model asks for tools (at
most 4 per answer and 6 rounds per question), each call must name one of the tools and carry a JSON object; the
arguments are forced inside the coach defaults, the core runs the tool, and the answer passes the projection, the
byte budget and the schema. Only that validated value becomes a tool message, so what leaves is the projected
day-level answer plus the user's own words. The model's reply is run through the vendor-name scrub before it is
shown. What the model hears about a call that did not run is one of a few fixed strings, never the core's message.
Each request is kept under a byte budget (96 KiB of JSON by default) by omitting earlier tool results, then the
oldest whole questions. **Nothing is persisted**: the conversation lives in memory and `coach_reset` clears it.

`coach_probe` (`coach/probe.rs`) asks the saved endpoint two made-up questions and runs no core call: whether the model
calls a tool, and whether the server cut a long prompt (a local server's default context is often small).

The **hand-off** (`coach/handoff.rs`) opens a chat site in your browser so that you can paste a day-level summary in
yourself; the app sends nothing. The **Support** screen (`coach/support.rs`) ships with no channel configured.

## Build, run, test

From this folder (the repository README has the whole sequence, including the core):

```sh
npm ci
npx tauri dev                       # debug, the core in-process
npx tauri build --bundles app       # release .app; stage ../core's release binary in src-tauri/resources/disconect-core/ first
npx tauri ios dev "iPhone 16"       # the iOS simulator
npx tsc --noEmit && npm run lint && npm run build
cargo test --manifest-path src-tauri/Cargo.toml
```

App arguments (after `--` with `tauri dev`, or `open … --args` for a bundle): `--db <path>` (use a scratch copy, never
your live store), `--screen <id>`, `--core inproc|disconect|hearthbeat`. Encryption: the app never shows recovery words
or creates a key; do that in a terminal with the Python core (`disconect key init`). The app unlocks with your
passphrase, or from the keychain if you turn that switch on. Keychain items are per code identity: the app and the
terminal each keep their own, and a rebuilt app forgets the app's copy.

`npm run lint` is the claims lint (`scripts/claims-lint.mjs` against `../CLAIMS-POLICY.md`). `third-party/` holds
`fitparser`'s MIT licence (the crates.io package ships none) and the iOS dependency licence list.

The macOS bundle is ad-hoc signed (no paid Apple account) and arm64 only. A copy that arrived with a quarantine flag
needs System Settings → Privacy & Security → "Open Anyway" once.

Not affiliated with or endorsed by any watch manufacturer.
