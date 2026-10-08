# Status

**v0, in progress.** Last updated 2026-10-09. This file says what is validated, on what, and what is not; the
README describes the features.

## Used on real data

- **The Mac app** is the maintainer's viewer of his own store: a release bundle built on 2026-10-03 carries an
  earlier version of this Rust core as its sidecar. That is use, not a test, and is not claimed as one.
- **The iPhone app**, installed on the maintainer's own phone as an unsigned build signed on the device by a
  sideloading tool (no paid developer account), **paired with the Mac once end to end on 2026-10-08**: QR code and
  six digits, then a pull of the whole store over the local network (four bundles, about 33 MB) into a 427 MB
  store on the phone in three to four minutes. The maintainer checked that the phone's Today screen matched the
  Mac's. A five-day trial of daily use started on 2026-10-08 and is not finished.
- That pairing ran on the maintainer's own store, encrypted with SQLCipher since 2026-10-06 (converted by the Python
  core; this core opens the same file with the same key file).

## Validated on synthetic data only

- Everything the test suites cover (counts in the README): decoding of synthesised FIT files against expected
  answers, the store, replay, the serve protocol, the MCP server, the relay (folder and LAN), pairing (known-answer
  vectors), the coach's egress rules against a loopback server, the iPhone start-up hook.
- In the private development tree, differential tests hold this core to the Python core's answers byte for byte on
  the same stores (`serve_diff`, `mcp_diff`, `core_diff`); those harnesses and the stores they run on are not
  published, and the tests that need them skip here.
- The iPhone-specific behaviour (keychain item bound to this device, backup exclusion, file protection, the app
  switcher cover, refused server roles) was measured in the iOS 18.1 simulator, not on the phone.
- Sync through a cloud-synced folder on a real phone is not tested.

## Not in this repository

- **Anything that talks to the watch over Bluetooth.** The live-link client that writes `live-*.jsonl` files is a
  separate, unpublished experiment. This app imports those files; a release build has no live link and says so on
  its Watch screen.
- **The Python core** is published separately (<https://github.com/GuyShtainer/DISCOnect>); key creation
  (`disconect key init`) is done there.
- **The maintainer's build scripts** (the signed release bundle with both cores, the IPA script) and the
  development notes; the README gives the plain commands instead.

## Not done

- No App Store or TestFlight build, no notarised Mac build; both apps are arm64 only and built on Apple silicon.
- Android is not started.
- The phone cannot offer a pairing or serve a relay (by design: the Mac does).
- The in-app licence screen for the iPhone build's dependencies is not built; the list is
  `app/third-party/ios-crates.md`.

## How this repository was made

The core and the app are developed inside a private monorepo beside the Python core. This repository is that
monorepo's history filtered down to the two directories (renamed `core/` and `app/`), then the standalone and
documentation commits on top. The planning notes, build products and personal data live outside those two
directories and are in no commit here. Commit messages and code comments keep the monorepo's development vocabulary
(plan, review and backlog names), which refer to documents that are not published. Commits are authored by the
maintainer under his GitHub no-reply address.
