#!/bin/bash
# The README's screenshots, from made-up data only. Builds the Python core's seeded 90-day demo export
# (docs/screenshots/make_screenshots.py there: 90 monitoring days, 90 nights, no real person), imports it with this
# repository's Rust core into a scratch store, and captures the app on that store: the Mac release bundle for the
# desktop shots, the kit's iOS simulator for the phone shots. Every capture is read before it is committed. The Today
# header prints the day the shot was taken, so a re-run differs there.
#
# Needs: the Python core checked out beside this repository (`../disconect` of the development tree; it is a separate
# repository, https://github.com/GuyShtainer/DISCOnect) with its .venv; the Rust core built in release
# (`cargo build --release` in ../../../core); the Mac bundle (`npx tauri build --bundles app`); for the phone
# shots a *debug* simulator build (`npx tauri ios build --debug --target aarch64-sim --ci`) and a booted iPhone
# simulator whose udid is passed as SIM_UDID with that build installed (`xcrun simctl install`). The phone shows an
# unencrypted store with no key file as "Pair with your Mac", so the phone store is encrypted first with the Python
# core's `disconect key init` (interactive; driven through a pty here, the recovery words are discarded) and the debug
# build unlocks it from DISCONECT_DEBUG_PASSPHRASE_FILE at start (release builds ignore that variable).
#
#   docs/screenshots/make_screenshots.sh            # the four Mac shots
#   SIM_UDID=<udid> docs/screenshots/make_screenshots.sh phone   # the four phone shots
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
app_dir="$(cd "$here/../.." && pwd)"
core_dir="$app_dir/../../core"      # standalone: ../core
python_core="$app_dir/../disconect"
what="${1:-mac}"
[ -d "$python_core/docs/screenshots" ] || { echo "the Python core's checkout is not at $python_core; its demo export generator is needed" >&2; exit 1; }
core="$core_dir/target/release/disconect-core"
[ -x "$core" ] || { echo "build the core first: cargo build --release in $core_dir" >&2; exit 1; }

tmp="$(mktemp -d -t disconect-shots)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/home" "$tmp/export"
( cd "$python_core" && .venv/bin/python -c '
import sys, pathlib; sys.path.insert(0, "docs/screenshots")
import make_screenshots as m; m.build_export(pathlib.Path(sys.argv[1]))' "$tmp/export" )
HOME="$tmp/home" "$core" --db "$tmp/demo.db" import "$tmp/export" >/dev/null
rm -f "$tmp/demo.db.write-lock"

# Keep only the chunks a PNG needs plus an sRGB tag: a raw capture carries the display's colour profile by name.
strip_png() {
  python3 - "$1" <<'EOF'
import struct, sys, zlib
p = sys.argv[1]; d = open(p, "rb").read(); out, i = [d[:8]], 8
def chunk(t, b): return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b) & 0xFFFFFFFF)
while i < len(d):
    n, = struct.unpack(">I", d[i:i + 4]); t = d[i + 4:i + 8]
    if t in (b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND"):
        out.append(d[i:i + 12 + n])
        if t == b"IHDR": out.append(chunk(b"sRGB", b"\x00"))
    i += 12 + n
open(p, "wb").write(b"".join(out))
EOF
}

screens=("today --screen today" "trends --screen trend --trend steps" "sleep --screen sleep/2025-06-30" "health --screen health --health-days 1825")

if [ "$what" = mac ]; then
  app="$app_dir/src-tauri/target/release/bundle/macos/disconect-app.app"
  [ -d "$app" ] || { echo "build the Mac bundle first: npx tauri build --bundles app" >&2; exit 1; }
  for s in "${screens[@]}"; do
    set -- $s; name=$1; shift
    HOME="$tmp/home" "$app/Contents/MacOS/disconect-app" --db "$tmp/demo.db" "$@" --theme light >/dev/null 2>&1 &
    pid=$!; sleep "${SETTLE:-7}"
    # Only the window owned by the process just launched: another copy of the app may be open on a real store.
    wid=$(osascript -l JavaScript -e "
      ObjC.import('CoreGraphics'); const l = \$.CGWindowListCopyWindowInfo(\$.kCGWindowListOptionOnScreenOnly, 0); let r = '';
      for (let i = 0; i < \$.CFArrayGetCount(l); i++) { const d = ObjC.castRefToObject(\$.CFArrayGetValueAtIndex(l, i));
        if (ObjC.unwrap(d.objectForKey('kCGWindowOwnerPID')) != $pid) continue; const nm = d.objectForKey('kCGWindowName');
        if (!nm.isNil() && String(ObjC.unwrap(nm)).length > 0) r = String(ObjC.unwrap(d.objectForKey('kCGWindowNumber'))); } r")
    [ -n "$wid" ] || { kill "$pid"; echo "no window for $name" >&2; exit 1; }
    out="$here/mac-$name.png"
    screencapture -x -o -l "$wid" "$out"; kill "$pid"; wait "$pid" 2>/dev/null || true
    sips -s format png --matchTo "/System/Library/ColorSync/Profiles/sRGB Profile.icc" "$out" --out "$out" >/dev/null
    strip_png "$out"; echo "wrote $out"
  done
else
  udid="${SIM_UDID:?set SIM_UDID to a booted simulator with the debug app installed}"
  app="$app_dir/src-tauri/gen/apple/build/arm64-sim/DISCOnect.app"
  bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Info.plist")
  # Encrypt the scratch store: `key init` asks for the passphrase twice, prints the 24 words, then asks two of them back.
  printf 'made-up store, screenshots only\n' > "$tmp/passphrase.txt"
  ( cd "$python_core" && HOME="$tmp/home" DISCONECT_DB="$tmp/demo.db" python3 - "$tmp/passphrase.txt" <<'EOF'
import os, pty, re, select, sys, time
pw = open(sys.argv[1]).read().strip().encode()
pid, fd = pty.fork()
if pid == 0:
    os.execv(".venv/bin/disconect", [".venv/bin/disconect", "key", "init"])
out, words, answered, t0 = b"", {}, set(), time.time()
while time.time() - t0 < 300:
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        try: chunk = os.read(fd, 4096)
        except OSError: break
        if not chunk: break
        out += chunk
        text = out.decode(errors="replace")
        for n, w in re.findall(r"(\d+)\.([a-z]+)", text): words[int(n)] = w
        tail = text.rstrip()
        m = re.search(r"Type word #(\d+):\s*$", tail)
        if m and m.group(1) not in answered:
            answered.add(m.group(1)); os.write(fd, words[int(m.group(1))].encode() + b"\n")
        elif tail.endswith("characters):") or tail.endswith("Repeat it:"):
            os.write(fd, pw + b"\n")
    elif os.waitpid(pid, os.WNOHANG)[0]:
        break
sys.exit(0 if b"database encrypted" in out else 1)
EOF
  ) || { echo "key init on the scratch store failed" >&2; exit 1; }
  export SIMCTL_CHILD_DISCONECT_DEBUG_PASSPHRASE_FILE="$tmp/passphrase.txt"
  xcrun simctl status_bar "$udid" override --time 9:41 --batteryState charged --batteryLevel 100 --cellularBars 4 --wifiBars 3
  data=$(xcrun simctl get_app_container "$udid" "$bundle_id" data)
  xcrun simctl terminate "$udid" "$bundle_id" 2>/dev/null || true
  dir="$data/Library/Application Support/$bundle_id"; mkdir -p "$dir"
  rm -f "$dir"/disconect.db "$dir"/disconect.db-wal "$dir"/disconect.db-shm "$dir"/disconect.db.keys.json "$dir"/disconect.db.write-lock
  cp "$tmp/demo.db" "$dir/disconect.db"; cp "$tmp/demo.db.keys.json" "$dir/disconect.db.keys.json"
  for s in "${screens[@]}"; do
    set -- $s; name=$1; shift
    xcrun simctl launch --terminate-running-process "$udid" "$bundle_id" "$@" --theme light >/dev/null
    sleep "${SETTLE:-6}"
    out="$here/phone-$name.png"
    xcrun simctl io "$udid" screenshot "$out" >/dev/null
    sips -s format png --matchTo "/System/Library/ColorSync/Profiles/sRGB Profile.icc" "$out" --out "$out" >/dev/null
    strip_png "$out"; echo "wrote $out"
  done
  xcrun simctl terminate "$udid" "$bundle_id" 2>/dev/null || true
fi
