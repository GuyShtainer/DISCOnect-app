#!/usr/bin/env python3
"""A stand-in for the lab's live.py for evidence runs without a watch (DISCONECT_LIVE_LAB=<this file>).

Prints status lines and two synthetic readings, writes a synthetic live-<stamp>.jsonl into --raw-dir, waits for
stdin EOF (the app's stop) and prints a stopped line like the real lab. Synthetic values only. The readings are
fixed, so a second run writes a file with the same readings (the core answers DUPLICATE for it)."""
import argparse
import json
import pathlib
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
args = parser.parse_args()
args.raw_dir.mkdir(parents=True, exist_ok=True)
T0 = 1_700_000_000
readings = [{"t": T0, "metric": "heart_rate", "value": 61}, {"t": T0 + 1, "metric": "steps", "value": 1234}]
path = args.raw_dir / f"live-{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{time.monotonic_ns()}.jsonl"
with path.open("a") as raw:

    def emit(obj):
        line = json.dumps(obj)
        raw.write(line + "\n")
        raw.flush()
        print(line, flush=True)

    for status in ("scanning", "connecting", "connected"):
        emit({"status": status})
        time.sleep(0.3)
    for r in readings:
        emit(r)
        time.sleep(0.3)
    sys.stdin.read()  # until the app closes the pipe
    emit({"status": "stopped", "readings": {"heart_rate": 1, "steps": 1}, "seconds": 2})
