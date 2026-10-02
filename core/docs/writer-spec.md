# `writer` module — port spec (Bet 11 slice 1c)

Source of truth: `projects/hearthbeat/src/hearthbeat/ingest/writer.py`, `ingest/clock.py`,
`ingest/sources.py`, `storage/_time.py`. Python wins on any disagreement; fix this page.

## Time text
Every stored instant is `iso_utc(dt)` = `YYYY-MM-DDTHH:MM:SSZ` (seconds, no fraction, UTC).
`utc_now_iso()` = now in that shape. Dates are `YYYY-MM-DD` local to the watch (see clock).

## Raw retention (`_store_raw`)
`INSERT OR IGNORE INTO raw_records(stream, source_key, source_scope, transport, device_id,
start_utc, end_utc, payload_kind, payload, payload_hash, payload_bytes, decode_summary,
imported_at)`. For a FIT file: `source_key = payload_hash = sha256(file bytes) hex` (lowercase),
`payload_kind = "fit"`, `payload = zlib(bytes)` — Python uses level 6 and verifies the round
trip; the compressed bytes are **not** part of parity, the decompressed bytes and the hash are —
`payload_bytes = len(bytes)`, `decode_summary = json.dumps({"messages": message_counts,
"dropped": dropped, "warnings": warnings[:10]}, sort_keys=True)` (excluded from parity),
`transport` = the run's transport (`usb` for a GARMIN tree, else the CLI's `--transport`
default — read `cli.py`), `imported_at = now`. Duplicate test for FIT is **by source_key alone**:
`SELECT 1 FROM raw_records WHERE payload_kind='fit' AND source_key=?` → DUPLICATE before decode.
`INSERT OR IGNORE` returning no row → DUPLICATE too (rollback).

## `write_fit(bytes, label)` → IMPORTED | DUPLICATE | FAILED
1. `files_seen += 1`; duplicate check.
2. `decode_fit` → on `FitDecodeError`: `record_parse_failure(stream or "fit:undecodable", label,
   kind, message, start_utc, end_utc, payload_hash = sha256, placeable = stream is Some)` → FAILED.
   `record_parse_failure`: `files_failed += 1`; failures list entry {file: label, kind, error:
   redacted}; provenance(stream, "parse", ok=false, kind, message); `INSERT OR IGNORE INTO
   import_failures(run_id, stream, start_utc, end_utc, raw_record_id, payload_hash, kind,
   recorded_at)` with stream NULL when not placeable, raw_record_id NULL.
3. provenance(stream, "parse", ok=true).
4. `BEGIN`; `_store_raw` (None → ROLLBACK, DUPLICATE); `_write_canonical`; `COMMIT`. A storage
   error → ROLLBACK, `files_failed += 1`, failure {kind: "storage"}, provenance(stream, "write",
   false, "storage", msg) → FAILED.
5. provenance(stream, "write", true, records = written); `_account` (files_imported += 1,
   records_written += written, per-stream files/records, dropped reasons summed, first 3
   warnings kept up to 20) → IMPORTED.

## Provenance (`stream_provenance`)
`INSERT OR IGNORE INTO stream_provenance(stream, updated_at)`; ok: `UPDATE … SET
last_<stage>_ok_at=now, updated_at=now, files_ok = files_ok + (1 if stage == "write" else 0),
records_written = records_written + records`; failure: `last_<stage>_error_at=now,
last_<stage>_error_kind=kind, last_<stage>_error_message = redacted[:500], updated_at=now,
files_failed = files_failed + 1`. Stage ∈ {parse, write}. Parity compares the counters only.

## Canonical rows (`_write_canonical`) — `scope = decoded.source_scope`, `device = decoded.device_id`
- samples: `INSERT OR REPLACE INTO metric_samples(metric, ts_utc, value, source_scope, device_id,
  raw_record_id)`; note the sample span (min/max ts) and device for the derive step.
- daily facts: `date = fact.date or offsets.local_date(fact.ts_utc)`; `observed = iso(ts_utc)`;
  `_upsert_daily("daily_metrics", "value", …)`.
- labels: same into `daily_labels` with column `label`.
- intervals: `INSERT OR REPLACE INTO monitoring_intervals(ts_utc, activity_type, steps, cycles,
  active_time_s, active_calories_kcal, distance_m, intensity, source_scope, device_id,
  raw_record_id)`; note the interval span and device.
- sleep: `_write_sleep` (below).
- activities: `activity_id = f"{start}|{scope}|{device or ''}"`; `INSERT OR REPLACE INTO
  activities(activity_id, start_utc, end_utc, sport, sub_sport, total_timer_s, total_elapsed_s,
  distance_m, calories_kcal, avg_hr, max_hr, avg_speed_mps, total_ascent_m, total_descent_m,
  source_scope, device_id, raw_record_id)`.
- offsets: `INSERT OR REPLACE INTO clock_offsets(ts_utc, offset_s, device_id, raw_record_id)`.
- `written` = number of rows written (samples + upserts that returned 1 + intervals + sleep rows
  + activities + offsets).

### `_upsert_daily(table, column, date, metric, value, observed, scope, device, raw_id)` → 0|1
Key: `date, metric, source_scope, COALESCE(device_id,'') = device or ''`. No row → INSERT
(date, metric, value, observed_utc, source_scope, device_id, raw_record_id) → 1. Existing: if
both `observed` and the existing `observed_utc` are Some and `observed < existing` (string
compare of ISO text) → 0, else UPDATE value/observed_utc/raw_record_id → 1. **Equal observed
→ later write wins**, so file order is part of the contract.

### `_write_sleep(sleep, scope, device, raw_id)`
`date = sleep.date or offsets.local_date(sleep.end_utc)`; end None → stats.dropped
`sleep_without_date` += 1, return 0. `sleep_id = f"{date}|{scope}|{device or ''}"`; `DELETE
FROM sleep_stages WHERE sleep_id=?`; `INSERT OR REPLACE INTO sleep_sessions(…33 columns, retro
as 0/1…)`; stages `INSERT INTO sleep_stages(sleep_id, stage, start_utc, end_utc)`. written = 1 +
stages. Then `observed = iso(end_utc)`: overall_score Some → upsert `sleep_score` (float);
asleep = [deep_s, light_s, rem_s] that are Some → upsert `sleep_duration` = `round(sum/60, 1)`
(Python `round` = half-to-even on the binary double; match bit-for-bit by rounding the exact
decimal expansion of the double, or by reproducing Python's algorithm).

## Derived dailies (run once per batch, after all files)
### `derive_daily_steps()` — scope `local`
Skip when no intervals were written this run. Window = interval span ± 1 day on `ts_utc`
(ISO text BETWEEN). `first_day, last_day = local_date(span_lo − 1 s), local_date(span_hi − 1 s)`.
Per device seen this run: rows `SELECT ts_utc, activity_type, steps, distance_m, raw_record_id
FROM monitoring_intervals WHERE source_scope='device' AND COALESCE(device_id,'') = ? AND ts_utc
BETWEEN ? AND ?`; `date = local_date(ts − 1 s)` (the record stamped exactly at local midnight
closes the previous day); skip dates outside [first_day, last_day]; per (date, activity_type):
steps max (ignoring NULL), distance max; `latest[date]` = (max ts_utc text, its raw_record_id).
Per date: `steps` = `float(sum over types of max steps)` if any type has steps → upsert
`daily_metrics` ("steps", observed = latest ts, scope local, device, raw_id of latest);
`distance` likewise. Returns the number of step-days (also `stats.derived_days`).

### `derive_daily_from_samples()` — scope `local`
Skip when no samples were written. Window = sample span ± 1 day; `first_day, last_day =
local_date(span_lo), local_date(span_hi)` (no −1 s here). Per device, per source metric in
`DERIVED_FROM_SAMPLES` = (stress→stress_avg mean), (heart_rate→heart_rate_min min),
(heart_rate→heart_rate_max max), (energy_reserve→energy_reserve_high max), (…_low min),
(…_charged charged), (…_drained drained): rows `SELECT ts_utc, value, raw_record_id FROM
metric_samples WHERE metric=? AND source_scope='device' AND COALESCE(device_id,'') = ? AND
ts_utc BETWEEN ? AND ? ORDER BY ts_utc`; group by `local_date(ts)` within [first_day,
last_day]; `latest[date]` as above; value = `round(reducer(readings), 3)`.
Reducers over the day's (ts, value) list: mean = `sum / n` (Python 3.14 `sum` of floats is
Neumaier-compensated — reproduce that algorithm, not a naive loop), min, max; `charged` /
`drained`: sort by (ts, value); consecutive pairs with `t_b − t_a ≤ 15 min`; charged = sum of
positive differences, drained = sum of −(negative differences); the day's first reading has no
predecessor.

## Run bookkeeping
`begin_run`: `INSERT INTO import_runs(started_at, transport, status) VALUES(now, transport,
'running')`. `finish_run(error)`: `UPDATE import_runs SET finished_at, status, files_seen,
files_imported, files_duplicate, files_failed, records_written, error`; status = "failed" if
error, else `failed` when files_failed and no files_imported, `partial` when any failed, else
`ok`. The CLI prints `ok: N imported, M duplicate, K failed, R rows written` and per-stream
lines; counts only.

## Batch driver (`sources._import_fit_batch`)
For every file: `offsets.extend(scan_clock_offsets(bytes))` (ClockOffsets also pre-loaded from
the store's `clock_offsets` table at writer start — check `cli.py`/`sources.py` for the exact
load point); then `write_fit` per file in order; then `derive_daily_steps`;
`derive_daily_from_samples`. Labels passed to `write_fit` are PII-masked names
(`connect_export.mask_label`) — the Rust side can use the file's relative path with any `@…`
local-part masked the same way; labels never reach the tables except `import_failures`? (no:
failures keep `file: label` only in the run summary, not in a table).

## Parity checklist for `tools/core_diff.py`
Compare P and R on: `raw_records` (stream, source_key, source_scope, transport, device_id,
start_utc, end_utc, payload_kind, payload_hash, payload_bytes, inflate(payload)); `metric_samples`
(metric, ts_utc, value, source_scope, device_id, raw → (stream, source_key)); `daily_metrics` and
`daily_labels` (date, metric, value|label, observed_utc, source_scope, device_id, raw →);
`sleep_sessions` (all columns but id/raw id, raw →), `sleep_stages` (sleep_id, stage, start,
end); `monitoring_intervals` (all data columns, raw →); `activities`; `clock_offsets`;
`stream_provenance` (stream, files_ok, files_failed, records_written); `import_runs` (counters,
status); `import_failures` (stream, start, end, payload_hash, kind); `export_ranges`;
`schema_migrations` versions; `sqlite_master` DDL; `user_version`. Excluded: every `id`,
`*_at`, `observed_utc`? — no, `observed_utc` is compared; error messages, `decode_summary`.
