# `fit` module — port spec

Source of truth: `src/disconect/ingest/fit_wellness.py` of the Python core
(<https://github.com/GuyShtainer/DISCOnect>, the oracle) and the maintainer's unpublished name map of how
`fitparser` and `fitdecode` differ ("the name map" below). This page is the translation table;
when it and the Python disagree, the Python wins and this page is fixed.

## Shape of the output (`ingest/model.py`)
`Decoded { stream, source_scope = "device", device_id: Option<String>, start_utc, end_utc,
samples: Vec<Sample{metric, ts_utc, value: f64}>, daily: Vec<DailyFact{metric, value, ts_utc}>,
labels: Vec<DailyLabel{metric, label, ts_utc}>, intervals: Vec<MonitoringInterval{ts_utc,
activity_type, steps: Option<i64>, cycles: Option<f64>, active_time_s, active_calories_kcal:
Option<i64>, distance_m, intensity: Option<i64>}>, sleep: Option<SleepSession>, activities:
Vec<Activity>, offsets: Vec<ClockOffset{ts_utc, offset_s: i64}>, message_counts: BTreeMap<String,
u64>, dropped: BTreeMap<String, u64>, warnings: Vec<String> }`. `record_count()` = samples +
daily + labels + intervals + (sleep ? 1 + stages : 0) + activities + offsets.
`message_counts` is keyed by **fitdecode's** message name (`unknown_N` for unknown numbers): it
is stored in `raw_records.decode_summary` which the harness excludes, but keep the spelling so
`status` output matches.

## Parser setup (fitparser)
- `FitStreamProcessor` with `SkipHeaderCrcValidation` + `SkipDataCrcValidation`; iterate
  `deserialize_next`; a CRC mismatch is recorded as a warning string, not a failure.
- Any decode error → `FitDecodeError { kind: "unrecognized_payload", message, stream: Some(stream)
  only if `file_id` was already seen, start_utc: seen_min, end_utc: seen_max }` (partial span kept).
- **Dispatch by `(mesg_num, field_num)`.** Names below are documentation only.
- Field reading helpers, applied to every field: absent ≡ invalid ≡ `""` ≡ None (name map rules 2, 7);
  `date_time` with raw < `0x10000000` ≡ None; developer fields (`developer_data_index.is_some()`)
  are skipped; `Value::Timestamp` → UTC instant via `with_timezone(&Utc)`; **`local_date_time`
  fields are recovered as FIT seconds by inverting fitparser's anchor** (`dt −
  Local.from_local_datetime(1989-12-31T00:00:00)`), then treated as a *wall clock read as UTC*:
  `local = FIT_EPOCH_UTC + seconds`.
- `_text(enum)`: fitdecode gives the profile name when known, else the number as decimal text.
  fitparser's newer profile names more values (name map rule 1). For parity the port emits the
  **number as text** whenever fitdecode 0.11's profile would (list in the name map: sport 63/sub_sport
  77, event 78, file types 41/44/49/68/73/79 …); simplest correct rule: decode with
  `ReturnNumericEnumValues`, then map the number to a name through a small table of the enum
  names fitdecode knows for the five enums we store as text (`file_id.type`, `activity_type`,
  `sleep_level`, `event_type`, `spo2 mode`, `sport`, `sub_sport`, `hrv status`). The harness
  flags any other enum text, so the table only needs the values that occur.
- `_number`: ints and floats → f64; bools never. `_int`: `round()` half-to-even then i64.

## File-level state
`file_type: Option<String>` (text of `file_id.type`), `last_full: Option<DateTime>` (updated by
every message carrying field 253 `timestamp`, before the handler runs), `sleep_levels: Vec<(ts,
stage)>`, `sleep_start/sleep_end`, `assessment: Option<map>`, `seen_min/seen_max` (`_touch`).
`feed(frame)`: `message_counts[name] += 1`; update `last_full`; call the handler by message number.

## Handlers (message number → behaviour)
| # | name | reads | emits / effect |
|---|---|---|---|
| 0 | file_id | type(0), serial_number(3), time_created(4) | `file_type = text(type)`; `stream = FILE_TYPE_STREAMS[file_type]` or `fit:<type>` (`monitoring_b`→`fit:monitoring_b`, `49`→`fit:sleep`, `68`→`fit:hrv`, `73`→`fit:skin_temp`, `44`→`fit:metrics`, `activity`→`fit:activity`); `device_id = text(serial)`; `_touch(time_created)` |
| 103 | monitoring_info | timestamp(253), local_timestamp(0), resting_metabolic_rate(5) | `_offset(ts, local)` → `ClockOffset(ts, local_wall_as_utc − ts)`; if rmr > 0 → `DailyFact("resting_metabolic_rate", rmr, ts)` |
| 55 | monitoring | timestamp(253) else timestamp_16(26), heart_rate(27), activity_type(5 or component of 24), steps/cycles(3), active_time(4), active_calories(19), distance(2), intensity(28 or component of 24) | ts: full, else `expand_timestamp_16(ts16, last_full)` (signed 16-bit delta: `delta = (ts16 − (base & 0xFFFF)) & 0xFFFF; if delta > 0x7FFF: delta −= 0x10000`), drop `monitoring_without_timestamp` if neither; drop `timestamp_16_far_from_reference` (counted, record still processed) when |ts − last_full| > 3600 s; `_touch(ts)`; heart_rate > 0 → `Sample("heart_rate")`, == 0 → drop `heart_rate_zero`; steps = int(field 3 as `steps`) when the profile resolves the subfield, else None; cycles = number(field 3 as `cycles`) — **and (oracle fix d033021)** when steps is None, cycles is Some and activity_type ∈ {walking, running}: `steps = raw field 3`, `cycles = raw as f64` (fitparser resolves these itself: steps = raw; set cycles = raw too). For other types cycles = raw / 2 (scale 2). Interval appended only if activity_type is Some and any counter is Some. |
| 211 | monitoring_hr_data | timestamp, resting_heart_rate(0), current_day_resting_heart_rate(1) | each > 0 → `DailyFact("resting_heart_rate" / "resting_heart_rate_current_day", v, ts)` |
| 227 | stress_level | stress_level_time(1), stress_level_value(0), **field 3 raw** | ts from field 1 (a date_time); if field 3 raw is an int in 0..=100 → `_touch`, `Sample("energy_reserve", ts, v)` (emitted even on sentinel frames); value None → return; value < 0 → drop `stress_sentinel`; else `_touch`, `Sample("stress", ts, v)` |
| 297 | respiration_rate | timestamp, respiration_rate(0) | < 0 → drop `respiration_sentinel`; else `Sample("respiration_rate")` (no `_touch`) |
| 269 | spo2_data | timestamp, reading_spo2(0), mode(2) | mode == "off_wrist" or value ≤ 0 → drop `spo2_off_wrist_or_zero`; else `Sample("spo2")` (no `_touch`) |
| 275 | sleep_level | timestamp, sleep_level(0) | `_touch`; push (ts, stage text) |
| 346 | sleep_assessment | 14 fields (see `_SLEEP_ASSESSMENT_FIELDS`) | assessment map column → value (None kept as None) |
| 21 | event | timestamp, event(0), event_type(1) | only when `file_type == "49"` and `text(event) == "74"`: event_type "start" → sleep_start = ts; "stop" → sleep_end = ts |
| 370 | hrv_status_summary | timestamp, weekly_average(0), last_night_average(1), last_night_5_min_high(2), baseline_low_upper(3), baseline_balanced_lower(4), baseline_balanced_upper(5), status(6) | `_touch`; each Some → `DailyFact(metric per `_HRV_SUMMARY_FIELDS`)`; status text → `DailyLabel("hrv_status", status, ts)` |
| 371 | hrv_value | timestamp, value(0) | `Sample("hrv_rmssd")` |
| 398 | skin_temp_overnight | timestamp, local_timestamp(0), nightly_value(4) → `skin_temp_nightly`, average_deviation(1) → `skin_temp_deviation`, average_7_day_deviation(2) → `skin_temp_7day_deviation` | `_touch`; `_offset(ts, local)`; DailyFacts |
| 229 | max_met_data | update_time(0), vo2_max(2), sport(5) | vo2max None or ≤ 0 → return; `_touch(update_time)`; `DailyFact("vo2max")`; sport text → `DailyLabel("vo2max_sport")` |
| 162 | timestamp_correlation | timestamp(253), local_timestamp(3) | `_offset` |
| 18 | session | start_time(2), timestamp(253), sport(5), sub_sport(6), total_timer_time(8), total_elapsed_time(7), total_distance(9), total_calories(11), avg_heart_rate(16), max_heart_rate(17), enhanced_avg_speed(124) else avg_speed(14), total_ascent(22), total_descent(23) | start None → return; `_touch(start)`; `Activity{…}` with `_int` for calories/avg_hr/max_hr |

Field numbers above come from the FIT profile as fitparser exposes them (`FitDataField::number`);
verify each against a field dump of a real file before trusting this table.

## Finish (`result()`)
`_finish_sleep`: skip when no levels, no assessment and no start. Session(start=sleep_start,
end=sleep_end); levels sorted by (ts, stage); walk: `previous = start`; for each (end, stage):
previous None → drop `sleep_stage_without_start`; end > previous → stage(stage, previous, end);
else drop `sleep_stage_zero_length`; `previous = end` always. Totals in whole seconds per stage;
if any stage: deep_s/light_s/rem_s/awake_s = totals or 0 (others stay None). Assessment columns:
None skipped; `avg_stress` f64, all others i64. end None and stages → end = last stage end;
start None and stages → start = first stage start. `out.sleep = session`.
Then `start_utc/end_utc = seen_min/seen_max`; if sleep.end_utc is Some → `end_utc =
max(end_utc or sleep.end, sleep.end)`.

## `scan_clock_offsets(bytes) -> Vec<ClockOffset>`
Same decoder, only messages 103, 398, 162 fed; any error → empty vec; warnings ignored.

## Order and offsets (sources.py, clock.py)
Files in a folder: `sorted(rglob("*"))` by full relative path string; zip entries by name.
Batch: first pass `scan_clock_offsets` over every file into `ClockOffsets` (sorted moments;
an equal moment replaces the offset), then `write_fit` per file in that order, then
`derive_daily_steps`, `derive_daily_from_samples`. `offset_at(moment)`: nearest stated offset
by absolute time distance, ties → the earlier one (bisect_left then candidates index−1, index,
`min` keeps the first). `local_date(moment)` = (moment + offset).date(); with no offsets at all
offset 0 and `assumed_utc += 1`.
