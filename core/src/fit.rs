// SPDX-License-Identifier: AGPL-3.0-or-later
//! Decode Garmin wellness FIT files into contract-shaped facts: the Rust twin of
//! `hearthbeat/ingest/fit_wellness.py` (the oracle; where this file and the Python disagree, the
//! Python wins).
//!
//! Parser: `fitparser` (MIT). Never Garmin's FIT SDK. Messages and fields are dispatched on
//! `(message number, field number)`, never on names (docs/kb/21): the names fitparser and
//! fitdecode give differ for anything their profile versions disagree on. The nine rules of
//! kb/21 map to helpers below: absent, invalid and empty-string values are all `None`; a
//! `date_time` below `0x10000000` is `None`; `local_date_time` values are recovered as FIT
//! seconds by inverting fitparser's host-zone anchor, so no result depends on the process zone;
//! CRCs are not validated by the parser and a mismatch is recorded as a warning instead.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use chrono::{DateTime, Duration, Local, NaiveDate, TimeZone, Utc};
use fitparser::de::{DecodeOption, FitObject, FitStreamProcessor};
use fitparser::profile::MesgNum;
use fitparser::profile::field_types::{ActivityType, EventType, Spo2MeasurementType};
use fitparser::{FitDataField, Value};

use crate::model::{
    Activity, ClockOffset, DailyFact, DailyLabel, Decoded, Instant, MonitoringInterval, Sample,
    SleepSession, SleepStage,
};

/// The decoder could not read the file; `kind` is a stable class for provenance.
///
/// `stream`, `start_utc` and `end_utc` carry whatever the decoder had learned before failing
/// (the file type once a `file_id` named one, the timestamps seen), so a failure can still be
/// placed on the coverage ledger. Each is `None` when the bytes broke before stating it.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{kind}: {message}")]
pub struct FitDecodeError {
    pub kind: String,
    pub message: String,
    pub stream: Option<String>,
    pub start_utc: Option<Instant>,
    pub end_utc: Option<Instant>,
}

/// `date_time` values below this are system uptime, not wall time (FIT profile).
const MIN_WALL_SECS: i64 = 0x1000_0000;

/// `stress_level` (message 227) field 3: the watch's own body-energy gauge, 0-100, one sample a
/// minute. Not named in the FIT profile; see the provenance note on `ENERGY_FIELD_NUM` in
/// `fit_wellness.py`.
const ENERGY_FIELD_NUM: u8 = 3;

/// `event.event` code that brackets a night in the sleep files. Not named in fitparser 0.11's
/// profile, so a plain number; every enum below is compared by number, never by the name text.
const SLEEP_EVENT_CODE: i64 = 74;
/// `file_id.type` of a sleep file (unnamed in the profile).
const FILE_TYPE_SLEEP: i64 = 49;
/// `file_id.type` of an HRV file.
const FILE_TYPE_HRV: i64 = 68;
/// `file_id.type` of a skin-temperature file.
const FILE_TYPE_SKIN_TEMP: i64 = 73;
/// `file_id.type` of a metrics file.
const FILE_TYPE_METRICS: i64 = 44;

const MSG_FILE_ID: u16 = 0;
const MSG_SESSION: u16 = 18;
const MSG_EVENT: u16 = 21;
const MSG_MONITORING: u16 = 55;
const MSG_MONITORING_INFO: u16 = 103;
const MSG_TIMESTAMP_CORRELATION: u16 = 162;
const MSG_MONITORING_HR_DATA: u16 = 211;
const MSG_MAX_MET_DATA: u16 = 229;
const MSG_STRESS_LEVEL: u16 = 227;
const MSG_SPO2_DATA: u16 = 269;
const MSG_SLEEP_LEVEL: u16 = 275;
const MSG_RESPIRATION_RATE: u16 = 297;
const MSG_SLEEP_ASSESSMENT: u16 = 346;
const MSG_HRV_STATUS_SUMMARY: u16 = 370;
const MSG_HRV_VALUE: u16 = 371;
const MSG_SKIN_TEMP_OVERNIGHT: u16 = 398;

const FIELD_TIMESTAMP: u8 = 253;

/// Sleep assessment fields by number, in the order of `Assessment::values`.
const ASSESSMENT_FIELDS: [u8; 14] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 15];

/// (field number, metric) pairs of `hrv_status_summary` that become daily facts.
const HRV_SUMMARY_FIELDS: [(u8, &str); 6] = [
    (0, "hrv_weekly_average"),
    (1, "hrv_last_night_average"),
    (2, "hrv_last_night_5min_high"),
    (3, "hrv_baseline_low_upper"),
    (4, "hrv_baseline_balanced_lower"),
    (5, "hrv_baseline_balanced_upper"),
];

/// (field number, metric) pairs of `skin_temp_overnight` that become daily facts.
const SKIN_TEMP_FIELDS: [(u8, &str); 3] = [
    (4, "skin_temp_nightly"),
    (1, "skin_temp_deviation"),
    (2, "skin_temp_7day_deviation"),
];

fn fit_epoch() -> Instant {
    // 1989-12-31T00:00:00Z
    DateTime::<Utc>::from_timestamp(631_065_600, 0).unwrap_or(DateTime::UNIX_EPOCH)
}

fn from_fit_secs(secs: i64) -> Instant {
    fit_epoch() + Duration::seconds(secs)
}

/// Rebuild a full timestamp from FIT's 16-bit compressed form.
///
/// The low 16 bits are relative to the last full timestamp in the stream. The delta is read as
/// signed so a reference written slightly *after* the sample (an event marker) does not push
/// the sample eighteen hours into the future.
pub fn expand_timestamp_16(timestamp_16: i64, last_full: Instant) -> Instant {
    let base = (last_full - fit_epoch()).num_seconds();
    let mut delta = (timestamp_16 - (base & 0xFFFF)) & 0xFFFF;
    if delta > 0x7FFF {
        delta -= 0x1_0000;
    }
    last_full + Duration::seconds(delta)
}

/// A decoded number that may have been an integer or a float on the wire.
#[derive(Debug, Clone, Copy)]
enum Num {
    Int(i64),
    Float(f64),
}

impl Num {
    fn as_i64(self) -> i64 {
        match self {
            Num::Int(v) => v,
            Num::Float(v) => v as i64,
        }
    }

    fn as_f64(self) -> f64 {
        match self {
            Num::Int(v) => v as f64,
            Num::Float(v) => v,
        }
    }
}

fn integer_of(value: &Value) -> Option<i64> {
    match value {
        Value::Enum(v) | Value::UInt8(v) | Value::UInt8z(v) => Some(i64::from(*v)),
        Value::SInt8(v) => Some(i64::from(*v)),
        Value::SInt16(v) => Some(i64::from(*v)),
        Value::UInt16(v) | Value::UInt16z(v) => Some(i64::from(*v)),
        Value::SInt32(v) => Some(i64::from(*v)),
        Value::UInt32(v) | Value::UInt32z(v) => Some(i64::from(*v)),
        Value::SInt64(v) => Some(*v),
        Value::UInt64(v) | Value::UInt64z(v) => i64::try_from(*v).ok(),
        _ => None,
    }
}

fn number_of(value: &Value) -> Option<Num> {
    match value {
        Value::Float32(v) => Some(Num::Float(f64::from(*v))),
        Value::Float64(v) => Some(Num::Float(*v)),
        Value::Byte(v) => Some(Num::Int(i64::from(*v))),
        Value::UInt64(v) | Value::UInt64z(v) => Some(
            i64::try_from(*v)
                .map(Num::Int)
                .unwrap_or(Num::Float(*v as f64)),
        ),
        other => integer_of(other).map(Num::Int),
    }
}

/// The host-zone anchor fitparser adds `local_date_time` seconds to.
fn local_anchor() -> Option<DateTime<Local>> {
    let naive = NaiveDate::from_ymd_opt(1989, 12, 31)?.and_hms_opt(0, 0, 0)?;
    Local.from_local_datetime(&naive).single()
}

/// One message's native (non-developer) fields, read the way the Python `_value` helpers read
/// them: absent, invalid and empty-string values are all `None`.
struct View<'a> {
    fields: Vec<&'a FitDataField>,
}

impl<'a> View<'a> {
    fn find(&self, number: u8) -> Option<&'a Value> {
        self.fields
            .iter()
            .filter(|f| f.number() == number)
            .map(|f| f.value())
            .find(|v| match v {
                Value::Invalid => false,
                Value::String(s) => !s.is_empty(),
                _ => true,
            })
    }

    /// `_number`: ints and floats, never bools.
    fn number(&self, number: u8) -> Option<f64> {
        self.find(number).and_then(number_of).map(Num::as_f64)
    }

    fn num(&self, number: u8) -> Option<Num> {
        self.find(number).and_then(number_of)
    }

    /// `_int`: the number rounded half to even.
    fn int(&self, number: u8) -> Option<i64> {
        self.number(number).map(|v| v.round_ties_even() as i64)
    }

    /// An integer exactly as it came off the wire (no rounding of floats).
    fn raw_int(&self, number: u8) -> Option<i64> {
        self.find(number).and_then(integer_of)
    }

    /// `_text`: the profile name when the parser knows one, else the number as decimal text.
    fn text(&self, number: u8) -> Option<String> {
        match self.find(number)? {
            Value::String(s) => Some(s.clone()),
            other => integer_of(other).map(|n| n.to_string()),
        }
    }

    /// A `date_time` field as a UTC moment; `None` below `0x10000000`.
    fn instant(&self, number: u8) -> Option<Instant> {
        let Value::Timestamp(dt) = self.find(number)? else {
            return None;
        };
        let secs = (dt.with_timezone(&Utc) - fit_epoch()).num_seconds();
        (secs >= MIN_WALL_SECS).then(|| from_fit_secs(secs))
    }

    /// A `local_date_time` field as a wall clock read as UTC: the FIT seconds are recovered by
    /// inverting fitparser's host-zone anchor, so the result does not depend on the process zone.
    fn local_wall(&self, number: u8) -> Option<Instant> {
        let Value::Timestamp(dt) = self.find(number)? else {
            return None;
        };
        let secs = (*dt - local_anchor()?).num_seconds();
        (secs >= MIN_WALL_SECS).then(|| from_fit_secs(secs))
    }
}

/// What the stream processor knew about a message before decoding changed it.
#[derive(Default)]
struct Raw {
    /// `monitoring` field 3 as it came off the wire (the profile rescales it per activity type,
    /// and which way depends on field order inside fitparser, so the raw value is read instead).
    cycles: Option<i64>,
    /// Every native integer field as it came off the wire, by field number: the enum fields are
    /// compared here by number, so a profile that later names a value cannot change behaviour.
    numbers: BTreeMap<u8, i64>,
}

impl Raw {
    fn number(&self, field: u8) -> Option<i64> {
        self.numbers.get(&field).copied()
    }
}

struct State {
    out: Decoded,
    file_type: Option<String>,
    file_type_number: Option<i64>,
    last_full: Option<Instant>,
    sleep_levels: Vec<(Instant, String)>,
    sleep_start: Option<Instant>,
    sleep_end: Option<Instant>,
    assessment: Option<[Option<Num>; 14]>,
    seen_min: Option<Instant>,
    seen_max: Option<Instant>,
}

impl State {
    fn new() -> Self {
        State {
            out: Decoded::new("fit:unknown", "device"),
            file_type: None,
            file_type_number: None,
            last_full: None,
            sleep_levels: Vec::new(),
            sleep_start: None,
            sleep_end: None,
            assessment: None,
            seen_min: None,
            seen_max: None,
        }
    }

    fn touch(&mut self, moment: Instant) {
        if self.seen_min.is_none_or(|m| moment < m) {
            self.seen_min = Some(moment);
        }
        if self.seen_max.is_none_or(|m| moment > m) {
            self.seen_max = Some(moment);
        }
    }

    /// A (timestamp, local timestamp) pair states the watch's UTC offset.
    fn offset(&mut self, ts_utc: Option<Instant>, local: Option<Instant>) {
        if let (Some(ts), Some(local)) = (ts_utc, local) {
            self.out.offsets.push(ClockOffset {
                ts_utc: ts,
                offset_s: (local - ts).num_seconds(),
            });
        }
    }

    fn daily(&mut self, metric: &str, value: f64, ts_utc: Instant) {
        self.out.daily.push(DailyFact {
            metric: metric.to_string(),
            value,
            ts_utc: Some(ts_utc),
            date: None,
        });
    }

    fn sample(&mut self, metric: &str, ts_utc: Instant, value: f64) {
        self.out.samples.push(Sample {
            metric: metric.to_string(),
            ts_utc,
            value,
        });
    }

    fn label(&mut self, metric: &str, label: String, ts_utc: Instant) {
        self.out.labels.push(DailyLabel {
            metric: metric.to_string(),
            label,
            ts_utc: Some(ts_utc),
            date: None,
        });
    }

    // ---- per-message handlers ----

    fn file_id(&mut self, v: &View, raw: &Raw) {
        self.file_type = v.text(0);
        self.file_type_number = raw.number(0);
        // `FILE_TYPE_STREAMS` maps these types; every other type is `fit:<type>`. A missing type
        // reads "None", exactly as the oracle's f-string does.
        let label = stream_label(self.file_type_number, self.file_type.as_deref());
        self.out.stream = format!("fit:{label}");
        self.out.device_id = v.text(3);
        if let Some(created) = v.instant(4) {
            self.touch(created);
        }
    }

    fn monitoring_info(&mut self, v: &View) {
        let ts_utc = v.instant(FIELD_TIMESTAMP);
        self.offset(ts_utc, v.local_wall(0));
        if let (Some(ts), Some(rmr)) = (ts_utc, v.number(5))
            && rmr > 0.0
        {
            self.daily("resting_metabolic_rate", rmr, ts);
        }
    }

    fn monitoring(&mut self, v: &View, raw: &Raw) {
        let ts_utc = match v.instant(FIELD_TIMESTAMP) {
            Some(ts) => ts,
            None => {
                let (Some(ts16), Some(base)) = (v.raw_int(26), self.last_full) else {
                    self.out.drop("monitoring_without_timestamp");
                    return;
                };
                let expanded = expand_timestamp_16(ts16, base);
                if (expanded - base).num_seconds().abs() > 3600 {
                    self.out.drop("timestamp_16_far_from_reference");
                }
                expanded
            }
        };
        self.touch(ts_utc);
        if let Some(heart_rate) = v.number(27) {
            if heart_rate > 0.0 {
                self.sample("heart_rate", ts_utc, heart_rate);
            } else {
                self.out.drop("heart_rate_zero");
            }
        }
        let activity_type = v.text(5);
        // `monitoring.cycles` carries steps (scale 1) for walking and running and half-steps
        // (scale 2) otherwise; a record that resolves to steps reports it under both names.
        let (steps, cycles) = match raw.cycles {
            Some(r)
                if matches!(
                    activity_type.as_deref().and_then(activity_type_number),
                    Some(n) if n == i64::from(ActivityType::Walking.as_u8())
                        || n == i64::from(ActivityType::Running.as_u8())
                ) =>
            {
                (Some(r), Some(r as f64))
            }
            Some(r) => (None, Some(r as f64 / 2.0)),
            None => (None, None),
        };
        let active_time_s = v.number(4);
        let active_calories_kcal = v.int(19);
        let distance_m = v.number(2);
        let any = steps.is_some()
            || cycles.is_some()
            || active_time_s.is_some()
            || active_calories_kcal.is_some()
            || distance_m.is_some();
        if let (Some(activity_type), true) = (activity_type, any) {
            self.out.intervals.push(MonitoringInterval {
                ts_utc,
                activity_type,
                steps,
                cycles,
                active_time_s,
                active_calories_kcal,
                distance_m,
                intensity: v.int(28),
            });
        }
    }

    fn monitoring_hr_data(&mut self, v: &View) {
        let Some(ts) = v.instant(FIELD_TIMESTAMP) else {
            return;
        };
        for (field, metric) in [
            (0, "resting_heart_rate"),
            (1, "resting_heart_rate_current_day"),
        ] {
            if let Some(value) = v.number(field)
                && value > 0.0
            {
                self.daily(metric, value, ts);
            }
        }
    }

    fn stress_level(&mut self, v: &View) {
        let Some(ts) = v.instant(1) else {
            return;
        };
        if let Some(energy) = v.raw_int(ENERGY_FIELD_NUM)
            && (0..=100).contains(&energy)
        {
            self.touch(ts);
            self.sample("energy_reserve", ts, energy as f64);
        }
        let Some(value) = v.number(0) else {
            return;
        };
        if value < 0.0 {
            self.out.drop("stress_sentinel");
            return;
        }
        self.touch(ts);
        self.sample("stress", ts, value);
    }

    fn respiration_rate(&mut self, v: &View) {
        let (Some(ts), Some(value)) = (v.instant(FIELD_TIMESTAMP), v.number(0)) else {
            return;
        };
        if value < 0.0 {
            self.out.drop("respiration_sentinel");
            return;
        }
        self.sample("respiration_rate", ts, value);
    }

    fn spo2_data(&mut self, v: &View, raw: &Raw) {
        let (Some(ts), Some(value)) = (v.instant(FIELD_TIMESTAMP), v.number(0)) else {
            return;
        };
        let off_wrist = raw.number(2) == Some(i64::from(Spo2MeasurementType::OffWrist.as_u8()));
        if off_wrist || value <= 0.0 {
            self.out.drop("spo2_off_wrist_or_zero");
            return;
        }
        self.sample("spo2", ts, value);
    }

    fn sleep_level(&mut self, v: &View) {
        let (Some(ts), Some(level)) = (v.instant(FIELD_TIMESTAMP), v.text(0)) else {
            return;
        };
        self.touch(ts);
        self.sleep_levels.push((ts, level));
    }

    fn sleep_assessment(&mut self, v: &View) {
        let mut values = [None; 14];
        for (slot, field) in ASSESSMENT_FIELDS.iter().enumerate() {
            values[slot] = v.num(*field);
        }
        self.assessment = Some(values);
    }

    fn event(&mut self, v: &View, raw: &Raw) {
        let Some(ts) = v.instant(FIELD_TIMESTAMP) else {
            return;
        };
        if self.file_type_number == Some(FILE_TYPE_SLEEP) && raw.number(0) == Some(SLEEP_EVENT_CODE) {
            match raw.number(1) {
                Some(n) if n == i64::from(EventType::Start.as_u8()) => self.sleep_start = Some(ts),
                Some(n) if n == i64::from(EventType::Stop.as_u8()) => self.sleep_end = Some(ts),
                _ => {}
            }
        }
    }

    fn hrv_status_summary(&mut self, v: &View) {
        let Some(ts) = v.instant(FIELD_TIMESTAMP) else {
            return;
        };
        self.touch(ts);
        for (field, metric) in HRV_SUMMARY_FIELDS {
            if let Some(value) = v.number(field) {
                self.daily(metric, value, ts);
            }
        }
        if let Some(status) = v.text(6) {
            self.label("hrv_status", status, ts);
        }
    }

    fn hrv_value(&mut self, v: &View) {
        if let (Some(ts), Some(value)) = (v.instant(FIELD_TIMESTAMP), v.number(0)) {
            self.sample("hrv_rmssd", ts, value);
        }
    }

    fn skin_temp_overnight(&mut self, v: &View) {
        let Some(ts) = v.instant(FIELD_TIMESTAMP) else {
            return;
        };
        self.touch(ts);
        self.offset(Some(ts), v.local_wall(0));
        for (field, metric) in SKIN_TEMP_FIELDS {
            if let Some(value) = v.number(field) {
                self.daily(metric, value, ts);
            }
        }
    }

    fn max_met_data(&mut self, v: &View) {
        let (Some(ts), Some(vo2max)) = (v.instant(0), v.number(2)) else {
            return;
        };
        if vo2max <= 0.0 {
            return;
        }
        self.touch(ts);
        self.daily("vo2max", vo2max, ts);
        if let Some(sport) = v.text(5) {
            self.label("vo2max_sport", sport, ts);
        }
    }

    fn timestamp_correlation(&mut self, v: &View) {
        self.offset(v.instant(FIELD_TIMESTAMP), v.local_wall(3));
    }

    fn session(&mut self, v: &View) {
        let Some(start) = v.instant(2) else {
            return;
        };
        self.touch(start);
        let speed = v.number(124).or_else(|| v.number(14));
        self.out.activities.push(Activity {
            start_utc: start,
            end_utc: v.instant(FIELD_TIMESTAMP),
            sport: v.text(5),
            sub_sport: v.text(6),
            total_timer_s: v.number(8),
            total_elapsed_s: v.number(7),
            distance_m: v.number(9),
            calories_kcal: v.int(11),
            avg_hr: v.int(16),
            max_hr: v.int(17),
            avg_speed_mps: speed,
            total_ascent_m: v.number(22),
            total_descent_m: v.number(23),
        });
    }

    // ---- driving ----

    fn feed(&mut self, num: u16, name: &str, v: &View, raw: &Raw) {
        *self.out.message_counts.entry(name.to_string()).or_insert(0) += 1;
        self.feed_handler(num, v, raw, true);
    }

    fn feed_handler(&mut self, num: u16, v: &View, raw: &Raw, track_last_full: bool) {
        if track_last_full && let Some(full) = v.instant(FIELD_TIMESTAMP) {
            self.last_full = Some(full);
        }
        match num {
            MSG_FILE_ID => self.file_id(v, raw),
            MSG_MONITORING_INFO => self.monitoring_info(v),
            MSG_MONITORING => self.monitoring(v, raw),
            MSG_MONITORING_HR_DATA => self.monitoring_hr_data(v),
            MSG_STRESS_LEVEL => self.stress_level(v),
            MSG_RESPIRATION_RATE => self.respiration_rate(v),
            MSG_SPO2_DATA => self.spo2_data(v, raw),
            MSG_SLEEP_LEVEL => self.sleep_level(v),
            MSG_SLEEP_ASSESSMENT => self.sleep_assessment(v),
            MSG_EVENT => self.event(v, raw),
            MSG_HRV_STATUS_SUMMARY => self.hrv_status_summary(v),
            MSG_HRV_VALUE => self.hrv_value(v),
            MSG_SKIN_TEMP_OVERNIGHT => self.skin_temp_overnight(v),
            MSG_MAX_MET_DATA => self.max_met_data(v),
            MSG_TIMESTAMP_CORRELATION => self.timestamp_correlation(v),
            MSG_SESSION => self.session(v),
            _ => {}
        }
    }

    fn finish_sleep(&mut self) {
        if self.sleep_levels.is_empty() && self.assessment.is_none() && self.sleep_start.is_none() {
            return;
        }
        let mut session = SleepSession {
            start_utc: self.sleep_start,
            end_utc: self.sleep_end,
            ..SleepSession::default()
        };
        let mut levels = std::mem::take(&mut self.sleep_levels);
        levels.sort();
        let mut previous = session.start_utc;
        for (end, stage) in levels {
            match previous {
                // No start event: the first stage's beginning is unknown.
                None => self.out.drop("sleep_stage_without_start"),
                Some(start) if end > start => session.stages.push(SleepStage {
                    stage,
                    start_utc: start,
                    end_utc: end,
                }),
                Some(_) => self.out.drop("sleep_stage_zero_length"),
            }
            previous = Some(end);
        }
        let mut totals: BTreeMap<&str, i64> = BTreeMap::new();
        for stage in &session.stages {
            *totals.entry(stage.stage.as_str()).or_insert(0) +=
                (stage.end_utc - stage.start_utc).num_seconds();
        }
        if !session.stages.is_empty() {
            let total = |name: &str| totals.get(name).copied().unwrap_or(0);
            session.deep_s = Some(total("deep"));
            session.light_s = Some(total("light"));
            session.rem_s = Some(total("rem"));
            session.awake_s = Some(total("awake"));
        }
        if let Some(values) = &self.assessment {
            apply_assessment(&mut session, values);
        }
        if session.end_utc.is_none() {
            session.end_utc = session.stages.last().map(|s| s.end_utc);
        }
        if session.start_utc.is_none() {
            session.start_utc = session.stages.first().map(|s| s.start_utc);
        }
        self.out.sleep = Some(session);
    }

    fn result(mut self) -> Decoded {
        self.finish_sleep();
        self.out.start_utc = self.seen_min;
        self.out.end_utc = self.seen_max;
        if let Some(sleep_end) = self.out.sleep.as_ref().and_then(|s| s.end_utc) {
            self.out.end_utc = Some(self.out.end_utc.map_or(sleep_end, |e| e.max(sleep_end)));
        }
        self.out
    }
}

fn apply_assessment(session: &mut SleepSession, values: &[Option<Num>; 14]) {
    let int = |slot: usize| values[slot].map(Num::as_i64);
    // Slots follow `ASSESSMENT_FIELDS` (field numbers 0..=11, 14, 15).
    if let Some(v) = int(0) {
        session.combined_awake_score = Some(v);
    }
    if let Some(v) = int(1) {
        session.awake_time_score = Some(v);
    }
    if let Some(v) = int(2) {
        session.awakenings_count_score = Some(v);
    }
    if let Some(v) = int(3) {
        session.deep_score = Some(v);
    }
    if let Some(v) = int(4) {
        session.duration_score = Some(v);
    }
    if let Some(v) = int(5) {
        session.light_score = Some(v);
    }
    if let Some(v) = int(6) {
        session.overall_score = Some(v);
    }
    if let Some(v) = int(7) {
        session.quality_score = Some(v);
    }
    if let Some(v) = int(8) {
        session.recovery_score = Some(v);
    }
    if let Some(v) = int(9) {
        session.rem_score = Some(v);
    }
    if let Some(v) = int(10) {
        session.restlessness_score = Some(v);
    }
    if let Some(v) = int(11) {
        session.awakenings_count = Some(v);
    }
    if let Some(v) = int(12) {
        session.interruptions_score = Some(v);
    }
    if let Some(v) = values[13] {
        session.avg_stress = Some(v.as_f64());
    }
}

/// `FILE_TYPE_STREAMS`: the stream suffix for a `file_id.type` text.
fn stream_label(number: Option<i64>, text: Option<&str>) -> &str {
    match number {
        Some(FILE_TYPE_SLEEP) => "sleep",
        Some(FILE_TYPE_HRV) => "hrv",
        Some(FILE_TYPE_SKIN_TEMP) => "skin_temp",
        Some(FILE_TYPE_METRICS) => "metrics",
        _ => text.unwrap_or("None"),
    }
}

/// Header and data CRC mismatches, one warning each; the parser itself is told to skip both.
fn crc_warnings(bytes: &[u8]) -> Vec<String> {
    fn crc16(bytes: &[u8]) -> u16 {
        // CRC-16/ARC (reflected polynomial 0xA001, zero start), the FIT file checksum.
        let mut crc: u16 = 0;
        for byte in bytes {
            crc ^= u16::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xA001
                } else {
                    crc >> 1
                };
            }
        }
        crc
    }
    fn le16(bytes: &[u8]) -> u16 {
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    let mut warnings = Vec::new();
    let mut pos = 0usize;
    while bytes.len().saturating_sub(pos) >= 12 {
        let rest = &bytes[pos..];
        let header = usize::from(rest[0]);
        let body = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
        if header < 12 || &rest[8..12] != b".FIT" || rest.len() < header {
            break;
        }
        if header >= 14 {
            let stored = le16(&rest[12..14]);
            if stored != 0 && crc16(&rest[..12]) != stored {
                warnings.push(format!(
                    "mismatching CRC in FIT header (header offset: {pos})"
                ));
            }
        }
        let end = header.saturating_add(body);
        if rest.len() < end.saturating_add(2) {
            break;
        }
        if crc16(&rest[..end]) != le16(&rest[end..end + 2]) {
            warnings.push(format!(
                "mismatching CRC in FIT data (header offset: {pos})"
            ));
        }
        pos += end + 2;
    }
    warnings
}

/// Native fields only: a developer field may reuse a native field number.
fn native_view(record: &fitparser::FitDataRecord, developer_fields: usize) -> View<'_> {
    let fields = record
        .fields()
        .iter()
        .filter(|f| {
            developer_fields == 0
                || !serde_json::to_value(f)
                    .ok()
                    .and_then(|v| v.get("developer_data_index").map(|d| !d.is_null()))
                    .unwrap_or(false)
        })
        .collect();
    View { fields }
}

thread_local! {
    static IN_PARSER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Make a panic inside the FIT parser print nothing. The default hook names the source file of
/// the panic, and for a panic inside the parser that is a path under the build machine's home
/// directory. The decoder turns the panic into a per-file failure anyway. Panics anywhere else
/// still reach the previous hook. Idempotent; called before the first decode and by the CLI at
/// start-up.
pub fn silence_parser_panics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !IN_PARSER.with(std::cell::Cell::get) {
                previous(info);
            }
        }));
    });
}

/// The number of a decoded `activity_type` value. The field is often filled by component
/// expansion from `current_activity_type_intensity`, so it is absent from the raw message and
/// only the decoded text is available; fitparser's own enum maps that text back to its number
/// (digit text, for values the profile does not name, is read as the number it is).
fn activity_type_number(text: &str) -> Option<i64> {
    if let Ok(number) = text.parse::<i64>() {
        return Some(number);
    }
    match ActivityType::from(text) {
        ActivityType::UnknownVariant(_) => None,
        named => Some(i64::from(named.as_u8())),
    }
}

fn processor() -> FitStreamProcessor {
    let mut processor = FitStreamProcessor::new();
    processor.add_option(DecodeOption::SkipHeaderCrcValidation);
    processor.add_option(DecodeOption::SkipDataCrcValidation);
    processor
}

/// Run the stream, handing every decoded data message to `on_message`.
///
/// Any failure (including a panic inside the parser) ends the run with its message.
fn run_stream<F>(bytes: &[u8], mut on_message: F) -> Result<(), String>
where
    F: FnMut(u16, &fitparser::FitDataRecord, usize, Raw),
{
    silence_parser_panics();
    let mut processor = processor();
    let mut buffer = bytes;
    // Between a header and its CRC a file is open; the oracle fails a stream that ends there.
    let mut open = false;
    while !buffer.is_empty() {
        IN_PARSER.with(|flag| flag.set(true));
        let step = catch_unwind(AssertUnwindSafe(|| -> Result<_, String> {
            let (rest, object) = processor
                .deserialize_next(buffer)
                .map_err(|e| e.to_string())?;
            match object {
                FitObject::Crc(_) => {
                    processor.reset();
                    open = false;
                    Ok((rest, None))
                }
                FitObject::Header(_) => {
                    open = true;
                    Ok((rest, None))
                }
                FitObject::DefinitionMessage(_) => Ok((rest, None)),
                FitObject::DataMessage(message) => {
                    let raw = Raw {
                        cycles: (message.global_message_number() == MSG_MONITORING)
                            .then(|| message.fields().get(&3).and_then(integer_of))
                            .flatten(),
                        numbers: message
                            .fields()
                            .iter()
                            .filter_map(|(k, v)| integer_of(v).map(|n| (*k, n)))
                            .collect(),
                    };
                    let developer_fields = message.developer_fields().len();
                    let record = processor
                        .decode_message(message)
                        .map_err(|e| e.to_string())?;
                    Ok((rest, Some((record, developer_fields, raw))))
                }
            }
        }));
        IN_PARSER.with(|flag| flag.set(false));
        let step = step.map_err(|_| "parser panicked on this input".to_string())??;
        let (rest, decoded) = step;
        if let Some((record, developer_fields, raw)) = decoded {
            let kind = record.kind();
            on_message(kind.as_u16(), &record, developer_fields, raw);
        }
        buffer = rest;
    }
    if open {
        return Err("FIT file truncated before its CRC".to_string());
    }
    Ok(())
}

fn message_name(record: &fitparser::FitDataRecord, num: u16) -> String {
    let kind: MesgNum = record.kind();
    if MesgNum::is_named_variant(kind.as_i64()) {
        kind.to_string()
    } else {
        format!("unknown_{num}")
    }
}

/// Decode one FIT file's bytes. Fails with [`FitDecodeError`] if unreadable; the error carries
/// the span seen so far.
pub fn decode_fit(bytes: &[u8]) -> Result<Decoded, FitDecodeError> {
    let mut state = State::new();
    let outcome = run_stream(bytes, |num, record, developer_fields, raw| {
        let view = native_view(record, developer_fields);
        let name = message_name(record, num);
        state.feed(num, &name, &view, &raw);
    });
    if let Err(message) = outcome {
        return Err(FitDecodeError {
            kind: "unrecognized_payload".to_string(),
            message,
            stream: state.file_type.as_ref().map(|_| state.out.stream.clone()),
            start_utc: state.seen_min,
            end_utc: state.seen_max,
        });
    }
    let warnings = crc_warnings(bytes);
    let mut decoded = state.result();
    decoded.warnings = warnings;
    Ok(decoded)
}

/// Cheap first pass: only the (timestamp, local timestamp) pairs a file states.
///
/// Run over a whole batch before writing so every file's local dates resolve against offsets
/// from every other file, whatever order they are processed in. Any failure gives an empty list.
pub fn scan_clock_offsets(bytes: &[u8]) -> Vec<ClockOffset> {
    let mut state = State::new();
    let outcome = run_stream(bytes, |num, record, developer_fields, raw| {
        if matches!(
            num,
            MSG_MONITORING_INFO | MSG_SKIN_TEMP_OVERNIGHT | MSG_TIMESTAMP_CORRELATION
        ) {
            let view = native_view(record, developer_fields);
            state.feed_handler(num, &view, &raw, false);
        }
    });
    if outcome.is_err() {
        return Vec::new();
    }
    state.out.offsets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_16_wraps_both_ways() {
        let base = from_fit_secs(1_100_000_000);
        let low = (1_100_000_000 & 0xFFFF) as i64;
        assert_eq!(
            expand_timestamp_16(low + 5, base),
            base + Duration::seconds(5)
        );
        assert_eq!(
            expand_timestamp_16(low - 5, base),
            base - Duration::seconds(5)
        );
    }
}
