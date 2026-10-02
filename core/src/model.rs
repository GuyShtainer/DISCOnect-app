// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a decoder hands the writer: the Rust twin of `hearthbeat/ingest/model.py`.
//!
//! Plain data, no SQL, no parser types. `serde_json::to_value(&decoded)` has exactly the key set
//! and nesting of the Python oracle's canonical JSON (`tests/decoded_json.py`): instants are
//! `YYYY-MM-DDTHH:MM:SSZ` strings, absent values are null, `warnings` is a count and
//! `record_count` is added.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};

/// A UTC moment, whole seconds.
pub type Instant = DateTime<Utc>;

const ISO: &str = "%Y-%m-%dT%H:%M:%SZ";

fn ser_instant<S: Serializer>(value: &Instant, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.format(ISO).to_string())
}

fn ser_opt_instant<S: Serializer>(
    value: &Option<Instant>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(moment) => ser_instant(moment, serializer),
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Sample {
    pub metric: String,
    #[serde(serialize_with = "ser_instant")]
    pub ts_utc: Instant,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DailyFact {
    pub metric: String,
    pub value: f64,
    #[serde(serialize_with = "ser_opt_instant")]
    pub ts_utc: Option<Instant>,
    pub date: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DailyLabel {
    pub metric: String,
    pub label: String,
    #[serde(serialize_with = "ser_opt_instant")]
    pub ts_utc: Option<Instant>,
    pub date: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MonitoringInterval {
    #[serde(serialize_with = "ser_instant")]
    pub ts_utc: Instant,
    pub activity_type: String,
    pub steps: Option<i64>,
    pub cycles: Option<f64>,
    pub active_time_s: Option<f64>,
    pub active_calories_kcal: Option<i64>,
    pub distance_m: Option<f64>,
    pub intensity: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SleepStage {
    pub stage: String,
    #[serde(serialize_with = "ser_instant")]
    pub start_utc: Instant,
    #[serde(serialize_with = "ser_instant")]
    pub end_utc: Instant,
}

/// One night. Any field the source did not state stays `None` (never 0).
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct SleepSession {
    #[serde(serialize_with = "ser_opt_instant")]
    pub start_utc: Option<Instant>,
    #[serde(serialize_with = "ser_opt_instant")]
    pub end_utc: Option<Instant>,
    pub date: Option<String>,
    pub stages: Vec<SleepStage>,
    pub deep_s: Option<i64>,
    pub light_s: Option<i64>,
    pub rem_s: Option<i64>,
    pub awake_s: Option<i64>,
    pub unmeasurable_s: Option<i64>,
    pub overall_score: Option<i64>,
    pub quality_score: Option<i64>,
    pub duration_score: Option<i64>,
    pub recovery_score: Option<i64>,
    pub deep_score: Option<i64>,
    pub rem_score: Option<i64>,
    pub light_score: Option<i64>,
    pub awake_time_score: Option<i64>,
    pub awakenings_count_score: Option<i64>,
    pub combined_awake_score: Option<i64>,
    pub restlessness_score: Option<i64>,
    pub interruptions_score: Option<i64>,
    pub awakenings_count: Option<i64>,
    pub avg_stress: Option<f64>,
    pub avg_spo2: Option<f64>,
    pub lowest_spo2: Option<i64>,
    pub avg_hr: Option<f64>,
    pub avg_respiration: Option<f64>,
    pub lowest_respiration: Option<f64>,
    pub highest_respiration: Option<f64>,
    pub retro: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Activity {
    #[serde(serialize_with = "ser_instant")]
    pub start_utc: Instant,
    #[serde(serialize_with = "ser_opt_instant")]
    pub end_utc: Option<Instant>,
    pub sport: Option<String>,
    pub sub_sport: Option<String>,
    pub total_timer_s: Option<f64>,
    pub total_elapsed_s: Option<f64>,
    pub distance_m: Option<f64>,
    pub calories_kcal: Option<i64>,
    pub avg_hr: Option<i64>,
    pub max_hr: Option<i64>,
    pub avg_speed_mps: Option<f64>,
    pub total_ascent_m: Option<f64>,
    pub total_descent_m: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ClockOffset {
    #[serde(serialize_with = "ser_instant")]
    pub ts_utc: Instant,
    pub offset_s: i64,
}

/// Everything one source file or record contributed.
///
/// `dropped` counts values the decoder refused (sentinels, off-wrist readings, undatable
/// stages) by reason, so data health can report them instead of them vanishing silently.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    pub stream: String,
    pub source_scope: String,
    pub device_id: Option<String>,
    pub start_utc: Option<Instant>,
    pub end_utc: Option<Instant>,
    pub samples: Vec<Sample>,
    pub daily: Vec<DailyFact>,
    pub labels: Vec<DailyLabel>,
    pub intervals: Vec<MonitoringInterval>,
    pub sleep: Option<SleepSession>,
    pub activities: Vec<Activity>,
    pub offsets: Vec<ClockOffset>,
    pub message_counts: BTreeMap<String, u64>,
    pub dropped: BTreeMap<String, u64>,
    pub warnings: Vec<String>,
}

impl Decoded {
    pub fn new(stream: &str, source_scope: &str) -> Self {
        Decoded {
            stream: stream.to_string(),
            source_scope: source_scope.to_string(),
            device_id: None,
            start_utc: None,
            end_utc: None,
            samples: Vec::new(),
            daily: Vec::new(),
            labels: Vec::new(),
            intervals: Vec::new(),
            sleep: None,
            activities: Vec::new(),
            offsets: Vec::new(),
            message_counts: BTreeMap::new(),
            dropped: BTreeMap::new(),
            warnings: Vec::new(),
        }
    }

    /// Count one refused value under `reason`.
    pub fn drop(&mut self, reason: &str) {
        *self.dropped.entry(reason.to_string()).or_insert(0) += 1;
    }

    /// Rows this decode will write, for provenance and the import summary.
    pub fn record_count(&self) -> u64 {
        let sleep = self.sleep.as_ref().map_or(0, |s| 1 + s.stages.len());
        (self.samples.len()
            + self.daily.len()
            + self.labels.len()
            + self.intervals.len()
            + sleep
            + self.activities.len()
            + self.offsets.len()) as u64
    }
}

/// The canonical JSON view: `warnings` as a count, plus `record_count`.
#[derive(Serialize)]
struct DecodedJson<'a> {
    stream: &'a str,
    source_scope: &'a str,
    device_id: &'a Option<String>,
    #[serde(serialize_with = "ser_opt_instant")]
    start_utc: &'a Option<Instant>,
    #[serde(serialize_with = "ser_opt_instant")]
    end_utc: &'a Option<Instant>,
    samples: &'a [Sample],
    daily: &'a [DailyFact],
    labels: &'a [DailyLabel],
    intervals: &'a [MonitoringInterval],
    sleep: &'a Option<SleepSession>,
    activities: &'a [Activity],
    offsets: &'a [ClockOffset],
    message_counts: &'a BTreeMap<String, u64>,
    dropped: &'a BTreeMap<String, u64>,
    warnings: usize,
    record_count: u64,
}

impl Serialize for Decoded {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        DecodedJson {
            stream: &self.stream,
            source_scope: &self.source_scope,
            device_id: &self.device_id,
            start_utc: &self.start_utc,
            end_utc: &self.end_utc,
            samples: &self.samples,
            daily: &self.daily,
            labels: &self.labels,
            intervals: &self.intervals,
            sleep: &self.sleep,
            activities: &self.activities,
            offsets: &self.offsets,
            message_counts: &self.message_counts,
            dropped: &self.dropped,
            warnings: self.warnings.len(),
            record_count: self.record_count(),
        }
        .serialize(serializer)
    }
}
