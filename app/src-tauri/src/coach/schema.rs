// SPDX-License-Identifier: AGPL-3.0-or-later
//! The positive schema (Bet 15 slice 3, attack finding B1): the last gate before a tool answer may leave
//! the machine. [`validate`] takes the *projected* answer ([`super::views::project`]) and **fails closed**:
//!
//! * every key must be in the tool's fixed key set (an unknown key is an error, never skipped);
//! * every string must be a `YYYY-MM-DD` date, a member of a closed vocabulary (the contract's metric ids,
//!   label ids, units, source scopes and streams, or a small table written down here) or one of a few
//!   exact allow-listed sentences;
//! * numbers and booleans are allowed where the schema says so; anything else is an error.
//!
//! A [`SchemaError`] carries the tool, a path made only of *schema* key names, and a fixed [`Reason`]. It
//! never carries the offending key or value, so an error can be shown, stored or sent without moving data
//! with it. This is a positive list on purpose: the privacy walk the MCP server runs is a blocklist, and a
//! blocklist cannot say "nothing else".
//!
//! The vocabularies come from `disconect_core::contract::Contract` (the one contract both cores load, the
//! app already links the core), so a metric added to the contract is sendable and nothing else is.

use disconect_core::contract::Contract;
use serde_json::Value;

/// The five tools whose answers may be sent (the sixth, `get_contract`, never is).
pub const SENDABLE_TOOLS: [&str; 5] =
    ["get_data_health", "get_metric_series", "get_sleep_detail", "list_activities", "get_period_facts"];

/// The one sentence a metric series carries for a metric with no data in the window.
pub const NOTE_NO_DATA: &str = "no data in this window for any source scope";
/// The fixed reasons an empty answer carries.
pub const REASONS: [&str; 3] =
    ["nothing stored yet", "no sleep stored yet", "no record of that night from any source"];
/// The two fixed sentences of a fact's `evidence.aggregation`.
pub const AGGREGATIONS: [&str; 2] = ["mean of the window's daily values", "mean of per-day means of samples"];

/// What [`super::caps::fit`] may have cut from an answer; the answer says so in `omitted`.
pub const OMITTED: &[&str] = &[
    "window_points", "window_dates", "evidence", "source_agreement", "ledger_gaps", "metric_detail",
    "ledger_rows", "metric_totals", "ledger",
];

const CADENCES: &[&str] = &["daily", "sample"];
const DIRECTIONS: &[&str] = &["higher", "lower", "unchanged"];
const CONFIDENCES: &[&str] = &["high", "medium", "low", "insufficient"];
const REASON_CODES: &[&str] = &["ok", "no_data", "no_data_in_window", "no_baseline", "baseline_too_thin"];
const GAP_STATUSES: &[&str] = &["failed", "not_covered", "source_empty"];
/// Sleep stage names as the core stores them; anything else is projected as `other`.
pub const STAGES: &[&str] = &["deep", "light", "rem", "awake", "unmeasurable", "other"];
const UNIT_EXTRAS: &[&str] = &["s", "m/s", "0-100"];

/// Sport names (the decoder's lower-case names for the common sports). The projection maps a name that is
/// not in this table to `other`, so a new sport degrades to a generic one and never blocks an answer.
pub const SPORTS: &[&str] = &[
    "generic", "running", "cycling", "transition", "fitness_equipment", "swimming", "basketball", "soccer",
    "tennis", "american_football", "training", "walking", "cross_country_skiing", "alpine_skiing",
    "snowboarding", "rowing", "mountaineering", "hiking", "multisport", "paddling", "flying", "e_biking",
    "motorcycling", "boating", "driving", "golf", "horseback_riding", "hunting", "fishing", "inline_skating",
    "rock_climbing", "sailing", "ice_skating", "snowshoeing", "stand_up_paddleboarding", "surfing",
    "wakeboarding", "water_skiing", "kayaking", "rafting", "windsurfing", "kitesurfing", "boxing",
    "floor_climbing", "baseball", "diving", "hiit", "racket", "meditation", "disc_golf", "cricket", "rugby",
    "hockey", "lacrosse", "volleyball", "other",
];
/// Sub-sport names, same rule as [`SPORTS`].
pub const SUB_SPORTS: &[&str] = &[
    "generic", "treadmill", "street", "trail", "track", "spin", "indoor_cycling", "road", "mountain",
    "downhill", "recumbent", "cyclocross", "hand_cycling", "track_cycling", "indoor_rowing", "elliptical",
    "stair_climbing", "lap_swimming", "open_water", "flexibility_training", "strength_training",
    "warm_up", "match", "exercise", "challenge", "indoor_skiing", "cardio_training", "indoor_walking",
    "e_bike_fitness", "bmx", "casual_walking", "speed_walking", "bike_to_run_transition",
    "run_to_bike_transition", "swim_to_bike_transition", "atv", "motocross", "backcountry", "resort",
    "rc_drone", "wingsuit", "whitewater", "skate_skiing", "yoga", "pilates", "indoor_running", "gravel_cycling",
    "e_mountain_bike", "commuting", "mixed_surface", "navigate", "track_me", "map", "single_gas_diving",
    "multi_gas_diving", "gauge_diving", "apnea_diving", "apnea_hunting", "virtual_activity", "obstacle",
    "breathing", "other",
];

/// Label values per label metric. The contract describes the first two sets; the rest are the values the
/// importers lower-case from the export files. A label value outside its table is dropped by the
/// projection (and counted), so a free-text label can never ride along.
fn label_values(metric: &str) -> &'static [&'static str] {
    match metric {
        "hrv_status" => &["balanced", "unbalanced", "low", "poor", "none"],
        "training_readiness_level" => &["prime", "high", "moderate", "low", "poor"],
        "training_readiness_context" => &["after_wakeup_reset", "after_post_exercise_reset", "update_realtime_variables"],
        "training_load_status" => &["optimal", "high", "low", "very_high", "very_low", "none"],
        "vo2max_sport" => SPORTS,
        _ => &[],
    }
}

/// True when `value` is an allowed label for the label metric `metric`.
pub fn label_allowed(metric: &str, value: &str) -> bool {
    label_values(metric).contains(&value)
}

/// `YYYY-MM-DD`: ten characters, digits and two dashes in place, month 1-12, day 1-31. It does not know the
/// calendar (February 30 passes): the check is that the string cannot carry a time or a word.
pub fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    let digit = |i: usize| bytes.get(i).is_some_and(u8::is_ascii_digit);
    let number = |a: usize, b: usize| -> u32 {
        (a..=b).filter_map(|i| bytes.get(i)).fold(0, |acc, d| acc * 10 + u32::from(d.saturating_sub(b'0')))
    };
    let shape = [0, 1, 2, 3, 5, 6, 8, 9].iter().all(|&i| digit(i))
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-');
    shape && (1..=12).contains(&number(5, 6)) && (1..=31).contains(&number(8, 9))
}

/// A closed set of words.
#[derive(Debug, Clone, Copy)]
pub enum Vocab {
    /// A table written in this crate.
    Fixed(&'static [&'static str]),
    /// A contract metric id.
    MetricId,
    /// A contract label id.
    LabelId,
    /// A contract metric id or label id (the coverage ledger lists both).
    MetricOrLabelId,
    /// A value of any label (the union of the tables).
    LabelValue,
    /// A unit the contract lists, plus the activity and sleep units.
    Unit,
    /// A stream id some metric of the contract lists.
    Stream,
    /// One of the contract's source scopes.
    SourceScope,
    /// A source scope or `any`.
    ScopeOrAny,
    /// `period.<metric id>`.
    FactId,
    /// The contract version string.
    ContractVersion,
}

impl Vocab {
    pub(crate) fn contains(self, word: &str) -> bool {
        let Ok(contract) = Contract::get() else {
            return false; // no contract, no vocabulary: fail closed
        };
        match self {
            Vocab::Fixed(list) => list.contains(&word),
            Vocab::MetricId => contract.metrics.iter().any(|m| m.metric == word),
            Vocab::LabelId => contract.labels.iter().any(|m| m.metric == word),
            Vocab::MetricOrLabelId => {
                contract.metrics.iter().chain(&contract.labels).any(|m| m.metric == word)
            }
            Vocab::LabelValue => {
                ["hrv_status", "training_readiness_level", "training_readiness_context", "training_load_status", "vo2max_sport"]
                    .iter()
                    .any(|metric| label_allowed(metric, word))
            }
            Vocab::Unit => {
                UNIT_EXTRAS.contains(&word) || contract.metrics.iter().any(|m| m.unit == word)
            }
            Vocab::Stream => contract.streams_for.iter().any(|s| s.streams.iter().any(|name| name == word)),
            Vocab::SourceScope => contract.source_scopes.iter().any(|s| s == word),
            Vocab::ScopeOrAny => word == "any" || contract.source_scopes.iter().any(|s| s == word),
            Vocab::FactId => word
                .strip_prefix("period.")
                .is_some_and(|metric| contract.metrics.iter().any(|m| m.metric == metric)),
            Vocab::ContractVersion => contract.contract_version == word,
        }
    }
}

/// The type of one JSON value.
#[derive(Debug, Clone)]
pub enum Ty {
    /// A `YYYY-MM-DD` string.
    Date,
    /// A whole number.
    Int,
    /// Any finite number.
    Number,
    /// `true` or `false`.
    Bool,
    /// A string from a closed vocabulary.
    Enum(Vocab),
    /// A string equal to one of these exact sentences.
    Sentence(&'static [&'static str]),
    /// An array whose every element has this type.
    Array(Box<Ty>),
    /// An object with this fixed key set (every key optional, none unlisted).
    Object(Vec<(&'static str, Ty)>),
    /// `null` or this type.
    Nullable(Box<Ty>),
    /// Any of these types.
    OneOf(Vec<Ty>),
}

/// Why a value was refused. Fixed text only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The tool has no schema (`get_contract` has none on purpose).
    UnknownTool,
    /// A key that the schema does not list.
    UnknownKey,
    /// A JSON type the schema does not allow here.
    WrongType,
    /// A string that is not `YYYY-MM-DD`.
    NotADate,
    /// A string outside the closed vocabulary or the allow-listed sentences.
    NotInVocabulary,
}

impl Reason {
    /// The fixed message.
    pub fn text(self) -> &'static str {
        match self {
            Reason::UnknownTool => "no schema for this tool",
            Reason::UnknownKey => "a key the schema does not list",
            Reason::WrongType => "a value of a type the schema does not allow",
            Reason::NotADate => "a string that is not a plain date",
            Reason::NotInVocabulary => "a string outside the allowed vocabulary",
        }
    }
}

/// A refusal: where (schema key names only) and why (fixed text). It holds no data from the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError {
    /// The tool, or `unknown` when the name is not one of the sendable five.
    pub tool: &'static str,
    /// Schema key names joined with `/`, `[]` for an array element; empty at the root.
    pub path: String,
    /// The fixed reason.
    pub reason: Reason,
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "coach schema refused {} at /{}: {}", self.tool, self.path, self.reason.text())
    }
}

impl std::error::Error for SchemaError {}

fn object(fields: Vec<(&'static str, Ty)>) -> Ty {
    Ty::Object(fields)
}
fn array(of: Ty) -> Ty {
    Ty::Array(Box::new(of))
}
fn nullable(of: Ty) -> Ty {
    Ty::Nullable(Box::new(of))
}
fn word(vocab: Vocab) -> Ty {
    Ty::Enum(vocab)
}

fn range() -> Ty {
    object(vec![("from", Ty::Date), ("to", Ty::Date), ("days", Ty::Int)])
}

/// An object keyed by the contract's source scopes (the keys are the scope names).
fn by_scope(of: Ty) -> Ty {
    let mut fields = Vec::new();
    if let Ok(contract) = Contract::get() {
        for scope in &contract.source_scopes {
            fields.push((scope.as_str(), of.clone()));
        }
    }
    Ty::Object(fields)
}

fn day_span() -> Vec<(&'static str, Ty)> {
    vec![("days_with_data", Ty::Int), ("first_day", Ty::Date), ("last_day", Ty::Date)]
}

/// The schema of one tool's projected answer, or `None` for a tool that is never sent.
pub fn schema_for(tool: &str) -> Option<Ty> {
    let schema = match tool {
        "get_metric_series" => object(vec![
            (
                "series",
                array(object(vec![
                    ("metric", word(Vocab::MetricId)),
                    ("unit", nullable(word(Vocab::Unit))),
                    ("cadence", word(Vocab::Fixed(CADENCES))),
                    ("source_scope", nullable(word(Vocab::SourceScope))),
                    ("from", Ty::Date),
                    ("to", Ty::Date),
                    (
                        "points",
                        array(object(vec![
                            ("date", Ty::Date),
                            ("value", Ty::Number),
                            ("min", Ty::Number),
                            ("mean", Ty::Number),
                            ("max", Ty::Number),
                            ("samples", Ty::Int),
                        ])),
                    ),
                    ("note", Ty::Sentence(&[NOTE_NO_DATA])),
                ])),
            ),
            (
                "labels",
                array(object(vec![
                    ("metric", word(Vocab::LabelId)),
                    ("from", Ty::Date),
                    ("to", Ty::Date),
                    (
                        "points",
                        array(object(vec![
                            ("date", Ty::Date),
                            ("label", word(Vocab::LabelValue)),
                            ("source_scope", word(Vocab::SourceScope)),
                        ])),
                    ),
                    ("dropped", Ty::Int),
                ])),
            ),
            ("ignored_count", Ty::Int),
            ("thinned", Ty::Int),
        ]),
        "get_period_facts" => object(vec![
            ("as_of", nullable(Ty::Date)),
            ("window", range()),
            (
                "baseline",
                object(vec![
                    ("from", Ty::Date),
                    ("to", Ty::Date),
                    ("days", Ty::Int),
                    ("min_days_with_data", Ty::Int),
                ]),
            ),
            (
                "facts",
                array(object(vec![
                    ("fact_id", word(Vocab::FactId)),
                    ("metric", word(Vocab::MetricId)),
                    ("unit", word(Vocab::Unit)),
                    ("cadence", word(Vocab::Fixed(CADENCES))),
                    ("source_scope", word(Vocab::ScopeOrAny)),
                    ("value", nullable(Ty::Number)),
                    ("window_min", nullable(Ty::Number)),
                    ("window_max", nullable(Ty::Number)),
                    ("window_days_with_data", Ty::Int),
                    ("baseline_days_with_data", Ty::Int),
                    (
                        "comparison",
                        nullable(object(vec![
                            ("baseline_mean", Ty::Number),
                            ("baseline_sd", nullable(Ty::Number)),
                            ("delta", Ty::Number),
                            ("delta_percent", nullable(Ty::Number)),
                            ("z_score", nullable(Ty::Number)),
                            ("direction", word(Vocab::Fixed(DIRECTIONS))),
                        ])),
                    ),
                    ("confidence", word(Vocab::Fixed(CONFIDENCES))),
                    ("reason_code", word(Vocab::Fixed(REASON_CODES))),
                    (
                        "evidence",
                        object(vec![
                            ("window_dates", array(Ty::Date)),
                            ("baseline_from", Ty::Date),
                            ("baseline_to", Ty::Date),
                            ("baseline_days_with_data", Ty::Int),
                            ("aggregation", Ty::Sentence(&AGGREGATIONS)),
                            ("window_points", array(object(vec![("date", Ty::Date), ("value", Ty::Number)]))),
                        ]),
                    ),
                ])),
            ),
            ("ignored_count", Ty::Int),
            ("reason", Ty::Sentence(&REASONS)),
            ("dropped_facts", Ty::Int),
            ("omitted", array(word(Vocab::Fixed(OMITTED)))),
        ]),
        "get_sleep_detail" => {
            let numbers = [
                "overall_score", "quality_score", "duration_score", "recovery_score", "deep_score", "rem_score",
                "light_score", "awake_time_score", "awakenings_count_score", "combined_awake_score",
                "restlessness_score", "interruptions_score", "awakenings_count", "avg_stress", "avg_spo2",
                "lowest_spo2", "avg_hr", "avg_respiration", "lowest_respiration", "highest_respiration",
            ];
            let mut session = vec![
                ("date", Ty::Date),
                ("source_scope", word(Vocab::SourceScope)),
                ("minutes", Ty::Number),
                ("retro", Ty::Bool),
                (
                    "stage_minutes",
                    object(vec![
                        ("deep", Ty::Number),
                        ("light", Ty::Number),
                        ("rem", Ty::Number),
                        ("awake", Ty::Number),
                        ("unmeasurable", Ty::Number),
                    ]),
                ),
                (
                    "stages",
                    array(object(vec![("stage", word(Vocab::Fixed(STAGES))), ("minutes", Ty::Number)])),
                ),
            ];
            session.extend(numbers.iter().map(|name| (*name, Ty::Number)));
            object(vec![
                ("date", nullable(Ty::Date)),
                ("sessions", array(object(session))),
                (
                    "units",
                    object(vec![
                        ("stage_minutes", word(Vocab::Unit)),
                        ("avg_hr", word(Vocab::Unit)),
                        ("avg_spo2", word(Vocab::Unit)),
                        ("scores", word(Vocab::Unit)),
                    ]),
                ),
                ("reason", Ty::Sentence(&REASONS)),
                ("truncated", Ty::Int),
            ])
        }
        "list_activities" => object(vec![
            (
                "activities",
                array(object(vec![
                    ("date", Ty::Date),
                    ("sport", word(Vocab::Fixed(SPORTS))),
                    ("sub_sport", word(Vocab::Fixed(SUB_SPORTS))),
                    ("total_timer_s", Ty::Number),
                    ("total_elapsed_s", Ty::Number),
                    ("distance_m", Ty::Number),
                    ("calories_kcal", Ty::Number),
                    ("avg_hr", Ty::Number),
                    ("max_hr", Ty::Number),
                    ("avg_speed_mps", Ty::Number),
                    ("total_ascent_m", Ty::Number),
                    ("total_descent_m", Ty::Number),
                    ("source_scope", word(Vocab::SourceScope)),
                ])),
            ),
            (
                "units",
                object(
                    [
                        "distance_m", "total_timer_s", "total_elapsed_s", "calories_kcal", "avg_hr", "max_hr",
                        "avg_speed_mps", "total_ascent_m", "total_descent_m",
                    ]
                    .iter()
                    .map(|name| (*name, word(Vocab::Unit)))
                    .collect(),
                ),
            ),
            ("truncated", Ty::Int),
        ]),
        "get_data_health" => object(vec![
            ("omitted", array(word(Vocab::Fixed(OMITTED)))),
            ("contract_version", word(Vocab::ContractVersion)),
            ("schema_version", Ty::Int),
            ("window", range()),
            ("never_imported", Ty::Bool),
            ("clock_offsets_known", Ty::Int),
            ("activities", Ty::Int),
            ("sleep", by_scope(object(vec![("nights", Ty::Int), ("first_day", Ty::Date), ("last_day", Ty::Date)]))),
            (
                "streams",
                array(object(vec![
                    ("stream", word(Vocab::Stream)),
                    ("records", Ty::Int),
                    ("first", Ty::Date),
                    ("last", Ty::Date),
                ])),
            ),
            (
                "metrics",
                array(object(vec![
                    ("metric", word(Vocab::MetricId)),
                    ("unit", word(Vocab::Unit)),
                    ("cadence", word(Vocab::Fixed(CADENCES))),
                    ("days_in_window", Ty::OneOf(vec![Ty::Int, by_scope(Ty::Int)])),
                    (
                        "total",
                        nullable({
                            let mut fields = day_span();
                            if let Ok(contract) = Contract::get() {
                                for scope in &contract.source_scopes {
                                    fields.push((scope.as_str(), object(day_span())));
                                }
                            }
                            object(fields)
                        }),
                    ),
                ])),
            ),
            (
                "source_agreement",
                array(object(vec![
                    ("metric", word(Vocab::MetricId)),
                    ("scope_a", word(Vocab::SourceScope)),
                    ("scope_b", word(Vocab::SourceScope)),
                    ("compared_with", nullable(word(Vocab::MetricId))),
                    ("unit", word(Vocab::Unit)),
                    ("days_compared", Ty::Int),
                    ("days_matching", Ty::Int),
                    ("max_abs_diff", Ty::Number),
                    ("mean_diff_a_minus_b", Ty::Number),
                    ("median_abs_diff", Ty::Number),
                ])),
            ),
            (
                "coverage",
                object(vec![
                    ("window", range()),
                    (
                        "ledger",
                        array(object(vec![
                            ("metric", word(Vocab::MetricOrLabelId)),
                            ("source_scope", word(Vocab::SourceScope)),
                            ("present", Ty::Int),
                            ("failed", Ty::Int),
                            ("source_empty", Ty::Int),
                            ("not_covered", Ty::Int),
                            ("sparse", Ty::Bool),
                            (
                                "gaps",
                                array(object(vec![
                                    ("from", Ty::Date),
                                    ("to", Ty::Date),
                                    ("status", word(Vocab::Fixed(GAP_STATUSES))),
                                ])),
                            ),
                            ("gaps_truncated", Ty::Bool),
                        ])),
                    ),
                    ("refinements_available", Ty::Bool),
                    ("undatable_files", Ty::Int),
                    ("unattributed_failures", Ty::Int),
                ]),
            ),
        ]),
        _ => return None,
    };
    Some(schema)
}

fn sendable(tool: &str) -> &'static str {
    SENDABLE_TOOLS.iter().find(|name| **name == tool).copied().unwrap_or("unknown")
}

fn join(path: &[&'static str]) -> String {
    path.join("/")
}

fn check(ty: &Ty, value: &Value, path: &mut Vec<&'static str>) -> Result<(), Reason> {
    match (ty, value) {
        (Ty::Nullable(_), Value::Null) => Ok(()),
        (Ty::Nullable(inner), other) => check(inner, other, path),
        (Ty::Bool, Value::Bool(_)) | (Ty::Number, Value::Number(_)) => Ok(()),
        (Ty::Int, Value::Number(n)) if n.is_i64() || n.is_u64() => Ok(()),
        (Ty::Date, Value::String(s)) => {
            if is_date(s) {
                Ok(())
            } else {
                Err(Reason::NotADate)
            }
        }
        (Ty::Enum(vocab), Value::String(s)) => {
            if vocab.contains(s) {
                Ok(())
            } else {
                Err(Reason::NotInVocabulary)
            }
        }
        (Ty::Sentence(allowed), Value::String(s)) => {
            if allowed.contains(&s.as_str()) {
                Ok(())
            } else {
                Err(Reason::NotInVocabulary)
            }
        }
        (Ty::Array(of), Value::Array(items)) => {
            path.push("[]");
            let result = items.iter().try_for_each(|item| check(of, item, path));
            if result.is_ok() {
                path.pop();
            }
            result
        }
        (Ty::Object(fields), Value::Object(map)) => {
            for (key, inner) in map {
                let Some((name, ty)) = fields.iter().find(|(name, _)| *name == key.as_str()) else {
                    return Err(Reason::UnknownKey);
                };
                path.push(*name);
                check(ty, inner, path)?;
                path.pop();
            }
            Ok(())
        }
        (Ty::OneOf(options), other) => {
            if options.iter().any(|ty| check(ty, other, &mut Vec::new()).is_ok()) {
                Ok(())
            } else {
                Err(Reason::WrongType)
            }
        }
        _ => Err(Reason::WrongType),
    }
}

/// Fail-closed validation of a projected answer against the tool's schema.
pub fn validate(tool: &str, projected: &Value) -> Result<(), SchemaError> {
    let name = sendable(tool);
    let Some(schema) = schema_for(name) else {
        return Err(SchemaError { tool: name, path: String::new(), reason: Reason::UnknownTool });
    };
    let mut path = Vec::new();
    check(&schema, projected, &mut path)
        .map_err(|reason| SchemaError { tool: name, path: join(&path), reason })
}

/// A projected answer that [`validate`] accepted. The field is private to this module and [`validated`] is
/// the only constructor, so a value of this type is proof the positive schema passed: the coach's tool-result
/// message ([`super::wire::ToolMessage`]) can be built from nothing else.
#[derive(Clone, PartialEq)]
pub struct Validated(Value);

impl Validated {
    /// The validated value (what the "what the model can see" drawer shows).
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// The compact JSON text that goes into the tool message, byte for byte.
    pub fn compact(&self) -> String {
        self.0.to_string()
    }
}

impl std::fmt::Debug for Validated {
    /// Never the data: only its size.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Validated({} bytes)", self.compact().len())
    }
}

/// [`validate`], keeping the proof: `Ok` hands the value back wrapped in [`Validated`].
pub fn validated(tool: &str, projected: Value) -> Result<Validated, SchemaError> {
    validate(tool, &projected)?;
    Ok(Validated(projected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dates_are_plain_days_only() {
        assert!(is_date("2025-06-14"));
        assert!(!is_date("2025-06-14T20:00:00Z"));
        assert!(!is_date("2025-13-01"));
        assert!(!is_date("2025-00-10"));
        assert!(!is_date("2025-06-32"));
        assert!(!is_date("2025/06/14"));
        assert!(!is_date("20250614xx"));
        assert!(!is_date("héllo-wörld"));
        assert!(!is_date(""));
    }

    #[test]
    fn an_unknown_key_is_refused_without_naming_it() {
        let answer = json!({"activities": [], "secret_note": "call 555-0100"});
        let err = validate("list_activities", &answer).expect_err("unknown key");
        assert_eq!(err.reason, Reason::UnknownKey);
        assert!(!err.to_string().contains("secret") && !err.to_string().contains("555"));
    }

    #[test]
    fn a_string_outside_the_vocabulary_is_refused_and_not_echoed() {
        let answer = json!({"activities": [{"date": "2025-06-14", "sport": "free text about my day"}]});
        let err = validate("list_activities", &answer).expect_err("text");
        assert_eq!((err.reason, err.path.as_str()), (Reason::NotInVocabulary, "activities/[]/sport"));
        assert!(!err.to_string().contains("free text"));
    }

    #[test]
    fn a_timestamp_where_a_date_belongs_is_refused() {
        let answer = json!({"activities": [{"date": "2025-06-14T20:00:00Z"}]});
        let err = validate("list_activities", &answer).expect_err("time");
        assert_eq!(err.reason, Reason::NotADate);
    }

    #[test]
    fn the_contract_tool_and_unknown_tools_have_no_schema() {
        assert_eq!(validate("get_contract", &json!({})).expect_err("none").reason, Reason::UnknownTool);
        assert_eq!(validate("who_knows", &json!({})).expect_err("none").tool, "unknown");
    }

    #[test]
    fn an_integer_slot_refuses_a_fraction_and_a_number_slot_accepts_both() {
        assert!(validate("get_data_health", &json!({"schema_version": 3})).is_ok());
        assert!(validate("get_data_health", &json!({"schema_version": 3.5})).is_err());
        assert!(validate("list_activities", &json!({"activities": [{"distance_m": 5.5}, {"distance_m": 5}]})).is_ok());
    }

    #[test]
    fn every_label_table_is_inside_the_label_vocabulary() {
        for metric in ["hrv_status", "training_readiness_level", "training_load_status", "vo2max_sport"] {
            for value in label_values(metric) {
                assert!(Vocab::LabelValue.contains(value), "{metric}/{value}");
            }
        }
        assert!(!Vocab::LabelValue.contains("a sentence"));
    }

    #[test]
    fn the_contract_vocabularies_load() {
        assert!(Vocab::MetricId.contains("steps"));
        assert!(Vocab::SourceScope.contains("device") && !Vocab::SourceScope.contains("any"));
        assert!(Vocab::ScopeOrAny.contains("any"));
        assert!(Vocab::FactId.contains("period.steps") && !Vocab::FactId.contains("steps"));
        assert!(Vocab::Unit.contains("bpm") && !Vocab::Unit.contains("furlongs"));
    }
}
