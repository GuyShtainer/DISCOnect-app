// SPDX-License-Identifier: AGPL-3.0-or-later
//! The read contract as data: `contract.json`, embedded at build time and parsed once.
//!
//! The Python core is the source (`disconect/contract.py`, `insight.py`, `coverage.py`); its test
//! `tests/test_contract_json.py` demands the file be byte-identical to a fresh serialisation of the
//! live tables, so nothing here is re-derived by hand. The loader is total: every field of the file
//! is a field below, and an unknown or missing one is a load error (`deny_unknown_fields`), so a
//! contract edit that the Rust side does not understand cannot slip through. Slice 3A serves only
//! [`Contract::version`] (`app.info`); the rest is for the read methods of later slices.

use std::sync::LazyLock;

use serde::Deserialize;

const CONTRACT_JSON: &str = include_str!("../contract.json");

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetricContract {
    pub metric: String,
    pub unit: String,
    pub cadence: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Conventions {
    pub time: String,
    pub missing_values: String,
    pub sources: String,
    pub privacy: String,
    pub coverage: String,
    pub completeness: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StreamsFor {
    pub metric: String,
    pub source_scope: String,
    pub streams: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComparisonTarget {
    pub metric: String,
    pub source_scope: String,
    pub compared_with: String,
    pub compared_scope: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceBand {
    pub min_days: u32,
    pub label: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InsightContract {
    pub rules: Vec<String>,
    pub confidence_bands: Vec<ConfidenceBand>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageRefinements {
    pub available: String,
    pub unavailable: String,
}

/// The whole file.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub contract_version: String,
    pub conventions: Conventions,
    pub source_scopes: Vec<String>,
    /// The sample metrics a day's completeness is measured for (7b-12).
    pub per_minute_metrics: Vec<String>,
    pub metrics: Vec<MetricContract>,
    pub labels: Vec<MetricContract>,
    pub streams_for: Vec<StreamsFor>,
    pub session_streams: Vec<String>,
    pub session_streams_for: Vec<StreamsFor>,
    pub sparse_metrics: Vec<String>,
    pub comparison_targets: Vec<ComparisonTarget>,
    pub insight: InsightContract,
    pub coverage_refinements: CoverageRefinements,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("contract.json does not parse: {0}")]
    Parse(String),
    #[error("contract_version is not an integer")]
    Version,
}

static LOADED: LazyLock<Result<Contract, ContractError>> = LazyLock::new(|| {
    serde_json::from_str(CONTRACT_JSON).map_err(|e| ContractError::Parse(e.to_string()))
});

impl Contract {
    /// The embedded contract, parsed on first use.
    pub fn get() -> Result<&'static Contract, ContractError> {
        LOADED.as_ref().map_err(Clone::clone)
    }

    /// `int(CONTRACT_VERSION)`: what `app.info.contract` reports.
    pub fn version(&self) -> Result<i64, ContractError> {
        self.contract_version
            .parse()
            .map_err(|_| ContractError::Version)
    }

    /// The metric's definition among the numeric metrics (`contract.metric`).
    pub fn metric(&self, name: &str) -> Option<&MetricContract> {
        self.metrics.iter().find(|m| m.metric == name)
    }

    /// `'sample'` or `'daily'` for a numeric metric, None for anything else (`contract.cadence_for`).
    pub fn cadence_for(&self, name: &str) -> Option<&str> {
        self.metric(name).map(|m| m.cadence.as_str())
    }

    /// `metric in contract.SPARSE_METRICS`.
    pub fn is_sparse(&self, name: &str) -> bool {
        self.sparse_metrics.iter().any(|m| m == name)
    }

    /// Unit of a numeric or label metric (`contract.unit_for`).
    pub fn unit_for(&self, name: &str) -> Option<&str> {
        self.metrics
            .iter()
            .chain(&self.labels)
            .find(|m| m.metric == name)
            .map(|m| m.unit.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> &'static Contract {
        match Contract::get() {
            Ok(c) => c,
            Err(e) => unreachable!("contract.json must load: {e}"),
        }
    }

    #[test]
    fn every_field_loads_and_the_version_is_two() {
        let c = contract();
        assert_eq!(c.version(), Ok(2));
        assert_eq!(c.source_scopes, ["device", "vendor_cloud", "local", "live"]);
        assert_eq!(c.per_minute_metrics, ["heart_rate", "stress", "respiration_rate", "energy_reserve"]);
        assert_eq!(c.session_streams, ["json:live"]);
        assert_eq!(c.session_streams_for.len(), 5);
        assert!(c.metrics.len() > 50 && c.labels.len() == 5);
        assert!(c.streams_for.len() > 70 && c.sparse_metrics.len() > 10);
        assert_eq!(c.comparison_targets.len(), 4);
        assert_eq!(c.insight.rules.len(), 3);
        let bands: Vec<_> = c
            .insight
            .confidence_bands
            .iter()
            .map(|b| (b.min_days, b.label.as_str()))
            .collect();
        assert_eq!(bands, [(8, "high"), (5, "medium"), (3, "low")]);
        assert_ne!(
            c.coverage_refinements.available,
            c.coverage_refinements.unavailable
        );
        for text in [
            &c.conventions.time,
            &c.conventions.missing_values,
            &c.conventions.sources,
            &c.conventions.privacy,
            &c.conventions.coverage,
            &c.conventions.completeness,
        ] {
            assert!(!text.is_empty());
        }
    }

    #[test]
    fn lookups_match_the_python_helpers() {
        let c = contract();
        assert_eq!(c.unit_for("heart_rate"), Some("bpm"));
        assert_eq!(c.unit_for("hrv_status"), Some("label"));
        assert_eq!(c.unit_for("not_a_metric"), None);
        assert_eq!(c.metric("steps").map(|m| m.cadence.as_str()), Some("daily"));
        assert!(
            c.metric("hrv_status").is_none(),
            "labels are not numeric metrics"
        );
    }

    #[test]
    fn metric_names_are_unique_and_scopes_are_declared() {
        let c = contract();
        let mut names: Vec<_> = c
            .metrics
            .iter()
            .chain(&c.labels)
            .map(|m| m.metric.as_str())
            .collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
        assert!(
            c.streams_for
                .iter()
                .all(|s| c.source_scopes.contains(&s.source_scope) && !s.streams.is_empty())
        );
    }

    #[test]
    fn an_unknown_field_is_a_load_error() {
        let result: Result<Contract, _> =
            serde_json::from_str(r#"{"contract_version":"1","surprise":1}"#);
        assert!(result.is_err());
    }
}
