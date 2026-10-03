// SPDX-License-Identifier: AGPL-3.0-or-later
//! The read layer as a library (pitch 11c): queries over the store that return `serde_json::Value`
//! decoded by SQLite storage class, with `serve` as a thin transport over them. The phone (row 12)
//! has no child processes, so this is a library first and a protocol second.
//!
//! Slice 3A scaffolded it; slice 3B adds `insight` (`data.facts`), `queries` (the sample-day
//! aggregates it reads) and `numerics` (`fsum` and the exact `stdev` of Python's `statistics`);
//! slice 3C adds `coverage` (the ledger) and the calendar half of `queries` (`data.metric`,
//! `data.today`); slice 3D adds `health` (`data.health`, `import.last`) and the import progress hook
//! (`sources::import_path`) that `import.run` streams.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use crate::contract::ContractError;

pub mod coverage;
pub mod health;
pub mod insight;
pub mod numerics;
pub mod pyrepr;
pub mod queries;

/// Why a read failed, before it has a protocol code (`serve` maps it; a phone shell maps it its own way).
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The store could not be read (`database`).
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    /// Python raised a `ValueError` here (`bad_params`): a malformed stored date or time, a value that
    /// cannot be written as JSON.
    #[error("{0}")]
    Value(String),
    /// Python raised something unexpected here (`internal`, reported as `unexpected <name>`).
    #[error("unexpected {0}")]
    Unexpected(&'static str),
    #[error(transparent)]
    Contract(#[from] ContractError),
}

/// The protocol methods the oracle has that this core does not answer yet. Each would answer
/// `unknown_method`; `tools/serve_diff.py` counts a Python success against it as "not yet ported",
/// never as a difference. A test keeps this list and `METHODS` disjoint and complete. Slice 3D
/// ported the last three (`data.health`, `import.last`, `import.run`), so none is left.
pub const DEFERRED_METHODS: &[&str] = &[];
