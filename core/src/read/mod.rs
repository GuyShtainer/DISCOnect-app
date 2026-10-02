// SPDX-License-Identifier: AGPL-3.0-or-later
//! The read layer as a library (pitch 11c): queries over the store that return `serde_json::Value`
//! decoded by SQLite storage class, with `serve` as a thin transport over them. The phone (row 12)
//! has no child processes, so this is a library first and a protocol second.
//!
//! Slice 3A only scaffolds it. What lands here later, in the pitch's order: `insight` (`data.facts`),
//! `coverage` / `queries` (`data.metric`, `data.today`), `health` (`data.health`), then the `import.*`
//! progress hook. Until then each of those methods is absent from [`crate::serve::METHODS`].

/// The protocol methods the oracle has that this core does not answer yet. Each answers
/// `unknown_method`; `tools/serve_diff.py` counts a Python success against it as "not yet ported",
/// never as a difference. A test keeps this list and `METHODS` disjoint and complete.
pub const DEFERRED_METHODS: &[&str] = &[
    "data.facts",
    "data.metric",
    "data.today",
    "data.health",
    "import.last",
    "import.run",
];
