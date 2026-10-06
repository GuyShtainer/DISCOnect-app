// SPDX-License-Identifier: AGPL-3.0-or-later
//! Store comparison and synthetic-data helpers shared by the relay tests (12-B's `fingerprint` and
//! `daily_rows`, moved here unchanged in 12-E so `pair_test.rs` reuses them).
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::fixtures;

pub fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).expect("count")
}

pub fn fit_drop(dir: &Path, name: &str, stems: &[&str]) -> PathBuf {
    let target = dir.join(name);
    fs::create_dir_all(&target).expect("mkdir");
    for stem in stems {
        fs::copy(
            fixtures().join("synthetic").join(format!("{stem}.fit.bin")),
            target.join(format!("{stem}.fit")),
        )
        .expect("copy fixture");
    }
    target
}

pub fn export_with_uds(dir: &Path, name: &str, day: &str, steps: i64) -> PathBuf {
    let root = dir.join(name);
    let path = root.join(format!(
        "DI_CONNECT/DI-Connect-Aggregator/UDSFile_{day}_{day}.json"
    ));
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(
        path,
        format!(
            r#"[{{"calendarDate":"{day}","totalSteps":{steps},"wellnessEndTimeGmt":"{day}T12:00:00.0","wellnessStartTimeGmt":"{day}T00:00:00.0"}}]"#
        ),
    )
    .expect("write");
    fs::create_dir_all(root.join("DI_CONNECT/DI-Connect-Uploaded-Files")).expect("mkdir");
    root
}

pub const MONITORING: [&str; 2] = ["monitoring_timestamp16", "monitoring_cycles_resolution"];

pub type Fingerprint = (BTreeSet<String>, BTreeSet<String>, Vec<i64>);

/// Raw keys and bytes, ranges and table counts: what a second device must reproduce.
pub fn fingerprint(conn: &Connection) -> Fingerprint {
    let collect = |sql: &str| -> BTreeSet<String> {
        let mut stmt = conn.prepare(sql).expect("prepare");
        stmt.query_map([], |r| r.get(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    };
    let raw = collect(
        "SELECT stream || '|' || source_key || '|' || payload_hash || '|' || transport || '|' || imported_at FROM raw_records",
    );
    let ranges = collect("SELECT stream || '|' || from_day || '|' || to_day FROM export_ranges");
    let counts = [
        "SELECT count(*) FROM daily_metrics",
        "SELECT count(*) FROM daily_labels",
        "SELECT count(*) FROM metric_samples",
        "SELECT count(*) FROM monitoring_intervals",
        "SELECT count(*) FROM clock_offsets",
    ]
    .map(|sql| count(conn, sql))
    .to_vec();
    (raw, ranges, counts)
}

pub fn daily_rows(conn: &Connection) -> BTreeSet<String> {
    let mut stmt = conn
        .prepare(
            "SELECT 'm|' || date || '|' || metric || '|' || source_scope || '|' || value || '|' || COALESCE(observed_utc, '') \
             FROM daily_metrics UNION ALL \
             SELECT 'l|' || date || '|' || metric || '|' || source_scope || '|' || label || '|' || COALESCE(observed_utc, '') \
             FROM daily_labels",
        )
        .expect("prepare");
    stmt.query_map([], |r| r.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

