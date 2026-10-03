// SPDX-License-Identifier: AGPL-3.0-or-later
//! The coverage ledger against the Python oracle's committed answers (`ledger-synthetic*.json.gz`,
//! written by `tests/gen_serve_fixtures.py` from `coverage.ledger`), on the synthetic store and its
//! schema-v1 twin. `data.health` ports the ledger into the protocol in a later slice; until then no
//! serve request reaches `ledger`, so this is what holds it to the oracle. Values are compared as
//! `serde_json::Value`, whose numbers keep integers and floats apart.

use std::io::Read;
use std::path::{Path, PathBuf};

use disconect_core::contract::Contract;
use disconect_core::read::coverage;
use disconect_core::store;
use serde_json::Value;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../hearthbeat/tests/fixtures/serve")
}

fn gunzip_json(path: &Path) -> Value {
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).expect("fixture"))
        .read_to_string(&mut text)
        .expect("gunzip");
    serde_json::from_str(&text).expect("json")
}

fn check(store_file: &str, ledger_file: &str, refinements: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("store.db");
    std::fs::copy(fixtures().join(store_file), &db).expect("copy store");
    let opened = store::open_read_only_with(&db, None).expect("open");
    let contract = Contract::get().expect("contract");
    let fixture = gunzip_json(&fixtures().join(ledger_file));
    let cases = fixture["cases"].as_array().expect("cases");
    assert!(cases.len() >= 9);
    for case in cases {
        let last_day = case["last_day"].as_str().expect("last_day");
        let window_days = case["window_days"].as_i64().expect("window_days");
        let got = coverage::ledger(opened.conn(), contract, last_day, window_days).expect("ledger");
        assert_eq!(
            got["refinements_available"],
            Value::Bool(refinements),
            "refinements on {store_file}"
        );
        if got != case["result"] {
            let key = got
                .as_object()
                .and_then(|g| {
                    g.keys()
                        .find(|k| got[k.as_str()] != case["result"][k.as_str()])
                })
                .cloned();
            unreachable!(
                "ledger differs for window_days={window_days}: first differing key {key:?}"
            );
        }
    }
}

#[test]
fn the_ledger_equals_the_oracles_on_the_synthetic_store() {
    check("synthetic.hbdb", "ledger-synthetic.json.gz", true);
}

#[test]
fn the_ledger_equals_the_oracles_on_a_schema_v1_store() {
    check("synthetic-v1.hbdb", "ledger-synthetic-v1.json.gz", false);
}

#[test]
fn the_ledger_shows_every_status_gap_truncation_and_drift_somewhere() {
    let fixture = gunzip_json(&fixtures().join("ledger-synthetic.json.gz"));
    let mut statuses = std::collections::BTreeSet::new();
    let (mut truncated, mut drift, mut sparse, mut failures) = (false, false, false, 0);
    for case in fixture["cases"].as_array().expect("cases") {
        let result = &case["result"];
        drift |= !result["map_drift"].as_array().expect("drift").is_empty();
        failures += result["unattributed_failures"].as_i64().expect("count");
        for row in result["ledger"].as_array().expect("rows") {
            truncated |= row["gaps_truncated"] == Value::Bool(true);
            sparse |= row["sparse"] == Value::Bool(true);
            for gap in row["gaps"].as_array().expect("gaps") {
                statuses.insert(gap["status"].as_str().expect("status").to_string());
            }
        }
    }
    assert!(truncated && drift && sparse && failures > 0);
    assert_eq!(
        statuses.into_iter().collect::<Vec<_>>(),
        ["failed", "not_covered", "source_empty"]
    );
}
