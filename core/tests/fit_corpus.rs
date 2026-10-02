// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `fit` module against the Python oracle on a real export corpus (health data: never
//! prints values, only stems and JSON paths). Opt in with
//! `DISCONECT_TEST_FIT_DIR=<dir of *.fit> DISCONECT_TEST_FIT_EXPECTED=<dir of <stem>.expected.json>
//!  cargo test --test fit_corpus -- --ignored --nocapture`.

mod common;

use std::fs;
use std::path::PathBuf;

use common::decoded_cmp::compare_outcome;
use disconect_core::fit::decode_fit;

#[test]
#[ignore = "needs the real export corpus (DISCONECT_TEST_FIT_DIR / DISCONECT_TEST_FIT_EXPECTED)"]
fn corpus_matches_the_oracle() {
    let dir =
        PathBuf::from(std::env::var("DISCONECT_TEST_FIT_DIR").expect("DISCONECT_TEST_FIT_DIR"));
    let expected_dir = PathBuf::from(
        std::env::var("DISCONECT_TEST_FIT_EXPECTED").expect("DISCONECT_TEST_FIT_EXPECTED"),
    );
    let mut stems: Vec<String> = fs::read_dir(&dir)
        .expect("read corpus dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter_map(|n| n.strip_suffix(".fit").map(str::to_string))
        .collect();
    stems.sort();
    let total = stems.len();
    let (mut identical, mut accepted) = (0usize, 0usize);
    let mut mismatches = Vec::new();
    for stem in &stems {
        let bytes = fs::read(dir.join(format!("{stem}.fit"))).expect("read fit");
        let expected: serde_json::Value = serde_json::from_slice(
            &fs::read(expected_dir.join(format!("{stem}.expected.json"))).expect("read expected"),
        )
        .expect("parse expected");
        let mut file_accepted = 0usize;
        match compare_outcome(&expected, &decode_fit(&bytes), &mut file_accepted) {
            Ok(()) => identical += 1,
            Err(path) => mismatches.push(format!("{stem}: {path}")),
        }
        accepted += file_accepted;
    }
    println!("{identical}/{total} identical");
    println!("digit-vs-name string pairs accepted: {accepted}");
    for line in &mismatches {
        println!("MISMATCH {line}");
    }
    assert!(
        mismatches.is_empty(),
        "{} corpus files differ",
        mismatches.len()
    );
}
