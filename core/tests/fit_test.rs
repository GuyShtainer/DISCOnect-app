// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `fit` module against the Python oracle's answers on the synthetic fixtures.

mod common;

use std::fs;

use common::decoded_cmp::compare_outcome;
use disconect_core::fit::{decode_fit, scan_clock_offsets};

fn fixture_names() -> Vec<String> {
    let dir = common::fixtures().join("synthetic");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .expect("read synthetic dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter_map(|n| n.strip_suffix(".fit.bin").map(str::to_string))
        .collect();
    names.sort();
    names
}

#[test]
fn synthetic_fixtures_match_the_oracle() {
    let dir = common::fixtures().join("synthetic");
    let names = fixture_names();
    assert!(names.len() >= 11, "expected at least 11 synthetic fixtures");
    let mut accepted = 0usize;
    let mut failures = Vec::new();
    for name in &names {
        let bytes = fs::read(dir.join(format!("{name}.fit.bin"))).expect("read fixture");
        let expected: serde_json::Value = serde_json::from_slice(
            &fs::read(dir.join(format!("{name}.expected.json"))).expect("read expected"),
        )
        .expect("parse expected");
        let outcome = decode_fit(&bytes);
        if let Err(path) = compare_outcome(&expected, &outcome, &mut accepted) {
            failures.push(format!("{name}: first difference at {path}"));
        }
    }
    println!("digit-vs-name string pairs accepted: {accepted}");
    assert!(
        failures.is_empty(),
        "fixtures differ:\n{}",
        failures.join("\n")
    );
}

#[test]
fn scan_clock_offsets_agrees_with_the_full_decode() {
    let dir = common::fixtures().join("synthetic");
    for name in fixture_names() {
        let bytes = fs::read(dir.join(format!("{name}.fit.bin"))).expect("read fixture");
        let scanned = scan_clock_offsets(&bytes);
        match decode_fit(&bytes) {
            Ok(decoded) => assert_eq!(scanned, decoded.offsets, "{name}"),
            Err(_) => assert!(scanned.is_empty(), "{name}"),
        }
    }
}

// The next three tests pin the behaviour the Python decoder shows on the same mutated bytes.

#[test]
fn truncated_or_trailing_input_fails_with_a_stable_kind_and_the_partial_span() {
    let bytes = fs::read(common::fixtures().join("synthetic/skin_temp.fit.bin")).expect("read");
    for cut in [
        1,
        5,
        13,
        bytes.len() / 2,
        bytes.len() - 3,
        bytes.len() - 2,
        bytes.len() - 1,
    ] {
        let error = decode_fit(&bytes[..cut]).expect_err("truncated input must fail");
        assert_eq!(error.kind, "unrecognized_payload", "cut {cut}");
        // The stream is named only once the file_id data message (ending at byte 49) is read.
        assert_eq!(error.stream.is_some(), cut >= 49, "cut {cut}");
    }
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(&[0, 1, 2]);
    let error = decode_fit(&trailing).expect_err("trailing bytes must fail");
    assert_eq!(error.stream.as_deref(), Some("fit:skin_temp"));
    assert!(error.start_utc.is_some());
}

#[test]
fn empty_input_decodes_to_an_empty_unknown_stream() {
    let decoded = decode_fit(&[]).expect("empty input is not an error");
    assert_eq!(decoded.stream, "fit:unknown");
    assert_eq!(decoded.record_count(), 0);
}

#[test]
fn crc_mismatches_are_warnings_not_failures() {
    let bytes = fs::read(common::fixtures().join("synthetic/skin_temp.fit.bin")).expect("read");
    let mut data = bytes.clone();
    let last = data.len() - 1;
    data[last] ^= 0xFF;
    assert_eq!(
        decode_fit(&data)
            .expect("bad data CRC still decodes")
            .warnings
            .len(),
        1
    );
    // A bad header CRC also breaks the file CRC, which covers the header: two warnings.
    let mut header = bytes;
    header[12] ^= 0xFF;
    assert_eq!(
        decode_fit(&header)
            .expect("bad header CRC still decodes")
            .warnings
            .len(),
        2
    );
}
