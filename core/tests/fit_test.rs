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

/// A minimal FIT file: one `monitoring_info` message (global 103) stating `timestamp` and
/// `local_timestamp` (both uint32, FIT seconds). The CRCs are zero; a mismatch is only a warning.
fn monitoring_info_pair(timestamp: u32, local_timestamp: u32) -> Vec<u8> {
    let mut records = vec![0x40, 0, 0, 103, 0, 2, 253, 4, 0x86, 0, 4, 0x86, 0x00];
    records.extend_from_slice(&timestamp.to_le_bytes());
    records.extend_from_slice(&local_timestamp.to_le_bytes());
    let mut file = vec![14, 0x20, 0x5C, 0x08];
    file.extend_from_slice(&u32::try_from(records.len()).expect("small").to_le_bytes());
    file.extend_from_slice(b".FIT");
    file.extend_from_slice(&[0, 0]);
    file.extend_from_slice(&records);
    file.extend_from_slice(&[0, 0]);
    file
}

#[test]
fn a_clock_offset_beyond_26_hours_is_dropped_and_counted_at_decode() {
    let base: u32 = 1_100_000_000;
    for (delta, kept) in [
        (93_600_i64, true),
        (-93_600, true),
        (93_601, false),
        (-93_601, false),
        (100_000, false),
        (0, true),
    ] {
        let local = u32::try_from(i64::from(base) + delta).expect("fits uint32");
        let bytes = monitoring_info_pair(base, local);
        let decoded = decode_fit(&bytes).expect("a dropped offset is not an error");
        assert_eq!(decoded.offsets.len(), usize::from(kept), "delta {delta}");
        if kept {
            assert_eq!(decoded.offsets[0].offset_s, delta, "delta {delta}");
            assert!(decoded.dropped.is_empty(), "delta {delta}");
        } else {
            assert_eq!(
                decoded.dropped.get("clock_offset_out_of_range"),
                Some(&1),
                "delta {delta}"
            );
        }
        assert_eq!(scan_clock_offsets(&bytes), decoded.offsets, "delta {delta}");
    }
}
