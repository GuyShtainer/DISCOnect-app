// SPDX-License-Identifier: AGPL-3.0-or-later
//! `canon` against the Python oracle: byte identity of canonical JSON on the committed synthetic
//! set, and (ignored, opt-in) on the records of a real account export, by hash and length only.

mod common;

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use disconect_core::canon::{self, CanonError, Value};
use sha2::{Digest, Sha256};

fn canon_dir() -> PathBuf {
    common::fixtures().join("canon")
}

fn case_names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(canon_dir())
        .expect("read canon dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter_map(|n| n.strip_suffix(".expected").map(str::to_string))
        .collect();
    names.sort();
    names
}

#[test]
fn every_synthetic_case_is_byte_identical_and_idempotent() {
    let names = case_names();
    assert!(
        names.len() >= 20,
        "expected at least 20 canonical-JSON cases, found {}",
        names.len()
    );
    let mut failures = Vec::new();
    for name in &names {
        let input = fs::read(canon_dir().join(format!("{name}.json"))).expect("read input");
        let expected =
            fs::read(canon_dir().join(format!("{name}.expected"))).expect("read expected");
        match canon::canonical(&input) {
            Ok(got) if got == expected => {}
            Ok(got) => failures.push(format!("{name}: got {}", String::from_utf8_lossy(&got))),
            Err(error) => failures.push(format!("{name}: {error}")),
        }
        match canon::canonical(&expected) {
            Ok(again) if again == expected => {}
            other => failures.push(format!("{name}: not idempotent ({other:?})")),
        }
    }
    assert!(
        failures.is_empty(),
        "canonical JSON differs:\n{}",
        failures.join("\n")
    );
}

#[test]
fn py_str_matches_python_str_of_the_parsed_value() {
    let pairs: Vec<(String, String)> = serde_json::from_slice(
        &fs::read(canon_dir().join("py_str.json")).expect("read py_str.json"),
    )
    .expect("parse py_str.json");
    assert!(pairs.len() >= 25);
    for (text, expected) in &pairs {
        let value = canon::parse(text.as_bytes()).expect("parse scalar");
        assert_eq!(
            &canon::py_str(&value).expect("py_str"),
            expected,
            "input {text}"
        );
    }
}

#[test]
fn containers_are_refused_as_keys() {
    for text in ["[]", "{}", "[1]", r#"{"a":1}"#] {
        let value = canon::parse(text.as_bytes()).expect("parse");
        assert!(
            matches!(canon::py_str(&value), Err(CanonError::Unsupported(_))),
            "{text}"
        );
    }
}

#[test]
fn forms_the_export_never_uses_are_refused_not_imitated() {
    let cases: [(&str, &[u8]); 7] = [
        ("NaN", b"[NaN]"),
        ("Infinity", b"{\"a\": Infinity}"),
        ("-Infinity", b"-Infinity"),
        ("2^64", b"18446744073709551616"),
        ("lone high surrogate", br#""\ud800""#),
        ("lone low surrogate", br#""\udc00x""#),
        ("invalid utf-8", &[b'"', 0xc3, 0x28, b'"']),
    ];
    for (name, input) in cases {
        assert!(
            matches!(canon::canonical(input), Err(CanonError::Unsupported(_))),
            "{name}"
        );
    }
}

#[test]
fn int_versus_float_follows_the_literal_text() {
    assert_eq!(canon::parse(b"70").expect("int"), Value::Int(70));
    assert_eq!(canon::parse(b"70.0").expect("float"), Value::Float(70.0));
    assert_eq!(canon::parse(b"7e1").expect("float"), Value::Float(70.0));
    assert_eq!(
        canon::canonical(b"[7e1, 70, 70.0]").expect("canonical"),
        b"[70.0,70,70.0]".to_vec()
    );
}

// ---- the real-export gate (health data: counts only, never a value) ----

fn walk_json(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            walk_json(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
}

/// (stream file stem, canonical sha256, byte length) per oracle row.
fn read_tsv_pairs(dir: &Path) -> Vec<(String, String, usize)> {
    let mut pairs = Vec::new();
    for entry in fs::read_dir(dir)
        .expect("read TSV dir")
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("tsv") {
            continue;
        }
        for line in fs::read_to_string(&path).expect("read tsv").lines() {
            let columns: Vec<&str> = line.split('\t').collect();
            assert_eq!(columns.len(), 3, "TSV row shape");
            let stem = path.file_stem().and_then(|n| n.to_str()).unwrap_or("?");
            pairs.push((
                stem.to_string(),
                columns[1].to_string(),
                columns[2].parse().expect("byte length"),
            ));
        }
    }
    pairs
}

#[test]
#[ignore = "needs the real export (DISCONECT_TEST_EXPORT_DIR) and the oracle hashes (DISCONECT_TEST_CANON_TSV_DIR)"]
fn real_export_records_are_hash_identical_to_the_oracle_and_idempotent() {
    let export = PathBuf::from(
        std::env::var("DISCONECT_TEST_EXPORT_DIR").expect("DISCONECT_TEST_EXPORT_DIR"),
    );
    let tsv_dir = PathBuf::from(
        std::env::var("DISCONECT_TEST_CANON_TSV_DIR").expect("DISCONECT_TEST_CANON_TSV_DIR"),
    );
    let expected = read_tsv_pairs(&tsv_dir);

    let mut files = Vec::new();
    walk_json(&export, &mut files);
    files.sort();
    let (mut unparsed, mut unsupported, mut records, mut not_idempotent) =
        (0usize, 0usize, 0usize, 0usize);
    let mut seen: HashSet<(String, usize)> = HashSet::new();
    for path in &files {
        let bytes = fs::read(path).expect("read export file");
        let parsed = match canon::parse(&bytes) {
            Ok(value) => value,
            Err(CanonError::Unsupported(_)) => {
                unsupported += 1;
                continue;
            }
            Err(CanonError::Syntax(_)) => {
                unparsed += 1;
                continue;
            }
        };
        let values: Vec<&Value> = match &parsed {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        for record in values {
            let bytes = canon::dumps(record);
            records += 1;
            match canon::canonical(&bytes) {
                Ok(again) if again == bytes => {}
                _ => not_idempotent += 1,
            }
            seen.insert((hex::encode(Sha256::digest(&bytes)), bytes.len()));
        }
    }
    let mut unmatched_by_stream: BTreeMap<&str, usize> = BTreeMap::new();
    for (stream, hash, length) in &expected {
        if !seen.contains(&(hash.clone(), *length)) {
            *unmatched_by_stream.entry(stream.as_str()).or_default() += 1;
        }
    }
    let matched = expected.len() - unmatched_by_stream.values().sum::<usize>();
    println!("unmatched per stream file: {unmatched_by_stream:?}");
    println!(
        "json files: {}, not parseable: {unparsed}, refused as unsupported: {unsupported}, records seen: {records}, \
         TSV rows: {}, matched: {matched}, not idempotent: {not_idempotent}",
        files.len(),
        expected.len()
    );
    assert_eq!(
        unsupported, 0,
        "a file used a form the canon module refuses"
    );
    assert_eq!(
        not_idempotent, 0,
        "canonicalisation is not idempotent on some record"
    );
    assert_eq!(
        matched,
        expected.len(),
        "some oracle records are not byte-identical"
    );
}
