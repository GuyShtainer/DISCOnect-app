// SPDX-License-Identifier: AGPL-3.0-or-later
//! The export decoders against the Python oracle on a real account export (health data: never
//! prints values, only counts and JSON paths). Opt in with
//! `DISCONECT_TEST_EXPORT_DIR=<export folder> DISCONECT_TEST_EXPORT_EXPECTED=<json_decoded folder>
//!  cargo test --test export_corpus -- --ignored --nocapture`.
//!
//! `<expected>/<stream with ':' as '_'>.jsonl` holds one `{"decoded", "hash", "key"}` line per
//! stored record; `<expected>/files.json` one `{stream, label, window, written_day,
//! records_in_file}` per recognised file.

mod common;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use common::decoded_cmp::compare;
use disconect_core::canon;
use disconect_core::export::{Step, decode_export};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set")))
}

#[test]
#[ignore = "needs the real export (DISCONECT_TEST_EXPORT_DIR / DISCONECT_TEST_EXPORT_EXPECTED)"]
fn export_decoding_matches_the_oracle() {
    let export = env_path("DISCONECT_TEST_EXPORT_DIR");
    let expected_dir = env_path("DISCONECT_TEST_EXPORT_EXPECTED");
    let mut expected: HashMap<(String, String), (Value, String)> = HashMap::new();
    for entry in fs::read_dir(&expected_dir)
        .expect("read expected dir")
        .filter_map(Result::ok)
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".jsonl") else {
            continue;
        };
        let stream = stem.replacen('_', ":", 1);
        for line in fs::read_to_string(entry.path())
            .expect("read jsonl")
            .lines()
        {
            let parsed: Value = serde_json::from_str(line).expect("parse line");
            let key = parsed["key"].as_str().expect("key").to_string();
            let hash = parsed["hash"].as_str().expect("hash").to_string();
            expected.insert((stream.clone(), key), (parsed["decoded"].clone(), hash));
        }
    }
    let files: Vec<Value> = serde_json::from_slice(
        &fs::read(expected_dir.join("files.json")).expect("read files.json"),
    )
    .expect("parse files.json");

    let decoded_files = decode_export(&export).expect("walk the export");
    let (mut total, mut matched, mut hash_ok, mut no_date) = (0usize, 0usize, 0usize, 0usize);
    let mut mismatches = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    let mut file_mismatches = 0usize;
    for file in &decoded_files {
        let stream = file.info.stream;
        let decode = match &file.loaded {
            Ok(decode) => decode,
            Err((kind, _)) => {
                mismatches.push(format!("{stream}: file failed to load ({kind})"));
                continue;
            }
        };
        assert!(decode.abort.is_none(), "{stream}: decoding aborted");
        let mut stored_here = 0usize;
        for step in &decode.steps {
            match step {
                Step::NoDate => no_date += 1,
                Step::Refused(_) => mismatches.push(format!("{stream}: refused record")),
                Step::Record {
                    key,
                    index,
                    decoded,
                } => {
                    total += 1;
                    stored_here += 1;
                    seen_keys.insert((stream.to_string(), key.clone()));
                    let Some((want, want_hash)) = expected.get(&(stream.to_string(), key.clone()))
                    else {
                        mismatches.push(format!("{stream}: a stored record has no oracle line"));
                        continue;
                    };
                    let actual = serde_json::to_value(decoded.as_ref()).expect("serialize decoded");
                    let mut digit_vs_name = 0usize;
                    match compare(want, &actual, &mut digit_vs_name) {
                        Ok(()) => matched += 1,
                        Err(path) => {
                            mismatches.push(format!("{stream}: decoded differs at {path}"))
                        }
                    }
                    let hash = hex::encode(Sha256::digest(canon::dumps(&decode.records[*index])));
                    if &hash == want_hash {
                        hash_ok += 1;
                    } else {
                        mismatches.push(format!("{stream}: canonical hash differs"));
                    }
                }
            }
        }
        let want_file = files
            .iter()
            .find(|f| f["stream"] == stream && f["label"] == file.info.label.as_str());
        match want_file {
            None => file_mismatches += 1,
            Some(want) => {
                let window = file
                    .info
                    .window
                    .as_ref()
                    .map(|(a, b)| serde_json::json!([a, b]))
                    .unwrap_or(Value::Null);
                let records_in_file = decode.records.len();
                let stored_or_dropped = stored_here
                    + decode
                        .steps
                        .iter()
                        .filter(|s| matches!(s, Step::NoDate))
                        .count();
                if want["window"] != window
                    || want["written_day"]
                        != file
                            .info
                            .written_day
                            .as_deref()
                            .map_or(Value::Null, Value::from)
                    || want["records_in_file"].as_u64() != Some(records_in_file as u64)
                    || stored_or_dropped != records_in_file && stream != "json:readiness"
                {
                    file_mismatches += 1;
                }
            }
        }
    }
    let missing = expected.keys().filter(|k| !seen_keys.contains(*k)).count();
    println!("{matched}/{total} decoded identical; {hash_ok}/{total} canonical hashes identical");
    println!(
        "oracle lines never produced: {missing} of {}; dateless records dropped: {no_date}",
        expected.len()
    );
    println!(
        "files: {} recognised, {} with a name/window/written-day/count mismatch",
        decoded_files.len(),
        file_mismatches
    );
    for line in &mismatches {
        println!("MISMATCH {line}");
    }
    assert!(
        mismatches.is_empty() && missing == 0 && file_mismatches == 0 && total == expected.len()
    );
}
