// SPDX-License-Identifier: AGPL-3.0-or-later
mod common;

use common::{PASSPHRASE, fixtures};
use disconect_core::keys::{self, KeyError};
use serde_json::Value;

fn fixture_doc() -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixtures().join("test.keys.json")).unwrap()).unwrap()
}

fn key_file_from(doc: &Value) -> keys::KeyFile {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k.keys.json");
    std::fs::write(&path, doc.to_string()).unwrap();
    keys::read_key_file(&path).unwrap()
}

#[test]
fn fixture_unlocks_and_key_id_matches() {
    let kf = keys::read_key_file(&fixtures().join("test.keys.json")).unwrap();
    let master = keys::unlock_with_passphrase(&kf, PASSPHRASE).unwrap();
    assert_eq!(keys::key_id_for(&master), kf.key_id);
    assert_eq!(hex::encode(kf.key_id), fixture_doc()["key_id"].as_str().unwrap());
    let hex_key = keys::db_key_hex(&master);
    assert_eq!(hex_key.len(), 64);
    assert!(hex_key.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn wrong_passphrase_is_refused() {
    let kf = keys::read_key_file(&fixtures().join("test.keys.json")).unwrap();
    assert!(matches!(keys::unlock_with_passphrase(&kf, "not the passphrase"), Err(KeyError::WrongPassphrase)));
}

#[test]
fn tampered_ct_is_wrong_passphrase() {
    let mut doc = fixture_doc();
    let ct = doc["wraps"][0]["ct"].as_str().unwrap().to_string();
    // Flip the first base64 character to a different valid one: still valid base64, bad tag.
    let first = if ct.starts_with('A') { "B" } else { "A" };
    doc["wraps"][0]["ct"] = Value::String(format!("{first}{}", &ct[1..]));
    let kf = key_file_from(&doc);
    assert!(matches!(keys::unlock_with_passphrase(&kf, PASSPHRASE), Err(KeyError::WrongPassphrase)));
}

fn with_params(edit: impl FnOnce(&mut Value)) -> Result<(), KeyError> {
    let mut doc = fixture_doc();
    edit(&mut doc["wraps"][0]["params"]);
    let kf = key_file_from(&doc);
    keys::unlock_with_passphrase(&kf, PASSPHRASE).map(|_| ())
}

#[test]
fn bad_kdf_params_are_corrupt() {
    let corrupt = |r: Result<(), KeyError>| matches!(r, Err(KeyError::KeyFileCorrupt(_)));
    assert!(corrupt(with_params(|p| p["p"] = 2.into())), "p = 2");
    assert!(corrupt(with_params(|p| p["v"] = 16.into())), "v = 0x10");
    assert!(corrupt(with_params(|p| p["m_kib"] = 1024.into())), "below the memory floor");
    assert!(corrupt(with_params(|p| p["t"] = 1.into())), "below the time floor");
    assert!(corrupt(with_params(|p| p["m_kib"] = 4_194_305u64.into())), "above the memory ceiling");
    assert!(corrupt(with_params(|p| p["t"] = 21.into())), "above the time ceiling");
    assert!(corrupt(with_params(|p| drop(p.as_object_mut().unwrap().remove("v")))), "missing key");
    assert!(corrupt(with_params(|p| p["extra"] = 1.into())), "extra key");
}

#[test]
fn malformed_files_are_corrupt_or_missing() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(keys::read_key_file(&dir.path().join("nope")), Err(KeyError::KeyFileMissing(_))));
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, r#"{"format":"other"}"#).unwrap();
    assert!(matches!(keys::read_key_file(&bad), Err(KeyError::KeyFileCorrupt(_))));
    let mut doc = fixture_doc();
    doc["format_version"] = 2.into();
    std::fs::write(&bad, doc.to_string()).unwrap();
    assert!(matches!(keys::read_key_file(&bad), Err(KeyError::KeyFileCorrupt(_))));
}

#[test]
fn passphrase_is_nfc_normalised() {
    // "e" + combining acute (NFD) and the precomposed form are the same passphrase.
    assert_eq!(*keys::normalise_passphrase("e\u{301}"), "\u{e9}".as_bytes());
}
