// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub const PASSPHRASE: &str = "core-test-passphrase-2026";

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Copy the fixture key file to `<db>.keys.json` (the fixtures themselves stay read-only).
pub fn install_key(db: &Path) -> PathBuf {
    let target = disconect_core::keys::sibling_with_suffix(db, ".keys.json");
    std::fs::copy(fixtures().join("test.keys.json"), &target).expect("copy key file");
    target
}

/// A temp dir holding a copy of the empty encrypted v3 fixture and its key file.
pub fn encrypted_copy() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("store.hbdb");
    std::fs::copy(fixtures().join("empty-v3.hbdb"), &db).expect("copy db");
    install_key(&db);
    (dir, db)
}

pub mod convergence;
pub mod decoded_cmp;
