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

/// Put back, after `Command::env_clear()`, the three variables a child needs to start inside the iOS
/// simulator. Measured 2026-10-06 (12-C, bisected on `cli_import_into_a_moved_legacy_folder...`):
/// `DYLD_ROOT_PATH` alone is not enough (without it dyld aborts: "DYLD_ROOT_PATH not set for simulator
/// program"; with it alone the child still dies with SIGTRAP in `libsystem_featureflags`), and that library
/// also needs `SIMULATOR_ROOT` and `SIMULATOR_SHARED_RESOURCES_DIRECTORY`. Every other `DYLD_*`,
/// `SIMULATOR_*`, `TMPDIR` and `__CF_*` name stayed cleared and was not needed. Only on `target_os = "ios"`;
/// elsewhere a no-op, so the desktop tests are unchanged.
pub fn simulator_env(cmd: &mut std::process::Command) -> &mut std::process::Command {
    if cfg!(target_os = "ios") {
        for name in ["DYLD_ROOT_PATH", "SIMULATOR_ROOT", "SIMULATOR_SHARED_RESOURCES_DIRECTORY"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
    }
    cmd
}
