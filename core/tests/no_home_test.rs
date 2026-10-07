// SPDX-License-Identifier: AGPL-3.0-or-later
//! With no `$HOME` (unset or empty) and no `$DISCONECT_DB` there is no default store: the binary says so and exits 1,
//! and never falls back to the password database. The Python twin is `tests/test_home.py`.

use std::process::{Command, Output};

const NO_STORE: &str = "error: no store: pass --db <path> or set DISCONECT_DB (HOME is not set)";

fn run(args: &[&str], home: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_disconect-core"));
    command.env_remove("DISCONECT_DB").args(args);
    match home {
        Some(value) => command.env("HOME", value),
        None => command.env_remove("HOME"),
    };
    command.stdin(std::process::Stdio::null()).output().expect("run the binary")
}

#[test]
fn serve_and_mcp_without_a_home_say_no_store_and_exit_1() {
    for home in [None, Some("")] {
        for args in [&[][..], &["mcp"][..]] {
            let out = run(args, home);
            assert_eq!(out.status.code(), Some(1), "{args:?} with HOME {home:?}");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(stderr.lines().any(|l| l == NO_STORE), "{args:?} with HOME {home:?}: {stderr}");
        }
    }
}

#[test]
fn a_db_override_needs_no_home() {
    let dir = tempfile::tempdir().expect("tmp");
    let db = dir.path().join("x.db");
    let out = Command::new(env!("CARGO_BIN_EXE_disconect-core"))
        .env_remove("HOME")
        .env("DISCONECT_DB", &db)
        .args(["mcp"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run the binary");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("HOME is not set"), "{stderr}");
}
