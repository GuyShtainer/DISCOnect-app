// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sets `cfg(monorepo)` when this crate sits in the monorepo beside the Python oracle (`../disconect`),
//! whose committed stores and answer scripts a few tests read. A standalone checkout of the crate does not
//! carry them: those tests are `ignore`d there, by name and with a reason, instead of failing. The pins
//! committed with the crate (`tests/fixtures`, `contract.json`, `mcp.json`) are not behind this cfg.

use std::path::Path;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(monorepo)");
    println!("cargo::rerun-if-changed=build.rs");
    // A path that does not exist would make cargo rerun this script (and rebuild the crate) every time.
    if Path::new(env!("CARGO_MANIFEST_DIR")).join("../disconect/tests/fixtures/serve").is_dir() {
        println!("cargo::rerun-if-changed=../disconect/tests/fixtures/serve");
        println!("cargo::rustc-cfg=monorepo");
    }
}
