// SPDX-License-Identifier: AGPL-3.0-or-later
//! Two cfgs for tests that need a neighbour of this crate in the monorepo (`projects/`), none of which a
//! standalone checkout carries; those tests are `ignore`d there, by name and with a reason, instead of failing:
//! * `monorepo`: the Python oracle (`../../disconect`) with its committed synthetic stores and transcripts;
//! * `ble_lab`: the Bluetooth lab (`../../ble-lab`), development builds only.
//! The core crate's own pins (`../../core/tests/fixtures`) are not behind either.

use std::path::Path;

fn main() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (cfg, relative) in [("monorepo", "../../disconect/tests/fixtures/serve"), ("ble_lab", "../../ble-lab")] {
        println!("cargo::rustc-check-cfg=cfg({cfg})");
        // A path that does not exist would make cargo rerun this script every time.
        if here.join(relative).is_dir() {
            println!("cargo::rerun-if-changed={relative}");
            println!("cargo::rustc-cfg={cfg}");
        }
    }
    tauri_build::build()
}
