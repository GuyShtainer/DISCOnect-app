// SPDX-License-Identifier: AGPL-3.0-or-later
//! Opt-in: `DISCONECT_TEST_DB=<db> DISCONECT_TEST_PASSPHRASE_FILE=<file> cargo test --test real_store -- --ignored --nocapture`
//! Prints counts only, never values.

use disconect_core::keys::PassphraseSource;
use disconect_core::store;

#[test]
#[ignore]
fn opens_a_real_store_read_only() {
    let db = std::env::var("DISCONECT_TEST_DB").expect("DISCONECT_TEST_DB");
    let pass_file = std::env::var("DISCONECT_TEST_PASSPHRASE_FILE").expect("DISCONECT_TEST_PASSPHRASE_FILE");
    let pass = std::fs::read_to_string(pass_file).unwrap();
    let pass = pass.trim_end_matches(['\n', '\r']);
    let ro = store::open_read_only(std::path::Path::new(&db), PassphraseSource::Explicit(pass)).unwrap();
    assert_eq!(ro.user_version().unwrap(), 3);
    println!("cipher_version = {}", ro.cipher_version().unwrap_or_default());
    let counts = store::table_counts(ro.conn()).unwrap();
    for (name, n) in &counts {
        println!("{name}: {n}");
    }
    let raw = counts.iter().find(|(n, _)| n == "raw_records").map(|(_, n)| *n).unwrap_or(0);
    assert!(raw > 0, "raw_records is empty");
}
