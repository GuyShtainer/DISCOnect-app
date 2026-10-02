//! Evidence test for Bet 3: the Rust command parses the REAL daily CSV exported by the Python
//! oracle (git-ignored `data/daily.csv`). Ignored by default because it needs local data:
//!     cargo test --test real_csv -- --ignored --nocapture

use std::path::PathBuf;

#[test]
#[ignore]
fn real_daily_csv_yields_step_rows() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data/daily.csv");
    let text = std::fs::read_to_string(&path).expect("export data/daily.csv with the Python CLI first");
    let rows = disconect_app_lib::parse_daily_steps(&text).expect("parse");
    assert!(rows.len() >= 14, "expected ≥14 days with steps, got {}", rows.len());
    assert!(rows.iter().all(|r| r.steps > 0 && r.steps < 100_000));
    assert!(rows.iter().all(|r| r.date.len() == 10));
    println!(
        "REAL CSV: {} days with steps, {}..{}, source {}",
        rows.len(),
        rows.first().unwrap().date,
        rows.last().unwrap().date,
        rows[0].source
    );
}
