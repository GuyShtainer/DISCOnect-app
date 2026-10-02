// SPDX-License-Identifier: AGPL-3.0-or-later
//! `fsum`, `fmean`, `stdev`, `round(x, 2)` and `_clean`'s `round(x, 3)` against CPython 3.14 on
//! generated vectors (`fixtures/py_numerics_read.json`, written by `hearthbeat/tests/gen_facts_numerics.py`:
//! plain numbers, no health data). Bits must match, not values; a `null` is a case where Python raises
//! and the port must answer `None`. Every case is checked; the test reports its counts and demands 100 %.

use disconect_core::read::numerics::{fmean, fsum, stdev};
use disconect_core::read::queries::{clean, round2};
use serde_json::Value;

fn float(hex: &str) -> f64 {
    f64::from_bits(u64::from_str_radix(hex, 16).expect("16 hex digits"))
}

fn values(packed: &str) -> Vec<f64> {
    assert_eq!(packed.len() % 16, 0);
    (0..packed.len() / 16)
        .map(|i| float(&packed[i * 16..(i + 1) * 16]))
        .collect()
}

fn fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/py_numerics_read.json");
    serde_json::from_slice(&std::fs::read(path).expect("read fixture")).expect("parse fixture")
}

/// `None` must match a JSON null, a float must match its bits.
fn same(got: Option<f64>, want: &Value) -> bool {
    match (got, want.as_str()) {
        (None, None) => want.is_null(),
        (Some(x), Some(hex)) => x.to_bits() == float(hex).to_bits(),
        _ => false,
    }
}

#[test]
fn fsum_fmean_and_stdev_are_bit_identical_to_python() {
    let data = fixture();
    let vectors = data["vectors"].as_array().expect("vectors");
    let (mut total_values, mut wrong, mut checked, mut raised) = (0usize, 0usize, 0usize, 0usize);
    let mut first_wrong: Option<String> = None;
    for (index, case) in vectors.iter().enumerate() {
        let v = values(case["v"].as_str().expect("packed values"));
        total_values += v.len();
        for (name, got, want) in [
            ("fsum", fsum(&v), &case["fsum"]),
            ("fmean", fmean(&v), &case["fmean"]),
            ("stdev", stdev(&v), &case["stdev"]),
        ] {
            checked += 1;
            raised += usize::from(want.is_null());
            if !same(got, want) {
                wrong += 1;
                first_wrong
                    .get_or_insert_with(|| format!("vector #{index} ({} values): {name}", v.len()));
            }
        }
    }
    eprintln!(
        "fsum/fmean/stdev: {} vectors, {total_values} values, {checked} results compared, {raised} where Python raises, {wrong} differ",
        vectors.len()
    );
    assert!(
        total_values >= 100_000,
        "the differential must cover at least 100k values"
    );
    assert!(
        raised > 0,
        "the fixture must include cases where Python raises"
    );
    assert_eq!(wrong, 0, "first difference: {first_wrong:?}");
}

#[test]
fn round_two_and_three_digits_are_bit_identical_to_python() {
    let data = fixture();
    let rounds = data["rounds"].as_array().expect("rounds");
    let mut wrong = 0usize;
    for case in rounds {
        let x = float(case[0].as_str().expect("x"));
        let two = float(case[1].as_str().expect("r2"));
        let three = float(case[2].as_str().expect("r3"));
        wrong += usize::from(round2(x).to_bits() != two.to_bits());
        wrong += usize::from(clean(x).to_bits() != three.to_bits());
    }
    eprintln!(
        "round(x, 2) and _clean round(x, 3): {} inputs, {} results compared, {wrong} differ",
        rounds.len(),
        rounds.len() * 2
    );
    assert!(rounds.len() >= 20_000);
    assert_eq!(wrong, 0);
}
