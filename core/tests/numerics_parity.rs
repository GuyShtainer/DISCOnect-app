// SPDX-License-Identifier: AGPL-3.0-or-later
//! `py_round` and `py_sum` against CPython 3.14 on generated cases (`fixtures/py_numerics.json`:
//! plain numbers, no health data). Bits must match, not just values.

use disconect_core::writer::{py_round, py_sum};
use serde_json::Value;

fn num(v: &Value) -> f64 {
    v.as_str().expect("repr string").parse::<f64>().expect("float repr")
}

fn fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/py_numerics.json");
    serde_json::from_slice(&std::fs::read(path).expect("read fixture")).expect("parse fixture")
}

#[test]
fn round_is_bit_identical_to_python() {
    let data = fixture();
    let cases = data["round"].as_array().expect("round cases");
    assert!(cases.len() > 500);
    for case in cases {
        let x = num(&case["x"]);
        for (digits, key) in [(3, "r3"), (1, "r1"), (2, "r2")] {
            assert_eq!(py_round(x, digits).to_bits(), num(&case[key]).to_bits(), "round({x:e}, {digits})");
        }
    }
}

#[test]
fn sum_and_mean_are_bit_identical_to_python() {
    let data = fixture();
    let cases = data["sum"].as_array().expect("sum cases");
    let mut naive_differs = 0;
    for case in cases {
        let values: Vec<f64> = case["v"].as_array().expect("values").iter().map(num).collect();
        let expected = num(&case["s"]);
        let got = py_sum(values.iter().copied());
        assert_eq!(got.to_bits(), expected.to_bits(), "sum of {} values", values.len());
        assert_eq!((got / values.len() as f64).to_bits(), num(&case["mean"]).to_bits());
        if values.iter().sum::<f64>().to_bits() != expected.to_bits() {
            naive_differs += 1;
        }
    }
    assert!(naive_differs > 0, "the cases must include sums where a naive loop disagrees with Python");
}
