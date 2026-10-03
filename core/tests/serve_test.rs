// SPDX-License-Identifier: AGPL-3.0-or-later
//! `serve` in-process: the protocol envelope and the start-up methods against the oracle's behaviour
//! (`disconect/tests/test_serve.py`), plus source-level rules that keep the transport honest.
//! Nothing here reaches the OS keychain: encrypted-store cases that would are process-level tests
//! with the keychain disabled (`serve_process_test.rs`).

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{PASSPHRASE, encrypted_copy};
use disconect_core::keys::PassphraseSource;
use disconect_core::read::DEFERRED_METHODS;
use disconect_core::serve::{self, Channel, METHODS, Session};
use disconect_core::store;
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Rig {
    session: Session,
    out: Buffer,
}

impl Rig {
    fn new(db: &std::path::Path) -> Rig {
        let out = Buffer::default();
        Rig {
            session: Session::new(db.to_path_buf(), Channel::new(Box::new(out.clone()))),
            out,
        }
    }

    /// Feed raw input; return every line written, parsed.
    fn feed(&mut self, input: &[u8]) -> Vec<Value> {
        assert_eq!(serve::serve_lines(&mut self.session, input), 0);
        let bytes = std::mem::take(&mut *self.out.0.lock().expect("buffer"));
        String::from_utf8(bytes)
            .expect("ascii output")
            .lines()
            .map(|l| serde_json::from_str(l).expect("protocol line"))
            .collect()
    }

    fn send(&mut self, method: &str, params: Value) -> Value {
        let mut lines = self
            .feed(format!("{}\n", json!({"id": 1, "method": method, "params": params})).as_bytes());
        assert_eq!(lines.len(), 1);
        lines.remove(0)
    }

    fn code(&mut self, method: &str, params: Value) -> String {
        let reply = self.send(method, params);
        assert!(reply.get("result").is_none(), "{reply}");
        reply["error"]["code"].as_str().expect("code").to_string()
    }
}

fn plain_store() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("plain.db");
    store::open_for_write(&db, "test", 1.0, PassphraseSource::Explicit("unused"))
        .expect("create store");
    (dir, db)
}

#[test]
fn app_info_names_the_product_the_notice_and_this_core() {
    let (_dir, db) = plain_store();
    let info = Rig::new(&db).send("app.info", json!({}))["result"].clone();
    assert_eq!(info["product"], "DISCOnect");
    assert_eq!(
        info["notice"],
        "Not affiliated with or endorsed by any watch manufacturer."
    );
    assert_eq!(info["encrypted"], false);
    assert_eq!(info["db"], db.to_string_lossy().as_ref());
    assert_eq!(info["contract"], 1);
    assert_eq!(info["schema"], store::SCHEMA_VERSION);
    assert!(
        info["core"]
            .as_str()
            .expect("core")
            .starts_with("disconect-core/")
    );
    let keys: Vec<&str> = info
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 7);
}

#[test]
fn malformed_and_unknown_requests_get_error_lines() {
    let (_dir, db) = plain_store();
    let lines = Rig::new(&db).feed(
        concat!(
            "not json\n[1]\n{\"id\":true,\"method\":\"app.info\"}\n{\"id\":7,\"method\":5}\n",
            "{\"id\":8,\"method\":\"no.such\"}\n\n{\"id\":\"x\",\"method\":\"app.info\",\"params\":[]}\n"
        )
        .as_bytes(),
    );
    let codes: Vec<(Value, &str)> = lines
        .iter()
        .map(|l| (l["id"].clone(), l["error"]["code"].as_str().expect("code")))
        .collect();
    assert_eq!(
        codes,
        [
            (Value::Null, "bad_params"),
            (Value::Null, "bad_params"),
            (Value::Null, "bad_params"),
            (json!(7), "bad_params"),
            (json!(8), "unknown_method"),
            (json!("x"), "bad_params"),
        ]
    );
}

#[test]
fn string_ids_round_trip_and_blank_lines_are_skipped() {
    let (_dir, db) = plain_store();
    let lines = Rig::new(&db).feed(b"\n   \n{\"id\":\"abc\",\"method\":\"app.info\"}\n");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], "abc");
    assert!(lines[0].get("result").is_some());
}

#[test]
fn the_last_line_needs_no_newline_and_a_cr_is_just_whitespace() {
    let (_dir, db) = plain_store();
    let lines = Rig::new(&db)
        .feed(b"{\"id\":1,\"method\":\"key.status\"}\r\n{\"id\":2,\"method\":\"key.status\"}");
    assert_eq!(
        lines.iter().map(|l| l["id"].clone()).collect::<Vec<_>>(),
        [json!(1), json!(2)]
    );
    let lines = Rig::new(&db)
        .feed(b"{\"id\":1,\"method\":\"key.status\"}\r{\"id\":2,\"method\":\"key.status\"}\n");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["error"]["message"], "request is not valid JSON");
}

#[test]
fn invalid_utf8_becomes_a_replacement_character_in_the_echoed_id() {
    let (_dir, db) = plain_store();
    let lines = Rig::new(&db).feed(b"{\"id\":\"\xff\",\"method\":\"key.status\"}\n");
    assert_eq!(lines[0]["id"], "\u{fffd}");
}

#[test]
fn big_and_odd_ids_are_echoed_digit_for_digit() {
    let (_dir, db) = plain_store();
    let mut rig = Rig::new(&db);
    // serde_json would turn the first id into a float, so read the raw bytes the core wrote
    assert_eq!(
        serve::serve_lines(
            &mut rig.session,
            &b"{\"id\":123456789012345678901234567890,\"method\":\"no.such\"}\n{\"id\":-0,\"method\":\"no.such\"}\n"[..]
        ),
        0
    );
    let raw = String::from_utf8(rig.out.0.lock().expect("buffer").clone()).expect("utf8");
    let ids: Vec<&str> = raw
        .lines()
        .map(|l| l.split(',').next().unwrap_or(""))
        .collect();
    assert_eq!(ids, ["{\"id\":123456789012345678901234567890", "{\"id\":0"]);
}

#[test]
fn a_plaintext_store_has_nothing_to_unlock_nothing_to_cache_and_is_open() {
    let (_dir, db) = plain_store();
    let mut rig = Rig::new(&db);
    assert_eq!(
        rig.code("key.unlock", json!({"passphrase": PASSPHRASE})),
        "not_encrypted"
    );
    assert_eq!(rig.code("key.unlock", json!({})), "not_encrypted");
    assert_eq!(
        rig.code("key.cache", json!({"enable": true})),
        "not_encrypted"
    );
    assert_eq!(rig.code("key.cache", json!({})), "bad_params");
    assert_eq!(
        rig.code("key.cache", json!({"enable": "yes"})),
        "bad_params"
    );
    assert_eq!(
        rig.code("key.unlock", json!({"passphrase": 12345})),
        "bad_params"
    );
    let status = rig.send("key.status", json!({}))["result"].clone();
    assert_eq!(
        status,
        json!({"key_file": false, "encrypted": false, "unlocked": true, "keychain": "absent", "kdf": null})
    );
}

#[test]
fn locked_until_unlocked_then_unlocked() {
    let (_dir, db) = encrypted_copy();
    let mut rig = Rig::new(&db);
    assert_eq!(rig.code("key.cache", json!({"enable": true})), "locked");
    assert_eq!(
        rig.code(
            "key.unlock",
            json!({"passphrase": "not the passphrase at all!"})
        ),
        "wrong_passphrase"
    );
    assert_eq!(
        rig.code("key.unlock", json!({"passphrase": "abc\u{e9}"})),
        "wrong_passphrase"
    );
    assert_eq!(
        rig.send("key.unlock", json!({"passphrase": PASSPHRASE}))["result"],
        json!({"unlocked": true})
    );
    assert_eq!(rig.code("key.cache", json!({"enable": "no"})), "bad_params");
}

#[test]
fn the_lone_surrogate_passphrase_is_bad_params_like_the_encoder_error() {
    let (_dir, db) = encrypted_copy();
    let mut rig = Rig::new(&db);
    let out = rig
        .feed(b"{\"id\":1,\"method\":\"key.unlock\",\"params\":{\"passphrase\":\"abc\\ud800\"}}\n");
    assert_eq!(out[0]["error"]["code"], "bad_params");
    assert_eq!(
        out[0]["error"]["message"],
        "'utf-8' codec can't encode character '\\ud800' in position 3: surrogates not allowed"
    );
}

#[test]
fn the_methods_table_and_the_deferred_list_partition_the_protocol() {
    let ported: Vec<&str> = METHODS.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        ported,
        [
            "app.info",
            "key.status",
            "key.unlock",
            "key.cache",
            "data.health",
            "data.metric",
            "data.today",
            "data.facts",
            "import.run",
            "import.last"
        ]
    );
    assert!(DEFERRED_METHODS.is_empty(), "slice 3D ported the last deferred methods");
    for name in DEFERRED_METHODS {
        assert!(
            !ported.contains(name),
            "{name} is deferred, so it must not be in METHODS"
        );
    }
    let (_dir, db) = plain_store();
    let mut rig = Rig::new(&db);
    for name in DEFERRED_METHODS {
        let reply = rig.send(name, json!({}));
        assert_eq!(reply["error"]["code"], "unknown_method", "{name}");
        assert_eq!(reply["error"]["message"], "no such method");
    }
}

// ---- data.facts ----

fn synthetic_copy() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("synthetic.db");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../disconect/tests/fixtures/serve/synthetic.hbdb");
    std::fs::copy(source, &db).expect("copy the committed synthetic store");
    (dir, db)
}

#[test]
fn facts_on_an_empty_store_say_so_and_carry_the_rules() {
    let (_dir, db) = plain_store();
    let reply = Rig::new(&db).send("data.facts", json!({}));
    let result = &reply["result"];
    assert_eq!(result["as_of"], Value::Null);
    assert_eq!(result["facts"], json!([]));
    assert_eq!(result["reason"], "nothing stored yet");
    assert_eq!(result["ignored_metrics"], json!([]));
    assert_eq!(result["rules"].as_array().map(Vec::len), Some(3));
    assert_eq!(result.as_object().map(|o| o.len()), Some(5));
}

#[test]
fn facts_need_an_unlocked_store_and_then_answer() {
    let (_dir, db) = encrypted_copy();
    let mut rig = Rig::new(&db);
    assert_eq!(rig.code("data.facts", json!({})), "locked");
    assert_eq!(rig.code("data.facts", json!({"days": "x"})), "locked", "locked is checked before the params");
    rig.send("key.unlock", json!({"passphrase": PASSPHRASE}));
    let reply = rig.send("data.facts", json!({}));
    assert!(reply["result"].get("as_of").is_some(), "{reply}");
}

#[test]
fn facts_parameters_are_integers_and_are_clamped_like_the_oracle() {
    let (_dir, db) = synthetic_copy();
    let mut rig = Rig::new(&db);
    for bad in [json!(true), json!("7"), json!(7.5), json!(7.0), json!(null), json!([7])] {
        assert_eq!(rig.code("data.facts", json!({"days": bad})), "bad_params");
        assert_eq!(rig.code("data.facts", json!({"baseline_days": bad})), "bad_params");
    }
    let wide = rig.send("data.facts", json!({"days": 99999, "baseline_days": 1_000_000}))["result"].clone();
    assert_eq!((wide["window"]["days"].clone(), wide["baseline"]["days"].clone()), (json!(31), json!(365)));
    let narrow = rig.send("data.facts", json!({"days": -3, "baseline_days": 0}))["result"].clone();
    assert_eq!((narrow["window"]["days"].clone(), narrow["baseline"]["days"].clone()), (json!(1), json!(1)));
    let huge = rig.feed(
        format!("{{\"id\":2,\"method\":\"data.facts\",\"params\":{{\"days\":1{}}}}}\n", "0".repeat(4299)).as_bytes(),
    );
    assert_eq!(huge[0]["result"]["window"]["days"], 31, "a bigint clamps like Python's");
}

#[test]
fn facts_leave_out_the_convention_text_and_the_manufacturer_name() {
    let (_dir, db) = synthetic_copy();
    let result = Rig::new(&db).send("data.facts", json!({}))["result"].clone();
    assert!(result.get("sources").is_none());
    assert!(result.get("missing_values").is_some());
    assert!(!result.to_string().to_lowercase().contains("garmin"));
    let facts = result["facts"].as_array().expect("facts");
    assert!(facts.len() > 20);
    let keys: Vec<&str> = facts[0].as_object().expect("fact").keys().map(String::as_str).collect();
    assert_eq!(keys.len(), 14);
}

// ---- source rules ----

fn source(relative: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .expect("source file")
}

/// Everything before the first `#[cfg(test)]`: the production half of a module.
fn production(text: &str) -> &str {
    text.split("#[cfg(test)]").next().unwrap_or(text)
}

#[test]
fn serve_never_reaches_the_environment_passphrase() {
    let text = source("src/serve.rs");
    for forbidden in [
        "PASSPHRASE_ENV",
        "take_env_passphrase",
        "PassphraseSource",
        "scrub_env_secrets",
        "DISCONECT_RECOVERY",
    ] {
        assert!(
            !text.contains(forbidden),
            "serve.rs must not touch {forbidden}"
        );
    }
    assert!(!text.contains("env::var(\"DISCONECT_PASSPHRASE\""));
}

#[test]
fn the_read_and_transport_modules_never_ask_the_host_for_its_time_zone_or_print() {
    for file in [
        "src/serve.rs",
        "src/read/mod.rs",
        "src/contract.rs",
        "src/identity.rs",
        "src/keychain.rs",
        "src/wirejson.rs",
    ] {
        let text = source(file);
        let code = production(&text);
        assert!(
            !code.contains("Local"),
            "{file}: local days come from the watch's stored offsets, not the host zone"
        );
        assert!(
            !code.contains("println!") && !code.contains("print!(") && !code.contains("dbg!"),
            "{file} prints"
        );
    }
    assert!(source("src/lib.rs").contains("#![deny(clippy::print_stdout)]"));
    assert!(source("src/serve.rs").contains("clippy::unwrap_used"));
}

#[test]
fn the_dependency_tree_has_no_network_crate_but_the_lan_relays_two() {
    let lock = source("Cargo.lock");
    for crate_name in [
        "reqwest",
        "hyper",
        "curl",
        "tokio",
        "native-tls",
        "rustls",
    ] {
        assert!(
            !lock.contains(&format!("name = \"{crate_name}\"")),
            "{crate_name} would be a network dependency"
        );
    }
    // Bet 12 slice B: the LAN relay is the one network feature (ADR 0005, "self-hosted"): `ureq` (client, no
    // TLS) and `tiny_http` (server), and nothing else in the crate may name them
    let allowed = ["src/relay/lan.rs", "src/relay/lan_server.rs"];
    let mut stack = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).expect("read src") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .expect("under the crate")
                .to_string_lossy()
                .into_owned();
            let text = std::fs::read_to_string(&path).expect("source");
            let names_network = text.contains("ureq::") || text.contains("tiny_http::");
            assert!(
                !names_network || allowed.contains(&relative.as_str()),
                "{relative} reaches the network outside the LAN relay modules"
            );
        }
    }
    assert!(!source("src/serve.rs").contains("relay::lan"), "serve talks to the relay only through `relay::config`");
}
