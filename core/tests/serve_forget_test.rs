// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pair.forget` through the router's own entry (`handle_line`): refused on every core that is not a phone, and on
//! iOS the whole delete, the `busy` answers that delete nothing, and a forget that is asked while locked. The order
//! and the crash completion are `phone_forget`'s own unit tests (a fake keychain).

use std::io::Write;
use std::sync::{Arc, Mutex};

use disconect_core::serve::{self, Channel, Session};
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

fn ask(session: &mut Session, out: &Buffer, method: &str, params: Value) -> Value {
    out.0.lock().expect("buffer").clear();
    let line = json!({"id": 3, "method": method, "params": params}).to_string();
    serve::handle_line(session, &line).expect("write");
    let bytes = out.0.lock().expect("buffer").clone();
    serde_json::from_slice(&bytes).expect("one protocol line")
}

#[cfg(not(target_os = "ios"))]
#[test]
fn every_core_that_is_not_a_phone_refuses_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = Buffer::default();
    let mut session = Session::new(dir.path().join("a.hbdb"), Channel::new(Box::new(out.clone())));
    std::fs::write(dir.path().join("a.hbdb"), b"x").unwrap();
    for params in [json!({}), json!({"preview": true})] {
        let reply = ask(&mut session, &out, "pair.forget", params);
        assert_eq!(reply["error"]["code"], "unsupported_transport");
        assert_eq!(reply["error"]["message"], "this core is not a phone; there is nothing to forget");
    }
    assert!(dir.path().join("a.hbdb").exists(), "nothing was deleted");
}

#[cfg(target_os = "ios")]
mod phone {
    use super::*;

    const KEY_FILE: &str = r#"{"format":"hearthbeat-keys","format_version":1,"key_id":"00112233445566778899aabbccddeeff","created_at":"","wraps":[{"purpose":"passphrase"}]}"#;

    fn seed() -> (tempfile::TempDir, Session, Buffer) {
        // no keychain in this test process: the delete fails by a fixed answer, which is what the sheet must show
        // SAFETY: set before any thread of this test reads it; every test in this file wants the same value.
        unsafe { std::env::set_var("DISCONECT_KEYCHAIN", "fail") };
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("disconect.db");
        for name in ["disconect.db", "disconect.db-wal", "disconect.db-shm", "disconect.db.write-lock", "relay.json"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        std::fs::write(dir.path().join("disconect.db.keys.json"), KEY_FILE).unwrap();
        let out = Buffer::default();
        let session = Session::new(db, Channel::new(Box::new(out.clone())));
        (dir, session, out)
    }

    fn left(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    #[test]
    fn a_locked_phone_forgets_everything_and_reports_the_failed_keychain_in_fixed_words() {
        let (dir, mut session, out) = seed();
        let reply = ask(&mut session, &out, "pair.forget", json!({}));
        assert_eq!(reply["result"], json!({"forgotten": true, "keychain": "failed: no keychain is available"}), "{reply}");
        assert_eq!(left(dir.path()), Vec::<String>::new(), "store, -wal, -shm, lock, key file, relay.json and the marker are gone");
        let status = ask(&mut session, &out, "key.status", json!({}));
        assert_eq!(status["result"]["key_file"], false, "{status}");
        // forgetting again is a no-op that still answers, never an error
        let again = ask(&mut session, &out, "pair.forget", json!({}));
        assert_eq!(again["result"]["forgotten"], true, "{again}");
    }

    #[test]
    fn another_writer_or_a_running_import_answers_busy_and_deletes_nothing() {
        let (dir, mut session, out) = seed();
        let before = left(dir.path());
        let held = disconect_core::write_lock::acquire(&dir.path().join("disconect.db"), "test", std::time::Duration::ZERO).expect("lock");
        let reply = ask(&mut session, &out, "pair.forget", json!({}));
        assert_eq!(reply["error"]["code"], "busy", "{reply}");
        drop(held);
        let mut after = left(dir.path());
        after.retain(|n| n != "disconect.db.write-lock.holder");
        assert_eq!(after, before, "nothing deleted, and no marker left behind");

        // an import in flight holds the slot (the same one a sync takes)
        let (dir, mut session, out) = seed();
        std::fs::remove_file(dir.path().join("disconect.db.keys.json")).unwrap(); // unlocked without a key file
        let (gate, hold) = std::sync::mpsc::channel::<()>();
        session.hold_next_import(hold);
        let line = json!({"id": 9, "method": "import.run", "params": {"path": dir.path().join("nothing").to_string_lossy()}}).to_string();
        serve::handle_line(&mut session, &line).expect("write"); // a worker now waits on the gate
        assert!(out.0.lock().unwrap().is_empty(), "the import answers later");
        let before = left(dir.path());
        let reply = ask(&mut session, &out, "pair.forget", json!({}));
        assert_eq!(reply["error"]["code"], "busy", "{reply}");
        assert_eq!(left(dir.path()), before);
        drop(gate);
        serve::serve_lines(&mut session, std::io::empty()); // ends the held import and waits for it
    }
}
