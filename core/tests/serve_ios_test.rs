// SPDX-License-Identifier: AGPL-3.0-or-later
//! iOS only: the phone refuses the server roles (relay serving and pairing offers) before any
//! handler runs, through the same entry the router uses (`handle_line`).
#![cfg(target_os = "ios")]

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

fn answer(method: &str) -> Value {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = Buffer::default();
    let mut session = Session::new(dir.path().join("none.hbdb"), Channel::new(Box::new(out.clone())));
    let line = json!({"id": 7, "method": method, "params": {}}).to_string();
    serve::handle_line(&mut session, &line).expect("write");
    let bytes = out.0.lock().expect("buffer").clone();
    serde_json::from_slice(&bytes).expect("one protocol line")
}

#[test]
fn the_five_server_roles_are_refused_on_ios() {
    for method in ["relay.addresses", "relay.serve", "pair.offer", "pair.confirm", "pair.cancel"] {
        let reply = answer(method);
        assert_eq!(reply["id"], 7, "{method}");
        assert_eq!(reply["error"]["code"], "unsupported_transport", "{method}");
        assert!(reply["error"]["message"].as_str().is_some_and(|m| m.contains("the Mac does")));
    }
}

#[test]
fn other_methods_still_reach_their_handlers() {
    let reply = answer("app.info");
    assert!(reply.get("error").is_none(), "{reply}");
}
