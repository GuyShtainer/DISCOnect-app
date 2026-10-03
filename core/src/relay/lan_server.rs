// SPDX-License-Identifier: AGPL-3.0-or-later
//! The LAN relay server (Bet 12, slice B): the Mac serves its relay folder over HTTP/1.1 on the
//! home network so a phone can push and pull without a cloud (ADR 0005, "self-hosted").
//!
//! It is blind. It never opens a bundle, never learns a record, and needs the master key only to
//! derive the token key and the account name (`lan::token_key`). Everything an authenticated
//! client can do is what a folder relay already allows: list, read, write and delete the objects of
//! the one account this server's master derives. Routes (docs/relay-protocol.md, "LAN relay"):
//!
//! * `GET /v1/health` -- unauthenticated: product, `"lan"`, version. No host name, no path.
//! * `GET /v1/objects` -- the account's object names, a JSON array.
//! * `GET|PUT|DELETE /v1/objects/<account>/<32 hex>` -- one object (`FolderRelay` semantics:
//!   a write is an atomic rename and replaces an existing object; a missing object is 404).
//!
//! Everything else answers 404 or 405; a bad token 401 with an empty body whatever the reason; a
//! name outside the pattern 400; a name under another account 403; a body over one bundle 413.
//! Nothing but the method and the status is ever logged.

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::json;
use tiny_http::{Header, Request, Response, Server};
use zeroize::Zeroizing;

use super::bundle::account_for;
use super::folder::{FolderRelay, MAX_OBJECT, Relay, RelayError, is_object_name};
use super::lan::{API_VERSION, HEALTH, OBJECTS, parse_auth, token_key, verify_tag, wall_clock};
use crate::identity::PRODUCT;

/// Worker threads taking requests off the listener.
const WORKERS: usize = 4;
/// How often an idle worker looks at the stop flag.
const POLL: Duration = Duration::from_millis(200);

/// What the server answers: a status and a body (empty on every error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
    pub json: bool,
}

impl Reply {
    fn status(status: u16) -> Reply {
        Reply {
            status,
            body: Vec::new(),
            json: false,
        }
    }
}

/// Everything a request needs: the folder, the one account served, and the token key.
pub struct Ctx {
    relay: FolderRelay,
    account: String,
    key: Zeroizing<[u8; 32]>,
}

impl Ctx {
    pub fn new(folder: impl Into<PathBuf>, master: &[u8]) -> Ctx {
        Ctx {
            relay: FolderRelay::new(folder),
            account: account_for(master),
            key: token_key(master),
        }
    }
}

fn relay_failure(error: &RelayError) -> Reply {
    match error {
        RelayError::BadName => Reply::status(400),
        RelayError::TooLarge => Reply::status(413),
        RelayError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => Reply::status(404),
        _ => Reply::status(500),
    }
}

/// Read at most one bundle (plus one byte to see an overflow). `None` when the body is too large
/// or cannot be read.
fn read_capped(body: &mut dyn Read) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    body.take(MAX_OBJECT + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= MAX_OBJECT).then_some(bytes)
}

/// Answer one request. `now` is the server's clock in Unix seconds (a parameter so tests can move
/// it); `body` is read only after the header's shape and timestamp pass, and the tag is checked
/// before anything touches the folder.
pub fn handle(
    ctx: &Ctx,
    method: &str,
    url: &str,
    auth: Option<&str>,
    declared_len: Option<usize>,
    body: &mut dyn Read,
    now: u64,
) -> Reply {
    if url.contains('?') {
        return Reply::status(404);
    }
    if url == HEALTH {
        if method != "GET" {
            return Reply::status(405);
        }
        let text = json!({"product": PRODUCT, "relay": "lan", "v": API_VERSION}).to_string();
        return Reply {
            status: 200,
            body: text.into_bytes(),
            json: true,
        };
    }
    let name = match url.strip_prefix(OBJECTS) {
        Some("") => None,
        Some(rest) => match rest.strip_prefix('/') {
            Some(name) => Some(name),
            None => return Reply::status(404),
        },
        None => return Reply::status(404),
    };
    let allowed = matches!(
        (name.is_some(), method),
        (false, "GET") | (true, "GET" | "PUT" | "DELETE")
    );
    if !allowed {
        return Reply::status(405);
    }
    let Some(header) = auth else {
        return Reply::status(401);
    };
    let Ok((timestamp, tag)) = parse_auth(header, now) else {
        return Reply::status(401);
    };
    if declared_len.is_some_and(|len| len as u64 > MAX_OBJECT) {
        return Reply::status(413);
    }
    let Some(bytes) = read_capped(body) else {
        return Reply::status(413);
    };
    if verify_tag(&*ctx.key, method, url, timestamp, &tag, &bytes).is_err() {
        return Reply::status(401);
    }
    let Some(name) = name else {
        return match ctx.relay.list(&ctx.account) {
            Ok(names) => Reply {
                status: 200,
                body: json!(names).to_string().into_bytes(),
                json: true,
            },
            Err(error) => relay_failure(&error),
        };
    };
    if !is_object_name(name) {
        return Reply::status(400);
    }
    if !name.starts_with(&format!("{}/", ctx.account)) {
        return Reply::status(403);
    }
    match method {
        "GET" => match ctx.relay.get(name) {
            Ok(object) => Reply {
                status: 200,
                body: object,
                json: false,
            },
            Err(error) => relay_failure(&error),
        },
        "PUT" => match ctx.relay.put(name, &bytes) {
            Ok(()) => Reply::status(204),
            Err(error) => relay_failure(&error),
        },
        _ => match ctx.relay.delete(name) {
            Ok(()) => Reply::status(204),
            Err(error) => relay_failure(&error),
        },
    }
}

/// Called once per request with the method and the status; nothing else is ever reported.
pub type Logger = Arc<dyn Fn(&str, u16) + Send + Sync>;

/// A running server: workers taking requests until [`LanServer::stop`] (or drop).
pub struct LanServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl LanServer {
    /// Listen on `listen` (`host:port`; port 0 picks one) and serve `folder` for `master`'s account.
    pub fn start(
        listen: &str,
        folder: impl Into<PathBuf>,
        master: &[u8],
        log: Logger,
    ) -> Result<LanServer, String> {
        let server =
            Server::http(listen).map_err(|_| "cannot listen on that address".to_string())?;
        let addr = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| "the listener has no IP address".to_string())?;
        let server = Arc::new(server);
        let ctx = Arc::new(Ctx::new(folder, master));
        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::new();
        for index in 0..WORKERS {
            let (server, ctx, stop, log) = (
                Arc::clone(&server),
                Arc::clone(&ctx),
                Arc::clone(&stop),
                Arc::clone(&log),
            );
            let worker = std::thread::Builder::new()
                .name(format!("lan-relay-{index}"))
                .spawn(move || work(&server, &ctx, &stop, &log))
                .map_err(|_| "cannot start a worker thread".to_string())?;
            workers.push(worker);
        }
        Ok(LanServer {
            addr,
            stop,
            workers,
        })
    }

    /// The address actually bound (the port when 0 was asked for).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop taking requests and wait for the workers (each finishes the request in hand).
    pub fn stop(mut self) {
        self.shutdown();
    }

    /// Serve until the process ends.
    pub fn wait(mut self) {
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl Drop for LanServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn work(server: &Server, ctx: &Ctx, stop: &AtomicBool, log: &Logger) {
    while !stop.load(Ordering::SeqCst) {
        let request = match server.recv_timeout(POLL) {
            Ok(Some(request)) => request,
            Ok(None) => continue,
            Err(_) => break,
        };
        answer(ctx, request, log);
    }
}

fn answer(ctx: &Ctx, mut request: Request, log: &Logger) {
    let method = request.method().as_str().to_string();
    let url = request.url().to_string();
    let auth = request
        .headers()
        .iter()
        .find(|h| h.field.equiv(super::lan::AUTH_HEADER))
        .map(|h| h.value.as_str().to_string());
    let declared = request.body_length();
    let reply = handle(
        ctx,
        &method,
        &url,
        auth.as_deref(),
        declared,
        request.as_reader(),
        wall_clock(),
    );
    log(&method, reply.status);
    let content_type: &[u8] = if reply.json {
        b"application/json"
    } else {
        b"application/octet-stream"
    };
    let mut response = Response::from_data(reply.body).with_status_code(reply.status);
    if let Ok(header) = Header::from_bytes(&b"Content-Type"[..], content_type) {
        response = response.with_header(header);
    }
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::lan::{MAX_SKEW_SECS, auth_value};

    fn master() -> Vec<u8> {
        (1u8..33).collect()
    }

    fn ctx(dir: &std::path::Path) -> Ctx {
        Ctx::new(dir.join("relay"), &master())
    }

    fn signed(ctx: &Ctx, method: &str, path: &str, body: &[u8], stamp: u64, now: u64) -> Reply {
        let header = auth_value(&*ctx.key, method, path, stamp, body).expect("header");
        handle(
            ctx,
            method,
            path,
            Some(&header),
            Some(body.len()),
            &mut &body[..],
            now,
        )
    }

    fn object(ctx: &Ctx, tail: &str) -> String {
        format!("{OBJECTS}/{}/{}", ctx.account, tail.repeat(32))
    }

    #[test]
    fn put_get_list_delete_round_trip_and_replace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = ctx(dir.path());
        let path = object(&ctx, "a");
        assert_eq!(signed(&ctx, "PUT", &path, b"one", 100, 100).status, 204);
        let got = signed(&ctx, "GET", &path, b"", 100, 100);
        assert_eq!((got.status, got.body.as_slice()), (200, &b"one"[..]));
        assert_eq!(signed(&ctx, "PUT", &path, b"two", 100, 100).status, 204);
        assert_eq!(signed(&ctx, "GET", &path, b"", 100, 100).body, b"two");
        let listed = signed(&ctx, "GET", OBJECTS, b"", 100, 100);
        let names: Vec<String> = serde_json::from_slice(&listed.body).expect("json");
        assert_eq!(
            names,
            vec![path.trim_start_matches("/v1/objects/").to_string()]
        );
        assert_eq!(signed(&ctx, "DELETE", &path, b"", 100, 100).status, 204);
        assert_eq!(signed(&ctx, "GET", &path, b"", 100, 100).status, 404);
        assert_eq!(signed(&ctx, "DELETE", &path, b"", 100, 100).status, 404);
    }

    #[test]
    fn health_needs_no_token_and_says_nothing_about_the_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = ctx(dir.path());
        let reply = handle(&ctx, "GET", HEALTH, None, None, &mut std::io::empty(), 0);
        assert_eq!(reply.status, 200);
        let text = String::from_utf8(reply.body).expect("utf8");
        assert_eq!(text, r#"{"product":"DISCOnect","relay":"lan","v":1}"#);
        assert_eq!(
            handle(&ctx, "PUT", HEALTH, None, None, &mut std::io::empty(), 0).status,
            405
        );
    }

    #[test]
    fn every_refusal_is_a_bare_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = ctx(dir.path());
        let path = object(&ctx, "b");
        // no header, malformed header, stale, wrong key, wrong method, wrong body
        let none = handle(&ctx, "GET", &path, None, None, &mut std::io::empty(), 100);
        assert_eq!((none.status, none.body.is_empty()), (401, true));
        let junk = handle(
            &ctx,
            "GET",
            &path,
            Some("junk"),
            None,
            &mut std::io::empty(),
            100,
        );
        assert_eq!(junk.status, 401);
        assert_eq!(
            signed(&ctx, "GET", &path, b"", 100, 100 + MAX_SKEW_SECS + 1).status,
            401
        );
        let other = Ctx::new(dir.path().join("relay"), &(2u8..34).collect::<Vec<_>>());
        let foreign = auth_value(&*other.key, "GET", &path, 100, b"").expect("header");
        assert_eq!(
            handle(
                &ctx,
                "GET",
                &path,
                Some(&foreign),
                None,
                &mut std::io::empty(),
                100
            )
            .status,
            401
        );
        let get_header = auth_value(&*ctx.key, "GET", &path, 100, b"").expect("header");
        assert_eq!(
            handle(
                &ctx,
                "DELETE",
                &path,
                Some(&get_header),
                None,
                &mut std::io::empty(),
                100
            )
            .status,
            401,
            "a token is bound to its method"
        );
        let put_header = auth_value(&*ctx.key, "PUT", &path, 100, b"x").expect("header");
        assert_eq!(
            handle(
                &ctx,
                "PUT",
                &path,
                Some(&put_header),
                Some(1),
                &mut &b"y"[..],
                100
            )
            .status,
            401,
            "a token is bound to its body"
        );
        // nothing was written by any of them
        assert_eq!(signed(&ctx, "GET", &path, b"", 100, 100).status, 404);
    }

    #[test]
    fn names_routes_and_sizes_are_validated_after_the_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = ctx(dir.path());
        assert_eq!(
            signed(&ctx, "PUT", &format!("{OBJECTS}/../escape"), b"x", 100, 100).status,
            400
        );
        assert_eq!(
            signed(
                &ctx,
                "PUT",
                &format!("{OBJECTS}/{}/xyz", ctx.account),
                b"x",
                100,
                100
            )
            .status,
            400
        );
        let foreign = format!("{OBJECTS}/{}/{}", "f".repeat(64), "a".repeat(32));
        assert_eq!(signed(&ctx, "PUT", &foreign, b"x", 100, 100).status, 403);
        assert_eq!(signed(&ctx, "GET", "/v1/other", b"", 100, 100).status, 404);
        assert_eq!(
            signed(&ctx, "GET", "/v1/objectsX", b"", 100, 100).status,
            404
        );
        assert_eq!(
            signed(&ctx, "GET", "/v1/objects?x=1", b"", 100, 100).status,
            404
        );
        assert_eq!(signed(&ctx, "PUT", OBJECTS, b"", 100, 100).status, 405);
        assert_eq!(signed(&ctx, "DELETE", OBJECTS, b"", 100, 100).status, 405);
        let path = object(&ctx, "c");
        let big = auth_value(&*ctx.key, "PUT", &path, 100, b"").expect("header");
        assert_eq!(
            handle(
                &ctx,
                "PUT",
                &path,
                Some(&big),
                Some(MAX_OBJECT as usize + 1),
                &mut std::io::empty(),
                100
            )
            .status,
            413,
            "a declared body over one bundle is refused before it is read"
        );
        let mut endless = std::io::repeat(7u8);
        assert_eq!(
            handle(&ctx, "PUT", &path, Some(&big), None, &mut endless, 100).status,
            413,
            "an undeclared body stops at the cap"
        );
    }
}
