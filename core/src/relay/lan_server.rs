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
//! * `POST /v1/pair/<id>` and `GET /v1/pair/<id>/payload` -- only when an offer is attached (`pair offer`),
//!   unauthenticated by design; see `pair_routes.rs` and `docs/relay-protocol.md`, "Pairing routes".
//!
//! Everything else answers 404 or 405; a bad token 401 with an empty body whatever the reason; a
//! name outside the pattern 400; a name under another account 403; a body over one bundle 413; a
//! body that stops arriving 408. Nothing but the method and the status is ever logged.
//!
//! **The HTTP layer is this file's own** (a deliberately small HTTP/1.1 subset, one request per
//! connection, `Connection: close`), not a library's: the library tried first (`tiny_http`) has no
//! time-outs, hides the socket, reads the rest of an unread body when a request is dropped, and
//! lets one stalled peer cost a worker. Bet 12 review F1 is closed in four layers:
//! 1. **The pre-tag** (`lan::verify_pre`, over the declared `Content-Length`) is checked before a
//!    single body byte is read: a peer without the key is answered 401 on the head alone, whatever
//!    it declares and whatever it then sends.
//! 2. **Every socket read and write has a time-out** ([`Limits::idle`], 10 s): the head must arrive
//!    within that budget in total, the body within `idle + declared / 256 KiB/s` (a 64 MiB bundle
//!    gets about 4.5 minutes; one byte every nine seconds gets nothing), the response likewise.
//! 3. **A connection is a thread, not a worker**: a stalled peer holds its own thread (at most
//!    [`MAX_CONNECTIONS`]; one more is closed unanswered), never the ability to answer anyone else.
//! 4. A refused request whose body was not read is answered, then drained by a short-lived thread
//!    ([`MAX_LINGERS`]) for at most a second, so the client gets the answer rather than a reset.
//!
//! What remains, stated: an unauthenticated peer can occupy connection slots with half-sent heads
//! for up to [`Limits::idle`] each (no per-address limits); a peer holding a captured header for
//! the exact length can hold a slot until the body budget ends and can make the server buffer what
//! it sends (one bundle at most per slot).

use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::json;
use zeroize::Zeroizing;

use super::bundle::account_for;
use super::folder::{FolderRelay, MAX_OBJECT, Relay, RelayError, is_object_name};
use super::lan::{
    API_VERSION, HEALTH, OBJECTS, parse_auth, token_key, verify_pre, verify_tag, wall_clock,
};
use super::pair_routes::{self, PAIR, PairHandle, PairOffer, PairShared};
use crate::identity::PRODUCT;

/// Connections served at once; one more is closed unanswered.
const MAX_CONNECTIONS: usize = 32;
/// The largest request head (request line and headers) accepted.
const MAX_HEAD: usize = 16 * 1024;
/// The most header lines in one request.
const MAX_HEADERS: usize = 64;
/// How often the accept loop looks at the stop flag when nothing is waiting.
const POLL: Duration = Duration::from_millis(25);
/// The slowest body rate the total read budget allows (bytes per second).
const MIN_RATE: u64 = 256 * 1024;
/// Threads at a time that drain a refused request's unread body.
const MAX_LINGERS: usize = 64;
/// How long, and how much, a drain thread reads before it lets go.
const LINGER_TOTAL: Duration = Duration::from_secs(1);
const LINGER_IDLE: Duration = Duration::from_millis(200);
const LINGER_CAP: u64 = 4 * 1024 * 1024;

/// How long the server waits on a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// No progress on a socket read or write for this long fails it (header, body, response); also
    /// the base of the total body budget.
    pub idle: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            idle: Duration::from_secs(10),
        }
    }
}

impl Limits {
    /// The most time a body of `declared` bytes may take to arrive.
    fn body_budget(&self, declared: u64) -> Duration {
        self.idle + Duration::from_secs(declared / MIN_RATE)
    }
}

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
    limits: Limits,
    lingers: Arc<AtomicUsize>,
    /// The pairing offer, if this server carries one (`pair offer`); `None`: every pair route is 404.
    /// Attachable while the server runs (the app's serve mode: one server, offers come and go).
    offer: Mutex<Option<Arc<PairShared>>>,
}

impl Ctx {
    pub fn new(folder: impl Into<PathBuf>, master: &[u8]) -> Ctx {
        Ctx::with_limits(folder, master, Limits::default())
    }

    pub fn with_limits(folder: impl Into<PathBuf>, master: &[u8], limits: Limits) -> Ctx {
        Ctx {
            relay: FolderRelay::new(folder),
            account: account_for(master),
            key: token_key(master),
            limits,
            lingers: Arc::new(AtomicUsize::new(0)),
            offer: Mutex::new(None),
        }
    }

    /// This context also serves `handle`'s offer on the pairing routes.
    pub fn with_offer(self, offer: Arc<PairShared>) -> Ctx {
        self.set_offer(Some(offer));
        self
    }

    fn set_offer(&self, offer: Option<Arc<PairShared>>) {
        *self.offer.lock().unwrap_or_else(|e| e.into_inner()) = offer;
    }

    fn current_offer(&self) -> Option<Arc<PairShared>> {
        self.offer.lock().unwrap_or_else(|e| e.into_inner()).clone()
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

/// Why a body was not obtained.
enum BodyError {
    TooLarge,
    /// A read failed, timed out or ended before the declared length.
    Unreadable,
}

/// Read exactly the declared bytes (never more than one bundle).
fn read_declared(body: &mut dyn Read, declared: u64) -> Result<Vec<u8>, BodyError> {
    if declared > MAX_OBJECT {
        return Err(BodyError::TooLarge);
    }
    let mut bytes = Vec::new();
    match body.take(declared).read_to_end(&mut bytes) {
        Ok(_) if bytes.len() as u64 == declared => Ok(bytes),
        _ => Err(BodyError::Unreadable),
    }
}

/// Answer one request. `now` is the server's clock in Unix seconds (a parameter so tests can move
/// it); `body` is read only after the header's shape, its timestamp and its pre-tag (over the
/// declared length) pass, and the tag is checked before anything touches the folder.
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
    if url == PAIR || url.starts_with(&format!("{PAIR}/")) {
        let offer = ctx.current_offer();
        return pair_routes::handle(offer.as_deref(), method, url, declared_len, body, now);
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
    let Ok(parsed) = parse_auth(header, now) else {
        return Reply::status(401);
    };
    // A request that declares no length (GET, DELETE) is read as an empty body, whatever follows;
    // chunked uploads are not part of the protocol.
    let declared = declared_len.map_or(0, |len| len as u64);
    if verify_pre(&*ctx.key, method, url, parsed.timestamp, declared, &parsed.pre).is_err() {
        return Reply::status(401);
    }
    let bytes = match read_declared(body, declared) {
        Ok(bytes) => bytes,
        Err(BodyError::TooLarge) => return Reply::status(413),
        Err(BodyError::Unreadable) => return Reply::status(408),
    };
    if verify_tag(&*ctx.key, method, url, parsed.timestamp, &parsed.tag, &bytes).is_err() {
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

/// Called once per answered request with the method and the status; nothing else is ever reported
/// (`?` stands for a request whose method could not be read).
pub type Logger = Arc<dyn Fn(&str, u16) + Send + Sync>;

fn bind(listen: &str) -> Result<TcpListener, String> {
    let listener =
        TcpListener::bind(listen).map_err(|_| "cannot listen on that address".to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "cannot configure the listener".to_string())?;
    Ok(listener)
}

/// A running server: an accept loop and one thread per connection, until [`LanServer::stop`] (or drop).
pub struct LanServer {
    addr: SocketAddr,
    ctx: Arc<Ctx>,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    acceptor: Option<JoinHandle<()>>,
}

impl LanServer {
    /// Listen on `listen` (`host:port`; port 0 picks one) and serve `folder` for `master`'s account.
    pub fn start(
        listen: &str,
        folder: impl Into<PathBuf>,
        master: &[u8],
        log: Logger,
    ) -> Result<LanServer, String> {
        LanServer::start_with(listen, folder, master, log, Limits::default())
    }

    /// [`LanServer::start`] with explicit [`Limits`] (tests shorten them).
    pub fn start_with(
        listen: &str,
        folder: impl Into<PathBuf>,
        master: &[u8],
        log: Logger,
        limits: Limits,
    ) -> Result<LanServer, String> {
        let listener = bind(listen)?;
        let ctx = Ctx::with_limits(folder, master, limits);
        LanServer::spawn(listener, ctx, log)
    }

    /// [`LanServer::start_with`] plus one pairing offer (Bet 12-E): binds first, so the offer carries
    /// the address actually bound (`http://<local_addr>`; `listen` must therefore be an address the
    /// joiner can reach, and a caller that wants a fixed URL refuses port 0 itself). Returns the
    /// server, the offer text and the offer's handle.
    pub fn start_with_offer(
        listen: &str,
        folder: impl Into<PathBuf>,
        master: &[u8],
        log: Logger,
        limits: Limits,
    ) -> Result<(LanServer, String, PairHandle), String> {
        let listener = bind(listen)?;
        let addr = listener
            .local_addr()
            .map_err(|_| "the listener has no address".to_string())?;
        let (text, handle) = PairOffer::new(&format!("http://{addr}"))
            .map_err(|_| "cannot make an offer".to_string())?;
        let ctx = Ctx::with_limits(folder, master, limits).with_offer(handle.shared());
        let server = LanServer::spawn(listener, ctx, log)?;
        Ok((server, text, handle))
    }

    fn spawn(listener: TcpListener, ctx: Ctx, log: Logger) -> Result<LanServer, String> {
        let addr = listener
            .local_addr()
            .map_err(|_| "the listener has no address".to_string())?;
        let ctx = Arc::new(ctx);
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let (loop_stop, loop_active, loop_ctx) = (Arc::clone(&stop), Arc::clone(&active), Arc::clone(&ctx));
        let acceptor = std::thread::Builder::new()
            .name("lan-relay-accept".into())
            .spawn(move || accept_loop(&listener, &loop_ctx, &loop_stop, &loop_active, &log))
            .map_err(|_| "cannot start the accept thread".to_string())?;
        Ok(LanServer {
            addr,
            ctx,
            stop,
            active,
            acceptor: Some(acceptor),
        })
    }

    /// Serve `offer` on the pairing routes from now on (replacing any offer attached before).
    pub fn attach_offer(&self, offer: Arc<PairShared>) {
        self.ctx.set_offer(Some(offer));
    }

    /// Stop serving the pairing routes (they answer `404` again).
    pub fn detach_offer(&self) {
        self.ctx.set_offer(None);
    }

    /// The address actually bound (the port when 0 was asked for).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop taking connections and give the requests in hand a few seconds to finish.
    pub fn stop(mut self) {
        self.shutdown();
    }

    /// Serve until the process ends.
    pub fn wait(mut self) {
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
        let give_up = Instant::now() + Duration::from_secs(5);
        while self.active.load(Ordering::SeqCst) > 0 && Instant::now() < give_up {
            std::thread::sleep(POLL);
        }
    }
}

impl Drop for LanServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Counts a connection while its thread lives, whatever way the thread ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn accept_loop(
    listener: &TcpListener,
    ctx: &Arc<Ctx>,
    stop: &AtomicBool,
    active: &Arc<AtomicUsize>,
    log: &Logger,
) {
    while !stop.load(Ordering::SeqCst) {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(_) => {
                std::thread::sleep(POLL);
                continue;
            }
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue; // over the limit: the stream is dropped, the peer sees a close
        }
        let slot = Slot(Arc::clone(active));
        let (ctx, log) = (Arc::clone(ctx), Arc::clone(log));
        let spawned = std::thread::Builder::new()
            .name("lan-relay-conn".into())
            .spawn(move || {
                let _slot = slot;
                serve_connection(&ctx, stream, &log);
            });
        drop(spawned); // on failure the closure, the stream and the slot are dropped with it
    }
}

/// A connection's bytes with a deadline: what arrived after the head first, then the socket.
struct Conn<'a> {
    stream: &'a TcpStream,
    buffered: Vec<u8>,
    position: usize,
    deadline: Instant,
    idle: Duration,
    /// Body bytes handed out (the head is not counted).
    taken: u64,
}

impl Conn<'_> {
    /// One read from the socket, within the deadline and the idle limit.
    fn fill(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| IoError::from(ErrorKind::TimedOut))?;
        self.stream.set_read_timeout(Some(left.min(self.idle)))?;
        match self.stream.read(buf) {
            Err(e) if e.kind() == ErrorKind::WouldBlock => Err(IoError::from(ErrorKind::TimedOut)),
            other => other,
        }
    }
}

impl Read for Conn<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = if let Some(rest) = self.buffered.get(self.position..).filter(|r| !r.is_empty())
        {
            let count = rest.len().min(buf.len());
            buf[..count].copy_from_slice(&rest[..count]);
            self.position += count;
            count
        } else {
            self.fill(buf)?
        };
        self.taken += count as u64;
        Ok(count)
    }
}

/// A parsed request head.
struct Head {
    method: String,
    target: String,
    auth: Option<String>,
    length: Option<usize>,
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Read the head within the connection's deadline. `Ok(None)`: the peer closed before sending a
/// byte. `Err(status)`: refuse with that bare status.
fn read_head(conn: &mut Conn<'_>) -> Result<Option<Head>, u16> {
    let mut chunk = [0u8; 2048];
    let end = loop {
        if let Some(end) = find_head_end(&conn.buffered) {
            break end;
        }
        if conn.buffered.len() > MAX_HEAD {
            return Err(400);
        }
        match conn.fill(&mut chunk) {
            Ok(0) if conn.buffered.is_empty() => return Ok(None),
            Ok(0) => return Err(400),
            Ok(count) => conn.buffered.extend_from_slice(&chunk[..count]),
            Err(e) if e.kind() == ErrorKind::TimedOut && conn.buffered.is_empty() => {
                return Ok(None);
            }
            Err(e) if e.kind() == ErrorKind::TimedOut => return Err(408),
            Err(_) => return Ok(None),
        }
    };
    if end > MAX_HEAD {
        return Err(400);
    }
    conn.position = end + 4;
    let text = std::str::from_utf8(&conn.buffered[..end]).map_err(|_| 400u16)?;
    parse_head(text).map(Some)
}

fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn parse_head(text: &str) -> Result<Head, u16> {
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(400u16)?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(400);
    };
    let method_ok = !method.is_empty()
        && method.len() <= 16
        && method.bytes().all(|b| b.is_ascii_uppercase());
    let target_ok = target.starts_with('/')
        && target.len() <= 2048
        && target.bytes().all(|b| b.is_ascii_graphic());
    if !method_ok || !target_ok || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(400);
    }
    let (mut auth, mut length, mut count) = (None, None, 0usize);
    for line in lines {
        count += 1;
        if count > MAX_HEADERS {
            return Err(400);
        }
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        if !is_token(name) {
            return Err(400); // also refuses an obsolete folded line (it starts with a space)
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case(super::lan::AUTH_HEADER) {
            if auth.replace(value.to_string()).is_some() {
                return Err(400);
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            let digits = !value.is_empty()
                && value.len() <= 19
                && value.bytes().all(|b| b.is_ascii_digit());
            let parsed = value.parse::<u64>().ok().filter(|_| digits);
            let parsed = parsed.and_then(|n| usize::try_from(n).ok()).ok_or(400u16)?;
            if length.replace(parsed).is_some() {
                return Err(400);
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(400); // no chunked uploads: the pre-tag covers a length
        }
    }
    Ok(Head {
        method: method.to_string(),
        target: target.to_string(),
        auth,
        length,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        410 => "Gone",
        413 => "Content Too Large",
        _ => "Internal Server Error",
    }
}

/// Write the answer, a chunk at a time, within the response budget.
fn write_reply(mut stream: &TcpStream, reply: &Reply, limits: &Limits) -> std::io::Result<()> {
    let content_type = if reply.json {
        "application/json"
    } else {
        "application/octet-stream"
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n",
        reply.status,
        reason(reply.status)
    );
    if reply.status != 204 {
        head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
    }
    head.push_str("\r\n");
    let deadline = Instant::now() + limits.body_budget(reply.body.len() as u64);
    stream.write_all(head.as_bytes())?;
    for chunk in reply.body.chunks(64 * 1024) {
        if Instant::now() >= deadline {
            return Err(IoError::from(ErrorKind::TimedOut));
        }
        stream.write_all(chunk)?;
    }
    stream.flush()
}

fn serve_connection(ctx: &Ctx, stream: TcpStream, log: &Logger) {
    let idle = ctx.limits.idle;
    // an accepted socket may inherit the listener's non-blocking mode
    if stream.set_nonblocking(false).is_err()
        || stream.set_write_timeout(Some(idle)).is_err()
        || stream.set_nodelay(true).is_err()
    {
        return;
    }
    let mut conn = Conn {
        stream: &stream,
        buffered: Vec::new(),
        position: 0,
        deadline: Instant::now() + idle,
        idle,
        taken: 0,
    };
    let (method, reply, declared) = match read_head(&mut conn) {
        Ok(None) => return,
        Err(status) => ("?".to_string(), Reply::status(status), None),
        Ok(Some(head)) => {
            conn.deadline = Instant::now() + ctx.limits.body_budget(head.length.unwrap_or(0) as u64);
            let reply = handle(
                ctx,
                &head.method,
                &head.target,
                head.auth.as_deref(),
                head.length,
                &mut conn,
                wall_clock(),
            );
            (head.method, reply, head.length)
        }
    };
    log(&method, reply.status);
    let written = write_reply(&stream, &reply, &ctx.limits).is_ok();
    let _ = stream.shutdown(Shutdown::Write);
    let unread = declared.is_some_and(|len| len as u64 > conn.taken);
    if written && unread {
        linger(ctx, stream);
    }
}

/// Let a refused client finish sending before the socket closes (closing with unread data resets
/// the connection, and the client may lose the answer): a short drain on a thread of its own.
fn linger(ctx: &Ctx, stream: TcpStream) {
    if ctx.lingers.fetch_add(1, Ordering::SeqCst) >= MAX_LINGERS {
        ctx.lingers.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let lingers = Arc::clone(&ctx.lingers);
    let spawned = std::thread::Builder::new()
        .name("lan-relay-linger".into())
        .spawn(move || {
            let deadline = Instant::now() + LINGER_TOTAL;
            let (mut drained, mut buf) = (0u64, [0u8; 8192]);
            while drained < LINGER_CAP {
                let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                if stream.set_read_timeout(Some(left.min(LINGER_IDLE).max(Duration::from_millis(1)))).is_err() {
                    break;
                }
                match (&stream).read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => drained += count as u64,
                }
            }
            lingers.fetch_sub(1, Ordering::SeqCst);
        });
    if spawned.is_err() {
        ctx.lingers.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::lan::{MAX_SKEW_SECS, auth_value, auth_value_declaring};

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
        let big_len = MAX_OBJECT + 1;
        let big = auth_value_declaring(&*ctx.key, "PUT", &path, 100, big_len, b"").expect("header");
        assert_eq!(
            handle(
                &ctx,
                "PUT",
                &path,
                Some(&big),
                Some(big_len as usize),
                &mut std::io::empty(),
                100
            )
            .status,
            413,
            "a declared body over one bundle is refused before it is read"
        );
    }

    /// A body that must never be touched.
    struct Untouchable;
    impl Read for Untouchable {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("the body was read"))
        }
    }

    #[test]
    fn nothing_is_read_before_the_pre_tag_passes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = ctx(dir.path());
        let path = object(&ctx, "d");
        let other = Ctx::new(dir.path().join("relay"), &(2u8..34).collect::<Vec<_>>());
        for (label, header, declared) in [
            (
                "forged pre-tag, 1 MB declared",
                format!("v1.100.{}.{}", "00".repeat(32), "00".repeat(32)),
                1_000_000usize,
            ),
            (
                "another master's header",
                auth_value_declaring(&*other.key, "PUT", &path, 100, 1_000_000, b"").expect("h"),
                1_000_000,
            ),
            (
                "a header for 4 bytes replayed with a longer length",
                auth_value(&*ctx.key, "PUT", &path, 100, b"abcd").expect("h"),
                1_000_000,
            ),
            (
                "a header for 4 bytes replayed with a shorter length",
                auth_value(&*ctx.key, "PUT", &path, 100, b"abcd").expect("h"),
                3,
            ),
        ] {
            let reply = handle(
                &ctx,
                "PUT",
                &path,
                Some(&header),
                Some(declared),
                &mut Untouchable,
                100,
            );
            assert_eq!((reply.status, reply.body.is_empty()), (401, true), "{label}");
        }
        // an undeclared length is an empty body, and is never read either (no chunked uploads)
        let header = auth_value(&*ctx.key, "GET", OBJECTS, 100, b"").expect("h");
        let reply = handle(&ctx, "GET", OBJECTS, Some(&header), None, &mut Untouchable, 100);
        assert_eq!(reply.status, 200);
        // a body that stops arriving after a valid pre-tag is a 408, and nothing is written
        let header = auth_value(&*ctx.key, "PUT", &path, 100, b"abcd").expect("h");
        let reply = handle(&ctx, "PUT", &path, Some(&header), Some(4), &mut Untouchable, 100);
        assert_eq!(reply.status, 408);
        assert_eq!(signed(&ctx, "GET", &path, b"", 100, 100).status, 404);
        let reply = handle(&ctx, "PUT", &path, Some(&header), Some(4), &mut &b"ab"[..], 100);
        assert_eq!(reply.status, 408, "a body shorter than declared");
    }
}
