//! The bridge to the core, protocol in `projects/disconect/docs/serve-protocol.md`. The core is one
//! of three things: `disconect-core` serve as a supervised child (the sidecar, release default),
//! `hearthbeat-core` (the Python rollback), or `disconect-core` **in-process** on a thread
//! ([`crate::inproc`]; the debug default and the only choice on a phone). All three speak JSON Lines
//! and feed the one [`Router`], so the webview and the commands in `lib.rs` cannot tell them apart;
//! the webview and this process never hold the database key.
//!
//! Rules enforced here (pitch 07, "Protocol rules"): env allowlist on spawn, request ids,
//! per-method timeouts, one restart after a crash, stderr drained into a bounded buffer that is
//! never logged, the child killed on exit, and the passphrase carried only as `Zeroizing`
//! bytes that are written straight to the pipe (or the in-process channel). No business logic
//! lives in Rust.

use std::collections::{HashMap, VecDeque};
#[cfg(desktop)]
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
#[cfg(desktop)]
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::inproc::{self, InProcCore, LineSink, Runner};

/// Environment variables the child may inherit. Everything else, the passphrase env above
/// all, is dropped so a shell-launched app can never unlock through the tests-only path.
/// (An in-process core has no such filter; see `inproc.rs`.)
#[cfg(desktop)]
const ENV_ALLOWLIST: &[&str] = &["HOME", "PATH", "DISCONECT_DB", "DISCONECT_KEYS", "TMPDIR", "LANG"];
/// The live link's child reads the watch, never the store: no store or key path reaches it.
#[cfg(desktop)]
const LIVE_ENV_ALLOWLIST: &[&str] = &["HOME", "PATH", "TMPDIR", "LANG"];
/// How long `LiveLink::stop` waits for the child to unsubscribe and close the link on its own.
#[cfg(desktop)]
const LIVE_STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(3);
const STDERR_LINES_KEPT: usize = 200;
const MAX_RESTARTS: u32 = 1;
/// What an in-process `app.info.core` gains, so the About card says where the core runs.
const INPROC_SUFFIX: &str = " (in-process)";

/// A poisoned lock still guards intact data here (every critical section is a map or queue
/// operation), and with `panic = "unwind"` a panicking thread must not take the bridge with it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An error the webview can act on. `code` mirrors the protocol's string codes plus the
/// bridge's own: `core_exited`, `core_unavailable`, `timeout`, `bad_response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreError {
    pub code: String,
    pub message: String,
}

impl CoreError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.to_string(), message: message.into() }
    }
}

/// Where protocol events (`progress`, `log`) and bridge notices (`restarted`, `exited`) go.
/// The Tauri app forwards them to the window; tests collect them.
pub trait EventSink: Send + Sync + 'static {
    fn emit(&self, name: &str, payload: Value);
}

/// How to start the child: the executable plus its arguments (`--db PATH` when given).
#[derive(Clone, Debug)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl Launch {
    /// `--db` from the app's own argv (macOS: `open App.app --args --db PATH`), else none.
    pub fn db_from_args<I: IntoIterator<Item = String>>(args: I) -> Option<String> {
        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            if a == "--db" {
                return it.next();
            }
            if let Some(rest) = a.strip_prefix("--db=") {
                return Some(rest.to_string());
            }
        }
        None
    }

    pub fn new(program: PathBuf, db: Option<String>) -> Self {
        let mut args = Vec::new();
        if let Some(db) = db {
            args.push("--db".to_string());
            args.push(db);
        }
        Self { program, args }
    }
}

type Reply = Result<Value, CoreError>;

/// The id-to-oneshot router and the event forwarder: the one place a protocol line from any core
/// lands. The child's stdout reader and the in-process writer both call [`Self::route_line`].
pub struct Router {
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    next_id: AtomicU64,
    sink: Arc<dyn EventSink>,
}

impl Router {
    fn new(sink: Arc<dyn EventSink>) -> Arc<Self> {
        Arc::new(Self { pending: Mutex::new(HashMap::new()), next_id: AtomicU64::new(1), sink })
    }

    /// A response goes to its caller by id; an event goes to the window as `core://<name>`.
    pub fn route_line(&self, line: &str) {
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            return; // not protocol: the child isolates its stdout, so this is defensive only
        };
        if let Some(id) = msg.get("id").and_then(Value::as_u64) {
            self.deliver(id, msg);
        } else if let Some(name) = msg.get("event").and_then(Value::as_str) {
            self.sink.emit(&format!("core://{name}"), msg.clone());
        }
    }

    fn deliver(&self, id: u64, msg: Value) {
        let Some(tx) = lock(&self.pending).remove(&id) else { return };
        let outcome = match (msg.get("result"), msg.get("error")) {
            (Some(r), _) => Ok(r.clone()),
            (None, Some(e)) => Err(serde_json::from_value::<CoreError>(e.clone())
                .unwrap_or_else(|_| CoreError::new("bad_response", "malformed error from the core"))),
            _ => Err(CoreError::new("bad_response", "response without result or error")),
        };
        let _ = tx.send(outcome);
    }

    fn register(&self) -> (u64, oneshot::Receiver<Reply>) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        lock(&self.pending).insert(id, tx);
        (id, rx)
    }

    fn forget(&self, id: u64) {
        lock(&self.pending).remove(&id);
    }

    /// Fail every caller still waiting (the core went away).
    fn fail_all(&self, code: &str, message: &str) {
        let pending: Vec<_> = lock(&self.pending).drain().collect();
        for (_, tx) in pending {
            let _ = tx.send(Err(CoreError::new(code, message)));
        }
    }
}

impl LineSink for Router {
    fn line(&self, line: &str) {
        self.route_line(line);
    }
}

/// How the core is reached.
enum Backend {
    #[cfg(desktop)]
    Child(Launch),
    InProc { db: PathBuf, runner: Runner },
}

enum Running {
    #[cfg(desktop)]
    Child { child: Child, stdin: ChildStdin },
    InProc(InProcCore),
}

struct Inner {
    backend: Backend,
    running: Mutex<Option<Running>>,
    router: Arc<Router>,
    restarts: AtomicU64,
    stderr_tail: Mutex<VecDeque<String>>,
}

/// Handle to the supervised core (a child process or an in-process thread). Cheap to clone; all
/// clones share the one core.
#[derive(Clone)]
pub struct Sidecar(Arc<Inner>);

/// Timeout per method family. Imports and `sync.run` (a pull over the LAN can be long) run as long as they need; key operations may wait on a
/// keychain prompt; everything else is a read.
pub fn timeout_for(method: &str) -> Option<Duration> {
    if method.starts_with("import.") || method == "sync.run" || method == "pair.offer" {
        None
    } else if method.starts_with("key.") {
        Some(Duration::from_secs(60))
    } else {
        Some(Duration::from_secs(30))
    }
}

impl Sidecar {
    fn with_backend(backend: Backend, sink: Arc<dyn EventSink>) -> Self {
        Self(Arc::new(Inner {
            backend,
            running: Mutex::new(None),
            router: Router::new(sink),
            restarts: AtomicU64::new(0),
            stderr_tail: Mutex::new(VecDeque::new()),
        }))
    }

    /// Start the child now; a failure to start is returned, not retried.
    #[cfg(desktop)]
    pub fn start(launch: Launch, sink: Arc<dyn EventSink>) -> Result<Self, CoreError> {
        let me = Self::with_backend(Backend::Child(launch), sink);
        me.spawn()?;
        Ok(me)
    }

    /// Start the core in this process on a thread, serving the store at `db` (always explicit).
    pub fn start_inproc(db: PathBuf, sink: Arc<dyn EventSink>) -> Result<Self, CoreError> {
        Self::start_inproc_with(db, inproc::serve_runner, sink)
    }

    /// [`Self::start_inproc`] with the thread's body supplied (tests make it panic).
    #[doc(hidden)]
    pub fn start_inproc_with(db: PathBuf, runner: Runner, sink: Arc<dyn EventSink>) -> Result<Self, CoreError> {
        let me = Self::with_backend(Backend::InProc { db, runner }, sink);
        me.spawn()?;
        Ok(me)
    }

    pub fn is_inproc(&self) -> bool {
        matches!(self.0.backend, Backend::InProc { .. })
    }

    fn spawn(&self) -> Result<(), CoreError> {
        match &self.0.backend {
            #[cfg(desktop)]
            Backend::Child(launch) => self.spawn_child(launch),
            Backend::InProc { db, runner } => {
                let me = self.clone();
                let core = inproc::start(db.clone(), *runner, self.0.router.clone(), move |panicked| {
                    if panicked {
                        me.note("the in-process core stopped on an internal error");
                    }
                    me.on_exit(None);
                })
                .map_err(|e| CoreError::new("core_unavailable", format!("cannot start the core: {e}")))?;
                *lock(&self.0.running) = Some(Running::InProc(core));
                Ok(())
            }
        }
    }

    #[cfg(desktop)]
    fn spawn_child(&self, launch: &Launch) -> Result<(), CoreError> {
        let mut cmd = Command::new(&launch.program);
        cmd.args(&launch.args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for key in ENV_ALLOWLIST {
            if let Some(v) = std::env::var_os(key) {
                cmd.env(key, v);
            }
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| CoreError::new("core_unavailable", format!("cannot start the core: {e}")))?;
        let (Some(stdin), Some(stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CoreError::new("core_unavailable", "cannot reach the core's pipes"));
        };
        *lock(&self.0.running) = Some(Running::Child { child, stdin });
        self.drain_stderr(stderr);
        self.read_protocol(stdout);
        Ok(())
    }

    #[cfg(desktop)]
    fn drain_stderr(&self, stderr: std::process::ChildStderr) {
        let me = self.clone();
        std::thread::spawn(move || {
            // read_until + lossy decoding: a non-UTF-8 byte must never stop the drain, or the
            // child blocks once the pipe fills.
            let mut reader = BufReader::new(stderr);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => me.note(String::from_utf8_lossy(&buf).trim_end()),
                }
            }
        });
    }

    #[cfg(desktop)]
    fn read_protocol(&self, stdout: std::process::ChildStdout) {
        let me = self.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                me.0.router.route_line(&line);
            }
            let status = me.reap();
            me.on_exit(status);
        });
    }

    /// The core's stdout closed (child) or its thread ended (in-process): fail every caller,
    /// then restart once.
    fn on_exit(&self, status: Option<i32>) {
        if matches!(self.0.backend, Backend::InProc { .. }) {
            lock(&self.0.running).take(); // our own, finished core; a shutdown already took it
        }
        self.0.router.fail_all("core_exited", "the core stopped while answering");
        let n = self.0.restarts.fetch_add(1, Ordering::SeqCst) + 1;
        let sink = &self.0.router.sink;
        if n <= MAX_RESTARTS as u64 && self.spawn().is_ok() {
            sink.emit("core://restarted", serde_json::json!({ "attempt": n, "exit": status }));
        } else {
            sink.emit("core://exited", serde_json::json!({ "exit": status }));
        }
    }

    #[cfg(desktop)]
    fn reap(&self) -> Option<i32> {
        let taken = lock(&self.0.running).take()?;
        match taken {
            Running::Child { mut child, .. } => child.wait().ok().and_then(|s| s.code()),
            Running::InProc(_) => None,
        }
    }

    /// Keep one diagnostic line (bounded; never written to any log here).
    pub fn note(&self, line: impl Into<String>) {
        let mut tail = lock(&self.0.stderr_tail);
        if tail.len() == STDERR_LINES_KEPT {
            tail.pop_front();
        }
        tail.push_back(line.into());
    }

    /// Last diagnostic lines: the child's stderr, or the in-process core's notices.
    pub fn stderr_tail(&self) -> Vec<String> {
        lock(&self.0.stderr_tail).iter().cloned().collect()
    }

    fn write_line(&self, line: &[u8]) -> Result<(), CoreError> {
        let mut guard = lock(&self.0.running);
        let Some(running) = guard.as_mut() else {
            return Err(CoreError::new("core_unavailable", "the core is not running"));
        };
        match running {
            #[cfg(desktop)]
            Running::Child { stdin, .. } => stdin
                .write_all(line)
                .and_then(|_| stdin.write_all(b"\n"))
                .and_then(|_| stdin.flush())
                .map_err(|e| CoreError::new("core_unavailable", format!("cannot reach the core: {e}"))),
            Running::InProc(core) => core
                .send(line)
                .map_err(|e| CoreError::new("core_unavailable", format!("cannot reach the core: {e}"))),
        }
    }

    async fn await_reply(
        &self,
        id: u64,
        rx: oneshot::Receiver<Reply>,
        timeout: Option<Duration>,
    ) -> Reply {
        let fut = async { rx.await.unwrap_or_else(|_| Err(CoreError::new("core_exited", "the core went away"))) };
        match timeout {
            None => fut.await,
            Some(t) => match tokio::time::timeout(t, fut).await {
                Ok(r) => r,
                Err(_) => {
                    self.0.router.forget(id);
                    Err(CoreError::new("timeout", "the core did not answer in time"))
                }
            },
        }
    }

    /// `app.info.core` names where the core runs when it runs in this process.
    fn annotate(&self, method: &str, reply: Reply) -> Reply {
        if method != "app.info" || !self.is_inproc() {
            return reply;
        }
        reply.map(|mut v| {
            if let Some(core) = v.get("core").and_then(Value::as_str).map(|c| format!("{c}{INPROC_SUFFIX}")) {
                v["core"] = Value::String(core);
            }
            v
        })
    }

    /// Any method; `key.unlock` only without a passphrase (the keychain path), because a
    /// passphrase must never travel as a plain `Value`.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, CoreError> {
        self.call_with_timeout(method, params, timeout_for(method)).await
    }

    /// [`Self::call`] with an explicit timeout (tests; long-running diagnostics).
    pub async fn call_with_timeout(&self, method: &str, params: Value, timeout: Option<Duration>) -> Result<Value, CoreError> {
        if method == "key.unlock" && params.get("passphrase").is_some() {
            return Err(CoreError::new("bad_params", "use the unlock path for key.unlock"));
        }
        let (id, rx) = self.0.router.register();
        let line = serde_json::to_vec(&serde_json::json!({ "id": id, "method": method, "params": params }))
            .map_err(|e| CoreError::new("bad_params", e.to_string()))?;
        if let Err(e) = self.write_line(&line) {
            self.0.router.forget(id);
            return Err(e);
        }
        let reply = self.await_reply(id, rx, timeout).await;
        self.annotate(method, reply)
    }

    /// `key.unlock` with the passphrase held only in zeroized buffers: the request line is
    /// built into a `Zeroizing<Vec<u8>>`, written, and wiped when this function returns.
    pub async fn unlock(&self, passphrase: Zeroizing<String>) -> Result<Value, CoreError> {
        let (id, rx) = self.0.router.register();
        let line = {
            #[derive(Serialize)]
            struct Req<'a> {
                id: u64,
                method: &'static str,
                params: Params<'a>,
            }
            #[derive(Serialize)]
            struct Params<'a> {
                passphrase: &'a str,
            }
            let req = Req { id, method: "key.unlock", params: Params { passphrase: passphrase.as_str() } };
            Zeroizing::new(serde_json::to_vec(&req).map_err(|e| CoreError::new("bad_params", e.to_string()))?)
        };
        let written = self.write_line(&line);
        drop(line);
        drop(passphrase);
        if let Err(e) = written {
            self.0.router.forget(id);
            return Err(e);
        }
        self.await_reply(id, rx, timeout_for("key.unlock")).await
    }

    /// Stop the core (on app exit). A child's stdin closes first so a healthy core exits by
    /// itself, then it is killed after 2 s; an in-process core's input ends the same way and a
    /// thread still busy after 2 s (a long import) is left to the process exit.
    pub fn shutdown(&self) {
        self.0.restarts.store(MAX_RESTARTS as u64 + 1, Ordering::SeqCst);
        // taken out first: the core's own end-of-run path locks `running` too
        let taken = lock(&self.0.running).take();
        match taken {
            None => {}
            #[cfg(desktop)]
            Some(Running::Child { mut child, stdin }) => {
                drop(stdin);
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                while std::time::Instant::now() < deadline {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = child.kill();
                let _ = child.wait();
            }
            Some(Running::InProc(core)) => core.close_for(Duration::from_secs(2)),
        }
    }
}

/// Which core the app should run. Chosen by `--core hearthbeat|disconect|inproc` on the app's
/// own argv (rollback switch, pitch 11d step 3); never by an environment variable or a path
/// (debug builds apart, see [`plan`]), because the executable that receives the passphrase must be
/// one the bundle ships. `inproc` runs no executable at all: the core is this process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreChoice {
    /// `disconect-core`, the Rust port.
    Disconect,
    /// `hearthbeat-core`, the PyInstaller Python core (also the MCP server).
    Hearthbeat,
    /// `disconect-core` as a library, on a thread of the app (Bet 12a). No child, no bundle.
    InProcess,
}

impl CoreChoice {
    /// The `--core` spelling.
    pub fn name(self) -> &'static str {
        match self {
            Self::Disconect => "disconect",
            Self::Hearthbeat => "hearthbeat",
            Self::InProcess => "inproc",
        }
    }

    /// `--core <name>` or `--core=<name>` from the app's argv. `Ok(None)` when absent; an
    /// unknown or missing name is an error (fail closed: a typo must not pick a core).
    pub fn from_args<I: IntoIterator<Item = String>>(args: I) -> Result<Option<Self>, String> {
        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            let value = if a == "--core" {
                it.next().ok_or_else(|| "--core needs a value (hearthbeat, disconect or inproc)".to_string())?
            } else if let Some(rest) = a.strip_prefix("--core=") {
                rest.to_string()
            } else {
                continue;
            };
            return match value.as_str() {
                "disconect" => Ok(Some(Self::Disconect)),
                "hearthbeat" => Ok(Some(Self::Hearthbeat)),
                "inproc" => Ok(Some(Self::InProcess)),
                other => Err(format!("--core must be hearthbeat, disconect or inproc, not {other:?}")),
            };
        }
        Ok(None)
    }
}

/// An executable shipped inside the bundle's resources, if present.
fn bundled(dir: &Path, name: &str) -> Option<PathBuf> {
    let p = dir.join(name).join(name);
    p.is_file().then_some(p)
}

/// The bundled-executable rule, no environment: without a choice the Rust core first, then
/// the Python one; with a choice only that one (absent means `None`, never the other).
pub fn locate_bundled(dir: &Path, choice: Option<CoreChoice>) -> Option<PathBuf> {
    match choice {
        Some(CoreChoice::Disconect) => bundled(dir, "disconect-core"),
        Some(CoreChoice::Hearthbeat) => bundled(dir, "hearthbeat-core"),
        Some(CoreChoice::InProcess) => None,
        None => bundled(dir, "disconect-core").or_else(|| bundled(dir, "hearthbeat-core")),
    }
}

/// What `start_core` does, decided without touching the process: the core in this process, or a
/// sidecar child (with the `--core` choice, if any, for [`locate_core`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    InProcess,
    Sidecar(Option<CoreChoice>),
}

/// The selection rule. On a phone (`desktop == false`) the only core is in-process. On the
/// desktop `--core inproc` always selects it; with no `--core`, a **debug** build runs in-process
/// unless `DISCONECT_CORE` names an executable (`DISCONECT_CORE=inproc` is the explicit spelling),
/// and a **release** build runs the bundled sidecar: the keychain item the app shares with
/// `disconect-core mcp` is bound to the program that made it, so a release app that unlocked
/// in-process would own a different item than the sidecar it replaces (kb/23 class 5).
pub fn plan(choice: Option<CoreChoice>, debug_build: bool, desktop: bool, env_core: Option<&std::ffi::OsStr>) -> Plan {
    if !desktop {
        return Plan::InProcess;
    }
    match (choice, debug_build) {
        (Some(CoreChoice::InProcess), _) => Plan::InProcess,
        (None, true) if env_core.is_none_or(|v| v == "inproc") => Plan::InProcess,
        (choice, _) => Plan::Sidecar(choice),
    }
}

/// The test switches the core reads from its own environment (`DISCONECT_NOW` pins the clock,
/// `DISCONECT_KEYCHAIN` redirects or disables the keychain). The sidecar's environment allowlist
/// strips them; an in-process core would see the app's own.
pub const INPROC_TEST_SWITCHES: [&str; 2] = ["DISCONECT_NOW", "DISCONECT_KEYCHAIN"];

/// Whether the in-process core must refuse to start because a test switch is set: only in a
/// **release** build on the **desktop**, where a user's shell can set them and `--core inproc` is
/// an explicit choice. A debug build is the developer's own; a phone's environment cannot be set by
/// a user shell, so in-process stays allowed there. The answer names the variable, never its value.
/// Pure: the environment arrives through `getter` (`remove_var` is never used).
pub fn inproc_env_refusal(
    debug_build: bool,
    desktop: bool,
    getter: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<&'static str> {
    if debug_build || !desktop {
        return None;
    }
    if getter(INPROC_TEST_SWITCHES[0]).is_some() {
        return Some("DISCONECT_NOW is set; a release app will not run the in-process core with a test switch (unset it, or use the bundled core)");
    }
    if getter(INPROC_TEST_SWITCHES[1]).is_some() {
        return Some("DISCONECT_KEYCHAIN is set; a release app will not run the in-process core with a test switch (unset it, or use the bundled core)");
    }
    None
}

/// Where the core lives: a bundled sidecar under the app's resources, `disconect-core` first,
/// `hearthbeat-core` as the fallback, or exactly the one `--core` names. Debug builds, when no
/// `--core` is given, also honour `DISCONECT_CORE` (an executable path) first and fall back to
/// the dev venv's `disconect-serve`; release builds never let an environment variable pick
/// the executable that receives the passphrase.
pub fn locate_core(resource_dir: Option<&Path>, choice: Option<CoreChoice>) -> Option<PathBuf> {
    if choice == Some(CoreChoice::InProcess) {
        return None;
    }
    #[cfg(debug_assertions)]
    if choice.is_none() {
        if let Some(p) = std::env::var_os("DISCONECT_CORE") {
            return Some(PathBuf::from(p));
        }
    }
    if let Some(p) = resource_dir.and_then(|dir| locate_bundled(dir, choice)) {
        return Some(p);
    }
    #[cfg(debug_assertions)]
    if matches!(choice, None | Some(CoreChoice::Hearthbeat)) {
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../disconect/.venv/bin/disconect-serve");
        if dev.is_file() {
            return Some(dev);
        }
    }
    None
}

// ---- the live link (Bet 9 follow-up, 2026-10-05) ---------------------------------------------------------
//
// A read-only Bluetooth session to the watch, run by the lab's Python (`projects/ble-lab/live.py`, AGPL,
// a separate program) as a child of this process: one JSON line per reading on its stdout, forwarded to
// the window as `live://line`. The child lives only while the link is wanted: dropping its stdin ends it,
// a kill makes sure. Same env allowlist as the core. It stays in this file because this file is the one
// place that spawns (see `tests/egress_guards.rs`).

/// The child reading the watch, and the handle that ends it.
#[cfg(desktop)]
pub struct LiveLink {
    child: Arc<Mutex<Option<Child>>>,
}

#[cfg(desktop)]
impl LiveLink {
    /// Start `program args…`, forward its stdout lines as `live://line` events (one JSON object each; a line
    /// that is not one is dropped) and `live://ended {"exit": code}` when it stops.
    pub fn start(program: &Path, args: &[String], sink: Arc<dyn EventSink>) -> Result<Self, CoreError> {
        let mut cmd = Command::new(program);
        cmd.args(args).env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        for key in LIVE_ENV_ALLOWLIST {
            if let Some(v) = std::env::var_os(key) {
                cmd.env(key, v);
            }
        }
        let mut child = cmd.spawn().map_err(|e| CoreError::new("live_unavailable", format!("cannot start the live link: {e}")))?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CoreError::new("live_unavailable", "cannot reach the live link's pipe"));
        };
        let child = Arc::new(Mutex::new(Some(child)));
        let slot = child.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(value @ Value::Object(_)) = serde_json::from_str::<Value>(&line) {
                    sink.emit("live://line", value);
                }
            }
            let exit = lock(&slot).take().and_then(|mut c| c.wait().ok()).and_then(|s| s.code());
            sink.emit("live://ended", serde_json::json!({ "exit": exit }));
        });
        Ok(Self { child })
    }

    /// True while the child has not been reaped.
    pub fn running(&self) -> bool {
        lock(&self.child).as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None)))
    }

    /// End the session: close its stdin (the child's own stop signal, on which it unsubscribes and closes
    /// the link), give it [`LIVE_STOP_GRACE`] to exit by itself, then kill and reap whatever is left.
    pub fn stop(&self) {
        if let Some(mut child) = lock(&self.child).take() {
            drop(child.stdin.take());
            let deadline = std::time::Instant::now() + LIVE_STOP_GRACE;
            while std::time::Instant::now() < deadline {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(desktop)]
impl Drop for LiveLink {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch resource dir holding `<name>/<name>` files; removed on drop. (No tempfile
    /// crate: the app keeps its dependency list short.)
    struct Bundle(PathBuf);

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn bundle_with(names: &[&str]) -> Bundle {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("disconect-sidecar-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).expect("mkdir");
        for n in names {
            std::fs::create_dir_all(dir.join(n)).expect("mkdir");
            std::fs::write(dir.join(n).join(n), b"x").expect("write");
        }
        Bundle(dir)
    }

    #[test]
    fn core_flag_is_read_in_both_spellings_and_fails_closed() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(CoreChoice::from_args(args(&["app"])), Ok(None));
        assert_eq!(CoreChoice::from_args(args(&["app", "--core", "hearthbeat"])), Ok(Some(CoreChoice::Hearthbeat)));
        assert_eq!(CoreChoice::from_args(args(&["app", "--db", "x", "--core=disconect"])), Ok(Some(CoreChoice::Disconect)));
        assert!(CoreChoice::from_args(args(&["app", "--core", "python"])).is_err());
        assert!(CoreChoice::from_args(args(&["app", "--core", "/bin/sh"])).is_err());
        assert!(CoreChoice::from_args(args(&["app", "--core"])).is_err());
    }

    #[test]
    fn bundled_order_is_rust_then_python() {
        let both = bundle_with(&["disconect-core", "hearthbeat-core"]);
        let p = locate_bundled(both.0.as_path(), None).expect("found");
        assert!(p.ends_with("disconect-core/disconect-core"));
        let only_py = bundle_with(&["hearthbeat-core"]);
        let p = locate_bundled(only_py.0.as_path(), None).expect("found");
        assert!(p.ends_with("hearthbeat-core/hearthbeat-core"));
        let none = bundle_with(&[]);
        assert_eq!(locate_bundled(none.0.as_path(), None), None);
    }

    #[test]
    fn core_switch_picks_only_the_named_bundled_core() {
        let both = bundle_with(&["disconect-core", "hearthbeat-core"]);
        let py = locate_bundled(both.0.as_path(), Some(CoreChoice::Hearthbeat)).expect("found");
        assert!(py.ends_with("hearthbeat-core/hearthbeat-core"));
        let rs = locate_bundled(both.0.as_path(), Some(CoreChoice::Disconect)).expect("found");
        assert!(rs.ends_with("disconect-core/disconect-core"));
        // no silent fallback to the other core when the named one is missing
        let only_py = bundle_with(&["hearthbeat-core"]);
        assert_eq!(locate_bundled(only_py.0.as_path(), Some(CoreChoice::Disconect)), None);
        let only_rs = bundle_with(&["disconect-core"]);
        assert_eq!(locate_bundled(only_rs.0.as_path(), Some(CoreChoice::Hearthbeat)), None);
    }

    #[test]
    fn db_flag_is_read_from_argv_in_both_spellings() {
        let a = vec!["app".to_string(), "--db".to_string(), "/x.db".to_string()];
        assert_eq!(Launch::db_from_args(a).as_deref(), Some("/x.db"));
        let b = vec!["app".to_string(), "--db=/y.db".to_string()];
        assert_eq!(Launch::db_from_args(b).as_deref(), Some("/y.db"));
        assert_eq!(Launch::db_from_args(vec!["app".to_string()]), None);
    }

    #[test]
    fn timeouts_follow_the_method_family() {
        assert_eq!(timeout_for("import.run"), None);
        assert_eq!(timeout_for("key.status"), Some(Duration::from_secs(60)));
        assert_eq!(timeout_for("data.metric"), Some(Duration::from_secs(30)));
        assert_eq!(timeout_for("sync.run"), None);
        assert_eq!(timeout_for("sync.status"), Some(Duration::from_secs(30)));
        assert_eq!(timeout_for("pair.offer"), None);
        assert_eq!(timeout_for("pair.confirm"), Some(Duration::from_secs(30)));
    }

    #[test]
    fn the_in_process_core_refuses_test_switches_only_in_a_release_desktop_build() {
        use std::ffi::OsString;
        let env = |set: &'static [&'static str]| {
            move |name: &str| set.contains(&name).then(|| OsString::from("secret-value-xyz"))
        };
        for (debug, desktop, set, refused) in [
            (true, true, &["DISCONECT_NOW"][..], false),
            (true, true, &["DISCONECT_KEYCHAIN"][..], false),
            (true, false, &["DISCONECT_NOW"][..], false),
            (false, false, &["DISCONECT_NOW", "DISCONECT_KEYCHAIN"][..], false),
            (false, true, &[][..], false),
            (false, true, &["DISCONECT_NOW"][..], true),
            (false, true, &["DISCONECT_KEYCHAIN"][..], true),
            (false, true, &["DISCONECT_NOW", "DISCONECT_KEYCHAIN"][..], true),
            (false, true, &["DISCONECT_CORE", "DISCONECT_DB"][..], false),
        ] {
            let answer = inproc_env_refusal(debug, desktop, env(set));
            assert_eq!(answer.is_some(), refused, "debug={debug} desktop={desktop} set={set:?}");
            if let Some(text) = answer {
                assert!(set.iter().any(|name| text.starts_with(name)), "names the variable: {text}");
                assert!(!text.contains("secret-value-xyz"), "never the value: {text}");
            }
        }
    }

    #[test]
    fn inproc_is_a_core_choice_and_never_a_located_executable() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(CoreChoice::from_args(args(&["app", "--core", "inproc"])), Ok(Some(CoreChoice::InProcess)));
        assert_eq!(CoreChoice::from_args(args(&["app", "--core=inproc"])), Ok(Some(CoreChoice::InProcess)));
        let both = bundle_with(&["disconect-core", "hearthbeat-core"]);
        assert_eq!(locate_bundled(both.0.as_path(), Some(CoreChoice::InProcess)), None);
        assert_eq!(locate_core(Some(both.0.as_path()), Some(CoreChoice::InProcess)), None);
    }

    #[test]
    fn selection_debug_is_inproc_release_is_the_sidecar() {
        use std::ffi::OsStr;
        // debug, nothing said: in-process; a path in DISCONECT_CORE keeps the old dev loop
        assert_eq!(plan(None, true, true, None), Plan::InProcess);
        assert_eq!(plan(None, true, true, Some(OsStr::new("inproc"))), Plan::InProcess);
        assert_eq!(plan(None, true, true, Some(OsStr::new("/x/disconect-core"))), Plan::Sidecar(None));
        // release, nothing said: the sidecar, and no environment variable moves it
        assert_eq!(plan(None, false, true, None), Plan::Sidecar(None));
        assert_eq!(plan(None, false, true, Some(OsStr::new("inproc"))), Plan::Sidecar(None));
        // argv wins in both builds
        for debug in [true, false] {
            assert_eq!(plan(Some(CoreChoice::InProcess), debug, true, None), Plan::InProcess);
            assert_eq!(plan(Some(CoreChoice::Disconect), debug, true, None), Plan::Sidecar(Some(CoreChoice::Disconect)));
            assert_eq!(plan(Some(CoreChoice::Hearthbeat), debug, true, None), Plan::Sidecar(Some(CoreChoice::Hearthbeat)));
        }
        // a phone has no other choice, whatever argv or build says
        for choice in [None, Some(CoreChoice::Disconect), Some(CoreChoice::Hearthbeat), Some(CoreChoice::InProcess)] {
            assert_eq!(plan(choice, false, false, None), Plan::InProcess);
        }
    }

    #[cfg(desktop)]
    #[test]
    fn passphrase_env_is_not_in_the_allowlist() {
        assert!(!ENV_ALLOWLIST.contains(&"DISCONECT_PASSPHRASE"));
        assert!(!ENV_ALLOWLIST.contains(&"DISCONECT_RECOVERY_WORDS"));
        // the live child reads the watch, never the store
        for key in LIVE_ENV_ALLOWLIST {
            assert!(!key.starts_with("DISCONECT_"), "{key}");
        }
        assert!(LIVE_ENV_ALLOWLIST.iter().all(|k| ENV_ALLOWLIST.contains(k)));
    }

    #[cfg(desktop)]
    #[test]
    fn the_live_link_forwards_json_object_lines_only_and_reports_the_end() {
        use std::sync::mpsc;
        struct Collect(Mutex<mpsc::Sender<(String, Value)>>);
        impl EventSink for Collect {
            fn emit(&self, name: &str, payload: Value) {
                let _ = lock(&self.0).send((name.to_string(), payload));
            }
        }
        let (tx, rx) = mpsc::channel();
        let script = "printf '%s\\n' '{\"status\":\"scanning\"}' 'not json' '[1,2]' '{\"t\":1.5,\"metric\":\"heart_rate\",\"value\":70}'; exit 3";
        let link = LiveLink::start(Path::new("/bin/sh"), &["-c".to_string(), script.to_string()], Arc::new(Collect(Mutex::new(tx))))
            .expect("spawn");
        let mut got = Vec::new();
        while let Ok(event) = rx.recv_timeout(Duration::from_secs(5)) {
            let done = event.0 == "live://ended";
            got.push(event);
            if done {
                break;
            }
        }
        assert_eq!(
            got,
            vec![
                ("live://line".to_string(), serde_json::json!({"status": "scanning"})),
                ("live://line".to_string(), serde_json::json!({"t": 1.5, "metric": "heart_rate", "value": 70})),
                ("live://ended".to_string(), serde_json::json!({"exit": 3})),
            ]
        );
        assert!(!link.running());
        link.stop(); // a no-op after the end
    }

    #[cfg(desktop)]
    #[test]
    fn stopping_the_live_link_kills_a_child_that_waits_on_stdin() {
        struct Drop_;
        impl EventSink for Drop_ {
            fn emit(&self, _: &str, _: Value) {}
        }
        let link = LiveLink::start(Path::new("/bin/cat"), &[], Arc::new(Drop_)).expect("spawn");
        assert!(link.running());
        let started = std::time::Instant::now();
        link.stop(); // cat exits on EOF by itself: no kill, no full grace period
        assert!(!link.running());
        assert!(started.elapsed() < LIVE_STOP_GRACE, "the child ended on EOF, stop did not wait out the grace");
        // a child that ignores EOF is killed once the grace is over
        let stubborn = LiveLink::start(Path::new("/bin/sh"), &["-c".into(), "trap '' TERM; sleep 60".into()], Arc::new(Drop_)).expect("spawn");
        assert!(stubborn.running());
        let started = std::time::Instant::now();
        stubborn.stop();
        assert!(!stubborn.running());
        assert!(started.elapsed() >= LIVE_STOP_GRACE);
    }
}
