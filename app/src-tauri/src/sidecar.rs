//! The bridge to the Python core (`hearthbeat serve`), protocol in
//! `projects/hearthbeat/docs/serve-protocol.md`. One long-lived child per app; JSON Lines over
//! stdio; the webview and this process never hold the database key.
//!
//! Rules enforced here (pitch 07, "Protocol rules"): env allowlist on spawn, request ids,
//! per-method timeouts, one restart after a crash, stderr drained into a bounded buffer that is
//! never logged, the child killed on exit, and the passphrase carried only as `Zeroizing`
//! bytes that are written straight to the pipe. No business logic lives in Rust.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// Environment variables the child may inherit. Everything else, the passphrase env above
/// all, is dropped so a shell-launched app can never unlock through the tests-only path.
const ENV_ALLOWLIST: &[&str] = &["HOME", "PATH", "HEARTHBEAT_DB", "HEARTHBEAT_KEYS", "TMPDIR", "LANG"];
const STDERR_LINES_KEPT: usize = 200;
const MAX_RESTARTS: u32 = 1;

/// An error the webview can act on. `code` mirrors the protocol's string codes plus the
/// bridge's own: `core_exited`, `core_unavailable`, `timeout`, `bad_response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreError {
    pub code: String,
    pub message: String,
}

impl CoreError {
    fn new(code: &str, message: impl Into<String>) -> Self {
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

struct Running {
    child: Child,
    stdin: ChildStdin,
}

struct Inner {
    launch: Launch,
    running: Mutex<Option<Running>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Value, CoreError>>>>,
    next_id: AtomicU64,
    restarts: AtomicU64,
    stderr_tail: Mutex<VecDeque<String>>,
    sink: Arc<dyn EventSink>,
}

/// Handle to the supervised child. Cheap to clone; all clones share the one process.
#[derive(Clone)]
pub struct Sidecar(Arc<Inner>);

/// Timeout per method family. Imports run as long as they need; key operations may wait on a
/// keychain prompt; everything else is a read.
pub fn timeout_for(method: &str) -> Option<Duration> {
    if method.starts_with("import.") {
        None
    } else if method.starts_with("key.") {
        Some(Duration::from_secs(60))
    } else {
        Some(Duration::from_secs(30))
    }
}

impl Sidecar {
    /// Start the child now; a failure to start is returned, not retried.
    pub fn start(launch: Launch, sink: Arc<dyn EventSink>) -> Result<Self, CoreError> {
        let inner = Arc::new(Inner {
            launch,
            running: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            restarts: AtomicU64::new(0),
            stderr_tail: Mutex::new(VecDeque::new()),
            sink,
        });
        let me = Self(inner);
        me.spawn()?;
        Ok(me)
    }

    fn spawn(&self) -> Result<(), CoreError> {
        let launch = &self.0.launch;
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
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        *self.0.running.lock().unwrap() = Some(Running { child, stdin });
        self.drain_stderr(stderr);
        self.read_protocol(stdout);
        Ok(())
    }

    fn drain_stderr(&self, stderr: std::process::ChildStderr) {
        let inner = self.0.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut tail = inner.stderr_tail.lock().unwrap();
                if tail.len() == STDERR_LINES_KEPT {
                    tail.pop_front();
                }
                tail.push_back(line);
            }
        });
    }

    fn read_protocol(&self, stdout: std::process::ChildStdout) {
        let me = self.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                me.handle_line(&line);
            }
            me.on_exit();
        });
    }

    fn handle_line(&self, line: &str) {
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            return; // not protocol: the child isolates its stdout, so this is defensive only
        };
        if let Some(id) = msg.get("id").and_then(Value::as_u64) {
            self.deliver(id, msg);
        } else if let Some(name) = msg.get("event").and_then(Value::as_str) {
            self.0.sink.emit(&format!("core://{name}"), msg.clone());
        }
    }

    fn deliver(&self, id: u64, msg: Value) {
        let Some(tx) = self.0.pending.lock().unwrap().remove(&id) else { return };
        let outcome = match (msg.get("result"), msg.get("error")) {
            (Some(r), _) => Ok(r.clone()),
            (None, Some(e)) => Err(serde_json::from_value::<CoreError>(e.clone())
                .unwrap_or_else(|_| CoreError::new("bad_response", "malformed error from the core"))),
            _ => Err(CoreError::new("bad_response", "response without result or error")),
        };
        let _ = tx.send(outcome);
    }

    /// The child's stdout closed: fail every caller, then restart once.
    fn on_exit(&self) {
        let status = self.reap();
        let pending: Vec<_> = self.0.pending.lock().unwrap().drain().collect();
        for (_, tx) in pending {
            let _ = tx.send(Err(CoreError::new("core_exited", "the core stopped while answering")));
        }
        let n = self.0.restarts.fetch_add(1, Ordering::SeqCst) + 1;
        if n <= MAX_RESTARTS as u64 && self.spawn().is_ok() {
            self.0.sink.emit("core://restarted", serde_json::json!({ "attempt": n, "exit": status }));
        } else {
            self.0.sink.emit("core://exited", serde_json::json!({ "exit": status }));
        }
    }

    fn reap(&self) -> Option<i32> {
        let mut guard = self.0.running.lock().unwrap();
        let Some(mut r) = guard.take() else { return None };
        r.child.wait().ok().and_then(|s| s.code())
    }

    /// Last stderr lines of the child, for a diagnostics panel. Never written to any log here.
    pub fn stderr_tail(&self) -> Vec<String> {
        self.0.stderr_tail.lock().unwrap().iter().cloned().collect()
    }

    fn write_line(&self, line: &[u8]) -> Result<(), CoreError> {
        let mut guard = self.0.running.lock().unwrap();
        let Some(r) = guard.as_mut() else {
            return Err(CoreError::new("core_unavailable", "the core is not running"));
        };
        r.stdin
            .write_all(line)
            .and_then(|_| r.stdin.write_all(b"\n"))
            .and_then(|_| r.stdin.flush())
            .map_err(|e| CoreError::new("core_unavailable", format!("cannot reach the core: {e}")))
    }

    fn register(&self) -> (u64, oneshot::Receiver<Result<Value, CoreError>>) {
        let id = self.0.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.0.pending.lock().unwrap().insert(id, tx);
        (id, rx)
    }

    async fn await_reply(
        &self,
        id: u64,
        rx: oneshot::Receiver<Result<Value, CoreError>>,
        timeout: Option<Duration>,
    ) -> Result<Value, CoreError> {
        let fut = async { rx.await.unwrap_or_else(|_| Err(CoreError::new("core_exited", "the core went away"))) };
        match timeout {
            None => fut.await,
            Some(t) => match tokio::time::timeout(t, fut).await {
                Ok(r) => r,
                Err(_) => {
                    self.0.pending.lock().unwrap().remove(&id);
                    Err(CoreError::new("timeout", "the core did not answer in time"))
                }
            },
        }
    }

    /// Any method except `key.unlock`, whose passphrase must never travel as a plain `Value`.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, CoreError> {
        self.call_with_timeout(method, params, timeout_for(method)).await
    }

    /// [`Self::call`] with an explicit timeout (tests; long-running diagnostics).
    pub async fn call_with_timeout(&self, method: &str, params: Value, timeout: Option<Duration>) -> Result<Value, CoreError> {
        if method == "key.unlock" {
            return Err(CoreError::new("bad_params", "use the unlock path for key.unlock"));
        }
        let (id, rx) = self.register();
        let line = serde_json::to_vec(&serde_json::json!({ "id": id, "method": method, "params": params }))
            .map_err(|e| CoreError::new("bad_params", e.to_string()))?;
        self.write_line(&line)?;
        self.await_reply(id, rx, timeout).await
    }

    /// `key.unlock` with the passphrase held only in zeroized buffers: the request line is
    /// built into a `Zeroizing<Vec<u8>>`, written, and wiped when this function returns.
    pub async fn unlock(&self, passphrase: Zeroizing<String>) -> Result<Value, CoreError> {
        let (id, rx) = self.register();
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
        self.write_line(&line)?;
        drop(line);
        drop(passphrase);
        self.await_reply(id, rx, timeout_for("key.unlock")).await
    }

    /// Stop the child (on app exit). Stdin closes first so a healthy core exits by itself.
    pub fn shutdown(&self) {
        self.0.restarts.store(MAX_RESTARTS as u64 + 1, Ordering::SeqCst);
        let mut guard = self.0.running.lock().unwrap();
        if let Some(mut r) = guard.take() {
            drop(r.stdin);
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                if matches!(r.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = r.child.kill();
            let _ = r.child.wait();
        }
    }
}

/// Where the core lives: `DISCONECT_CORE` (an executable path) wins; then the bundled one-dir
/// sidecar under the app's resources; in debug builds, finally the dev venv's `hearthbeat-serve`.
pub fn locate_core(resource_dir: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("DISCONECT_CORE") {
        return Some(PathBuf::from(p));
    }
    if let Some(dir) = resource_dir {
        let bundled = dir.join("hearthbeat-core").join("hearthbeat-core");
        if bundled.is_file() {
            return Some(bundled);
        }
    }
    #[cfg(debug_assertions)]
    {
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../hearthbeat/.venv/bin/hearthbeat-serve");
        if dev.is_file() {
            return Some(dev);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn passphrase_env_is_not_in_the_allowlist() {
        assert!(!ENV_ALLOWLIST.contains(&"HEARTHBEAT_PASSPHRASE"));
        assert!(!ENV_ALLOWLIST.contains(&"HEARTHBEAT_RECOVERY_WORDS"));
    }
}
