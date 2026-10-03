// SPDX-License-Identifier: AGPL-3.0-or-later
//! The in-process core (Bet 12, slice A): `disconect-core`'s `serve::Session` on a thread of this
//! process instead of a child. Wire bytes are the sidecar's: requests go in as JSON lines through
//! [`ChannelReader`] into `serve::serve_lines` (the loop the binary runs over stdin), and every line
//! the session writes comes out of [`LineWriter`] one whole line at a time into a [`LineSink`]
//! (`sidecar.rs`'s id-to-oneshot router, or stdout in `examples/inproc_serve.rs`).
//!
//! What this module deliberately does NOT do, because the host is the app and not a private
//! process: it never calls `serve::isolate_stdout` (that would repoint the app's own fd 1 at
//! stderr) and never calls `keys::scrub_env_secrets` (it would mutate the app's environment).
//! The passphrase variable is not read anyway: `serve.rs` has no path to `take_env_passphrase` and
//! `disconect-core`'s `serve_never_reaches_the_environment_passphrase` fails if one appears, so the
//! sidecar's env allowlist has no in-process counterpart that is needed. What the core does see is
//! the app's own environment: `HOME`, `DISCONECT_DB`/`DISCONECT_KEYS` (path resolution), and the
//! test switches `DISCONECT_NOW` and `DISCONECT_KEYCHAIN`, which a release app launched from a
//! shell would honour; the sidecar's allowlist stripped them. Release builds default to the
//! sidecar for exactly that reason (and for the keychain binding, see the README).
//!
//! The database path is always passed in: the app resolves it (`home::resolve_default_db` on the
//! desktop, `app_data_dir()` on a phone); the core is never left to look at `$HOME` itself.
//!
//! The request path is `Zeroizing` end to end on the app side. Inside the core the request is
//! decoded into ordinary `String`s, exactly as in the sidecar process; that is the core's concern.

use std::io::{self, Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use disconect_core::serve::{self, Channel, Session};
use zeroize::Zeroizing;

/// Where whole protocol lines (no trailing newline) go.
pub trait LineSink: Send + Sync + 'static {
    fn line(&self, line: &str);
}

/// What runs on the core thread: serve `reader` with `session`, return an exit code. The default
/// is the binary's own loop; tests substitute one that panics.
pub type Runner = fn(Session, ChannelReader) -> i32;

/// The binary's loop over a channel instead of stdin (it also waits for running imports at EOF).
pub fn serve_runner(mut session: Session, reader: ChannelReader) -> i32 {
    serve::serve_lines(&mut session, reader)
}

/// `Read` over request lines sent from other threads. End of input is every sender being dropped.
pub struct ChannelReader {
    rx: Receiver<Zeroizing<Vec<u8>>>,
    current: Zeroizing<Vec<u8>>,
    at: usize,
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.at >= self.current.len() {
            match self.rx.recv() {
                Ok(next) => {
                    self.current = next;
                    self.at = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.current.len() - self.at);
        out[..n].copy_from_slice(&self.current[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// `Write` that hands each completed line to a sink. `Channel::write_line` writes one whole line
/// plus `\n` per call; a split write is still reassembled here.
struct LineWriter {
    sink: Arc<dyn LineSink>,
    buf: Vec<u8>,
}

impl Write for LineWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        while let Some(end) = self.buf.iter().position(|b| *b == b'\n') {
            let rest = self.buf.split_off(end + 1);
            let line = std::mem::replace(&mut self.buf, rest);
            self.sink.line(&String::from_utf8_lossy(&line[..end]));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A running core thread. Requests go in with [`Self::send`]; dropping or closing it ends the input.
pub struct InProcCore {
    tx: Option<Sender<Zeroizing<Vec<u8>>>>,
    handle: Option<JoinHandle<()>>,
}

/// Start the core thread for the store at `db`. `on_end(panicked)` runs on that thread when the
/// serve loop has finished (EOF) or panicked, after which the thread exits.
pub fn start(
    db: PathBuf,
    runner: Runner,
    sink: Arc<dyn LineSink>,
    on_end: impl FnOnce(bool) + Send + 'static,
) -> io::Result<InProcCore> {
    let (tx, rx) = channel::<Zeroizing<Vec<u8>>>();
    let handle = std::thread::Builder::new()
        .name("disconect-core".into())
        .spawn(move || {
            let session = Session::new(
                db,
                Channel::new(Box::new(LineWriter {
                    sink,
                    buf: Vec::new(),
                })),
            );
            let reader = ChannelReader {
                rx,
                current: Zeroizing::new(Vec::new()),
                at: 0,
            };
            // `panic = "unwind"` (Cargo.toml) is what makes this catch real; under `abort` it is dead code.
            let panicked = catch_unwind(AssertUnwindSafe(|| runner(session, reader))).is_err();
            on_end(panicked);
        })?;
    Ok(InProcCore {
        tx: Some(tx),
        handle: Some(handle),
    })
}

impl InProcCore {
    /// One request line (`\n` is added). The bytes are wiped when the core has read them.
    pub fn send(&self, line: &[u8]) -> io::Result<()> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(line.len() + 1));
        bytes.extend_from_slice(line);
        bytes.push(b'\n');
        self.send_bytes(bytes)
    }

    /// Raw input bytes exactly as given, for a stdin pump (`examples/inproc_serve.rs`): the core's
    /// loop does the line splitting, as it does over a pipe.
    pub fn send_raw(&self, chunk: &[u8]) -> io::Result<()> {
        self.send_bytes(Zeroizing::new(chunk.to_vec()))
    }

    fn send_bytes(&self, bytes: Zeroizing<Vec<u8>>) -> io::Result<()> {
        let gone = || io::Error::from(io::ErrorKind::BrokenPipe);
        self.tx
            .as_ref()
            .ok_or_else(gone)?
            .send(bytes)
            .map_err(|_| gone())
    }

    /// End the input and wait for the thread (running imports finish first, as at stdin EOF).
    pub fn close_and_wait(mut self) {
        self.tx = None;
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    /// End the input and wait up to `limit`; a thread still busy (a long import) is left to the
    /// process exit, like a sidecar that has to be killed.
    pub fn close_for(mut self, limit: Duration) {
        self.tx = None;
        if let Some(h) = self.handle.take() {
            let deadline = Instant::now() + limit;
            while !h.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(25));
            }
            if h.is_finished() {
                let _ = h.join();
            }
        }
    }
}
