// SPDX-License-Identifier: AGPL-3.0-or-later
//! `inproc_serve --db <path>`: the app's in-process core (`disconect_app_lib::inproc`) driven over
//! stdio with the sidecar's framing, so `tools/serve_diff.py --inproc` can compare it with the
//! Python oracle. It runs the same thread, request reader and line writer the app runs; only the
//! two ends differ (stdin in, stdout out, instead of the webview's router). Dev tool, not shipped.
//!
//! Unlike `disconect-core serve` it does not move fd 1 (`isolate_stdout`) or scrub the
//! environment, because neither is done in the app either; nothing in the core prints.

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::{mpsc, Arc};

use disconect_app_lib::inproc::{self, LineSink};

struct Stdout;

impl LineSink for Stdout {
    fn line(&self, line: &str) {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(line.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(flag), Some(db), None) = (args.next(), args.next(), args.next()) else {
        eprintln!("usage: inproc_serve --db <path>");
        return ExitCode::from(2);
    };
    if flag != "--db" {
        eprintln!("usage: inproc_serve --db <path>");
        return ExitCode::from(2);
    }
    let (done_tx, done_rx) = mpsc::channel::<bool>();
    let started = inproc::start(
        db.into(),
        inproc::serve_runner,
        Arc::new(Stdout),
        move |panicked| {
            let _ = done_tx.send(panicked);
        },
    );
    let core = match started {
        Ok(core) => core,
        Err(e) => {
            eprintln!("error: cannot start the in-process core: {}", e.kind());
            return ExitCode::from(1);
        }
    };
    let mut stdin = std::io::stdin().lock();
    let mut chunk = [0u8; 8192];
    loop {
        match stdin.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if core.send_raw(&chunk[..n]).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    core.close_and_wait(); // imports finish first, as at stdin EOF
    match done_rx.recv() {
        Ok(false) => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    }
}
