// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test helper for `tests/serve_process_test.rs`: isolates the protocol stream exactly as `serve`
//! does, then makes noise on every stdout path a stray write could take, then answers two requests.
//! The parent test asserts that stdout carries protocol lines only and stderr carries the noise.
//! (The oracle's twin injects a noisy method into the Python server; this binary has no methods to
//! inject into, so it drives the same isolation function directly.)

use std::io::Write;

use disconect_core::serve::{self, Channel};

fn main() {
    let private = match serve::isolate_stdout() {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("cannot isolate: {error}");
            std::process::exit(1);
        }
    };
    let channel = Channel::new(Box::new(private));
    println!("STRAY PRINT");
    let _ = std::io::stdout().write_all(b"STRAY STDOUT\n");
    let _ = std::io::stdout().flush();
    // SAFETY: a plain write(2) to descriptor 1, which now points at stderr.
    unsafe {
        let noise = b"STRAY RAW WRITE\n";
        libc::write(1, noise.as_ptr().cast(), noise.len());
    }
    let _ = channel.write_line("{\"id\":1,\"result\":{\"ok\":true}}");
    let _ = channel.write_line("{\"id\":2,\"result\":{\"ok\":true}}");
}
