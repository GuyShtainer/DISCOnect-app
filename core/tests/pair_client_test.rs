//! 12-H: the pairing client's cancel points and request timeout, against a bare TCP server that plays the
//! offerer badly (answers while a cancel lands; or never answers at all).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use disconect_core::pair::{self, Offer, PairError};
use disconect_core::pair_client::{self, REQUEST_TIMEOUT};

/// A syntactically valid offer for `url` (a real X25519 public key; the secrets are random, so it is not
/// joinable), expiring well after the test.
fn forged_offer(url: &str) -> String {
    let (_secret, public) = pair::ephemeral().expect("key");
    let exp = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs() + 300;
    Offer { pub_key: public, c: [7u8; 32], s: [9u8; 16], id: [5u8; 16], exp, url: url.to_string() }.encode()
}

fn listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://127.0.0.1:{}", listener.local_addr().expect("addr").port());
    (listener, url)
}

/// (a) The cancel lands while the offerer is answering the POST: the join ends as `Cancelled` and the code is
/// never shown, on any caller (the CLI joiner has no guard of its own).
#[test]
fn a_cancel_during_the_post_shows_no_code() {
    let (listener, url) = listener();
    let cancel = Arc::new(AtomicBool::new(false));
    let server_cancel = Arc::clone(&cancel);
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf); // the request head and the 64-byte body, enough of it
        server_cancel.store(true, Ordering::SeqCst); // the user cancelled while the request was in flight
        let _ = stream.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = stream.flush();
    });
    let shown = AtomicUsize::new(0);
    let result = pair_client::join(&forged_offer(&url), &mut |_code| {
        shown.fetch_add(1, Ordering::SeqCst);
    }, &cancel);
    let error = result.err().expect("the join must not succeed");
    assert!(matches!(error, PairError::Cancelled), "{error:?}");
    assert_eq!(shown.load(Ordering::SeqCst), 0, "no code after a cancel");
}

/// (b) A hung offerer holds the POST; the cancel waits at most one request timeout, which is 10 s now, not 30.
#[test]
fn a_cancel_behind_a_hung_request_waits_one_request_timeout_at_most() {
    assert!(REQUEST_TIMEOUT <= Duration::from_secs(10));
    let (listener, url) = listener();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        std::thread::sleep(Duration::from_secs(40)); // never answers; the connection stays open
        drop(stream);
    });
    let cancel = AtomicBool::new(true); // cancelled before the (first and only) request even returns
    let started = Instant::now();
    let result = pair_client::join(&forged_offer(&url), &mut |_code| panic!("no code"), &cancel);
    let elapsed = started.elapsed();
    let error = result.err().expect("the join must not succeed");
    assert!(matches!(error, PairError::Cancelled), "{error:?}");
    assert!(elapsed >= Duration::from_secs(5), "the request did time out ({elapsed:?})");
    assert!(elapsed < Duration::from_secs(20), "one request timeout, not the old 30 s ({elapsed:?})");
}
