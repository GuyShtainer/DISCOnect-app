//! 12-H: the pairing client's cancel points and request timeout, against a bare TCP server that plays the
//! offerer badly (answers while a cancel lands; or never answers at all).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use disconect_core::pair::{self, Offer, PairError};
use disconect_core::pair_client::{self, Joined, LandStep, REQUEST_TIMEOUT};

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
    let Err(error) = result else { panic!("the join must not succeed") };
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
    let Err(error) = result else { panic!("the join must not succeed") };
    assert!(matches!(error, PairError::Cancelled), "{error:?}");
    assert!(elapsed >= Duration::from_secs(5), "the request did time out ({elapsed:?})");
    assert!(elapsed < Duration::from_secs(20), "one request timeout, not the old 30 s ({elapsed:?})");
}

/// A joined pairing with a master and key-file bytes that are never used: the landing is stopped at its first step.
fn joined_for(url: &str) -> Joined {
    Joined { master: zeroize::Zeroizing::new([3u8; 32]), key_file_bytes: b"not reached".to_vec(), url: url.to_string() }
}

/// (d) A landing that fails before its commit point (the key file) takes its relay.json back out: the next
/// offer, from any Mac, is not refused as already paired.
#[test]
fn a_landing_that_fails_before_the_key_file_leaves_no_relay_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("phone").join("phone.hbdb");
    let relay_file = dir.path().join("phone").join("relay.json");
    let joined = joined_for("http://10.0.0.2:4000");
    let mut stop_after_relay = |step: LandStep| match step {
        LandStep::RelayFile => Err(PairError::Landing("disk full".into())),
        _ => Ok(()),
    };
    let Err(error) = pair_client::land_with(&joined, &db, &relay_file, &mut stop_after_relay) else { panic!("stopped") };
    assert!(matches!(error, PairError::Landing(_)), "{error:?}");
    assert!(!relay_file.exists(), "relay.json is taken back out");
    assert!(!db.exists());
    assert!(pair_client::check_landing_site(&db, &relay_file, "http://10.0.0.9:4000").is_ok());
}

/// (d) A crash leftover (relay.json beside no key file and no store) never refuses the next join; a relay
/// file that already named the url before the landing is kept when the landing fails.
#[test]
fn a_relay_file_leftover_does_not_refuse_the_next_join_and_a_matching_one_is_kept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("phone.hbdb");
    let relay_file = dir.path().join("relay.json");
    std::fs::write(&relay_file, "{\"lan\": \"http://10.0.0.2:4000\"}\n").expect("leftover"); // the relay file's own shape
    assert!(pair_client::check_landing_site(&db, &relay_file, "http://10.0.0.9:4000").is_ok(), "a leftover is not a pairing");
    let joined = joined_for("http://10.0.0.2:4000"); // the same url the file already names
    let mut stop_after_relay = |step: LandStep| match step {
        LandStep::RelayFile => Err(PairError::Landing("killed".into())),
        _ => Ok(()),
    };
    assert!(pair_client::land_with(&joined, &db, &relay_file, &mut stop_after_relay).is_err());
    assert!(relay_file.exists(), "a relay file that named this url before the landing is not ours to remove");
    let other = joined_for("http://10.0.0.9:4000");
    assert!(pair_client::land_with(&other, &db, &relay_file, &mut stop_after_relay).is_err());
    assert!(!relay_file.exists(), "rewritten for another url, then taken back out");
}
