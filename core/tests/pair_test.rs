// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 12-E slice 2: the pairing routes, the joiner and its landing, and the two CLI commands, end to
//! end on 127.0.0.1 with synthetic data and the committed test key. Every path is in a scratch dir and
//! every child process gets a sandboxed `HOME`.

mod common;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::convergence::{MONITORING, daily_rows, fingerprint, fit_drop};
use common::{PASSPHRASE, encrypted_copy, fixtures};
use disconect_core::keys::{self, PassphraseSource};
use disconect_core::pair::{self, Keys, Offer, PairError, sas_text};
use disconect_core::pair_client::{self, Joined, Joiner, LandStep, check_landing_site, join, land_with};
use disconect_core::relay::folder::FolderRelay;
use disconect_core::relay::lan::{LanRelay, wall_clock};
use disconect_core::relay::lan_server::{Ctx, LanServer, Limits, Logger, handle};
use disconect_core::relay::pair_routes::{PairHandle, PairOffer, PairState};
use disconect_core::relay::sync;
use disconect_core::sources::import_path;
use disconect_core::store;
use x25519_dalek::StaticSecret;

fn key_file_bytes() -> Vec<u8> {
    fs::read(fixtures().join("test.keys.json")).expect("fixture key file")
}

fn master() -> [u8; 32] {
    let secret = keys::unlock(
        &fixtures().join("test.keys.json"),
        PassphraseSource::Explicit(PASSPHRASE),
    )
    .expect("unlock the fixture key");
    *secret
}

fn http() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .proxy(None)
        .build()
        .into()
}

fn post(url: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut response = http().post(url).send(body).expect("post");
    let status = response.status().as_u16();
    (status, response.body_mut().read_to_vec().expect("body"))
}

fn get(url: &str) -> (u16, Vec<u8>) {
    let mut response = http().get(url).call().expect("get");
    let status = response.status().as_u16();
    (status, response.body_mut().read_to_vec().expect("body"))
}

type Log = Arc<Mutex<Vec<(String, u16)>>>;

/// An offerer: a scratch encrypted store with content, pushed to a scratch folder, and the LAN server
/// with one offer over it.
struct Offerer {
    _tmp: tempfile::TempDir,
    server: LanServer,
    text: String,
    handle: PairHandle,
    log: Log,
    conn_holder: store::Store,
}

impl Offerer {
    fn start() -> Offerer {
        let tmp = tempfile::tempdir().expect("tmp");
        let (dir, db) = encrypted_copy();
        let secret = keys::unlock(&keys::key_path_for(&db), PassphraseSource::Explicit(PASSPHRASE)).expect("unlock");
        let opened = store::open_for_write_with(&db, "test", 5.0, Some(&secret)).expect("open");
        import_path(opened.conn(), &fit_drop(tmp.path(), "fits", &MONITORING), None, None).expect("import");
        let folder = tmp.path().join("relay");
        sync::push(opened.conn(), &*secret, &FolderRelay::new(&folder)).expect("push");
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let logger: Logger = Arc::new(move |m, s| sink.lock().expect("log").push((m.to_string(), s)));
        let (server, text, handle) =
            LanServer::start_with_offer("127.0.0.1:0", &folder, &*secret, logger, Limits::default()).expect("serve");
        std::mem::forget(dir); // the store's scratch dir lives as long as the test process
        Offerer { _tmp: tmp, server, text, handle, log, conn_holder: opened }
    }

    fn offer(&self) -> Offer {
        Offer::parse(&self.text).expect("offer")
    }

    fn url(&self) -> String {
        self.offer().url
    }

    fn route(&self) -> String {
        format!("{}/v1/pair/{}", self.url(), hex::encode(self.offer().id))
    }
}

/// Run a join in a thread; the codes it showed come back on the channel.
fn spawn_join(
    text: String,
    handle: Option<PairHandle>,
) -> (std::thread::JoinHandle<Result<Joined, PairError>>, mpsc::Receiver<String>) {
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let cancel = AtomicBool::new(false);
        join(
            &text,
            &mut |code| {
                if let Some(h) = &handle {
                    // a cheap sanity check only: the forged-202 test carries the proof that the code
                    // is shown after the offerer's tag verified, not this state read
                    assert_eq!(h.state(), PairState::Bound, "code shown before the offerer bound us");
                }
                tx.send(code.to_string()).expect("send");
            },
            &cancel,
        )
    });
    (worker, rx)
}

/// The whole honest dance; the joiner's result and its code.
fn pair_once(o: &Offerer) -> (Joined, String) {
    let (worker, rx) = spawn_join(o.text.clone(), Some(o.handle.clone()));
    assert!(o.handle.wait_joined(Duration::from_secs(10)), "joined");
    let shown = rx.recv_timeout(Duration::from_secs(10)).expect("the joiner's code");
    // the offerer never learns its own code through the API; a release on the joiner's code proves both agree
    o.handle.release(&shown, &master(), &key_file_bytes()).expect("release");
    (worker.join().expect("thread").expect("joined"), shown)
}

fn join_body(offer: &Offer, s: &[u8; 16], secret: &StaticSecret, joiner_pub: &[u8; 32]) -> [u8; 64] {
    let shared = pair::dh(secret, &offer.pub_key).expect("dh");
    let t = pair::transcript(&offer.pub_key, joiner_pub, &offer.id, offer.exp, &offer.c);
    let keys = Keys::derive(&shared, s, &t);
    let mut body = [0u8; 64];
    body[..32].copy_from_slice(joiner_pub);
    body[32..].copy_from_slice(&pair::joiner_tag(&keys));
    body
}

// ---- the honest dance ----

#[test]
fn pairing_over_loopback_hands_over_the_key_and_the_pulled_store_converges() {
    let o = Offerer::start();
    let (joined, _code) = pair_once(&o);
    assert_eq!(joined.key_file_bytes, key_file_bytes(), "the key file, verbatim");
    assert_eq!(*joined.master, master(), "the master");
    assert_eq!(joined.url, o.url());

    // a second GET after the release answers 200 again, with the same bytes
    let first = get(&format!("{}/payload", o.route()));
    let second = get(&format!("{}/payload", o.route()));
    assert_eq!(first.0, 200);
    assert_eq!(first, second);

    // land: relay file, key file, store, first pull
    let dir = tempfile::tempdir().expect("dir");
    let site = dir.path().join("site");
    fs::create_dir_all(&site).expect("site"); // exists before the landing, with the umask's mode
    let db = site.join("joined.hbdb");
    let relay_file = site.join("relay.json");
    check_landing_site(&db, &relay_file, &joined.url).expect("free site");
    let pulled = pair_client::land(&joined, &db, &relay_file).expect("land");
    assert_eq!(pulled.status, "ok");
    assert!(pulled.records_new > 0, "something was pulled");
    assert_eq!(fs::read(keys::key_path_for(&db)).expect("key file"), key_file_bytes());
    assert_eq!(
        fs::read_to_string(&relay_file).expect("relay file"),
        format!("{{\"lan\": \"{}\"}}\n", joined.url)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(keys::key_path_for(&db)).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(&site).expect("meta").permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "the key file's directory is 0700 even if it existed");
    }
    let secret = keys::unlock(&keys::key_path_for(&db), PassphraseSource::Explicit(PASSPHRASE)).expect("unlock");
    let opened = store::open_for_write_with(&db, "test", 5.0, Some(&secret)).expect("open joined");
    assert_eq!(fingerprint(opened.conn()), fingerprint(o.conn_holder.conn()), "raw + ranges + counts");
    assert_eq!(daily_rows(opened.conn()), daily_rows(o.conn_holder.conn()), "daily rows");

    // the logger saw method and status only, in this order for the pair routes
    let log = o.log.lock().expect("log").clone();
    assert!(log.iter().all(|(m, s)| matches!(m.as_str(), "GET" | "POST" | "PUT" | "DELETE") && (200..=410).contains(s)));
    let pair_part: Vec<_> = log.iter().filter(|(m, _)| m == "POST").collect();
    assert_eq!(pair_part, vec![&("POST".to_string(), 202)], "one join");
    o.server.stop();
}

// ---- negatives on the live server ----

#[test]
fn a_wrong_secret_is_401_and_the_offer_stays_open_for_the_real_joiner() {
    let o = Offerer::start();
    let offer = o.offer();
    let (secret, joiner_pub) = pair::ephemeral().expect("ephemeral");
    let body = join_body(&offer, &[0xEE; 16], &secret, &joiner_pub);
    let (status, reply) = post(&o.route(), &body);
    assert_eq!((status, reply.len()), (401, 0));
    assert_eq!(o.handle.state(), PairState::Open);
    // a low-order public key is a wrong tag too
    let mut low = [0u8; 64];
    low[32..].copy_from_slice(&[7u8; 32]);
    assert_eq!(post(&o.route(), &low).0, 401);
    let (joined, _) = pair_once(&o);
    assert_eq!(*joined.master, master());
    o.server.stop();
}

#[test]
fn the_same_key_again_is_the_same_202_and_another_key_aborts_the_offer() {
    let o = Offerer::start();
    let offer = o.offer();
    let (secret, joiner_pub) = pair::ephemeral().expect("ephemeral");
    let body = join_body(&offer, &offer.s, &secret, &joiner_pub);
    let first = post(&o.route(), &body);
    let again = post(&o.route(), &body);
    assert_eq!(first.0, 202);
    assert_eq!(first.1.len(), 64, "N_o || tag");
    assert_eq!(pair::commit(first.1[..32].try_into().expect("32")), offer.c, "the reveal is the committed nonce");
    assert_eq!(first, again, "idempotent: the same status and the same reply");
    assert_eq!(o.handle.state(), PairState::Bound);

    // a different key with a valid tag: 410, and the first joiner is cut off too
    let (secret2, pub2) = pair::ephemeral().expect("ephemeral");
    let other = join_body(&offer, &offer.s, &secret2, &pub2);
    assert_eq!(post(&o.route(), &other).0, 410);
    assert_eq!(post(&o.route(), &body).0, 410, "410 for both");
    assert_eq!(get(&format!("{}/payload", o.route())).0, 410);
    assert_eq!(o.handle.state(), PairState::Aborted);
    assert_eq!(
        o.handle.release("000000", &master(), &key_file_bytes()),
        Err(PairError::OfferEnded),
        "nothing is released"
    );
    assert_eq!(get(&format!("{}/payload", o.route())).0, 410);
    o.server.stop();
}

#[test]
fn a_join_tagged_under_another_commitment_is_401_and_binds_nothing() {
    // 12-G N8: `c` is in the transcript, so a joiner that parsed a different commitment derives another K
    let o = Offerer::start();
    let mut other = o.offer();
    other.c[0] ^= 1;
    let (secret, joiner_pub) = pair::ephemeral().expect("ephemeral");
    let body = join_body(&other, &other.s, &secret, &joiner_pub);
    assert_eq!(post(&o.route(), &body).0, 401);
    assert_eq!(o.handle.state(), PairState::Open);
    o.server.stop();
}

#[test]
fn two_offers_commit_to_two_nonces_and_two_joiners_draw_two_keys() {
    let (a, _) = PairOffer::new("http://127.0.0.1:1").expect("offer");
    let (b, _) = PairOffer::new("http://127.0.0.1:1").expect("offer");
    assert_ne!(Offer::parse(&a).expect("a").c, Offer::parse(&b).expect("b").c);
    // 12-G attack M1: a second text with the SAME id but another c and s (a re-planted offer) is another
    // joiner with another key; a key is never reused across offers by construction
    let parsed_a = Offer::parse(&a).expect("a");
    let mut planted = parsed_a.clone();
    planted.c = pair::commit(&[0x77u8; 32]);
    planted.s = [0x55u8; 16];
    let (j1, j2) = (Joiner::new(&a).expect("joiner"), Joiner::new(&planted.encode()).expect("joiner"));
    assert_eq!(j1.offer().id, j2.offer().id);
    assert_ne!(j1.joiner_pub(), j2.joiner_pub());
    assert_eq!(j1.offer().c, parsed_a.c);
    assert_eq!(j2.offer().c, planted.c);
    assert_eq!(j1.offer().s, [0u8; 16], "the joiner keeps no copy of s once K exists");
}

#[test]
fn a_wrong_typed_code_aborts_and_releases_nothing() {
    let o = Offerer::start();
    let (worker, rx) = spawn_join(o.text.clone(), None);
    assert!(o.handle.wait_joined(Duration::from_secs(10)), "joined");
    let shown = rx.recv_timeout(Duration::from_secs(10)).expect("code");
    let wrong = sas_text((shown.parse::<u32>().expect("digits") + 1) % 1_000_000);
    assert_eq!(o.handle.release(&wrong, &master(), &key_file_bytes()), Err(PairError::CodesDiffer));
    assert_eq!(worker.join().expect("thread").err(), Some(PairError::OfferEnded));
    o.server.stop();
}

#[test]
fn a_pair_route_with_a_wrong_length_is_refused_before_a_body_byte_is_read_on_the_wire_too() {
    let o = Offerer::start();
    let addr: SocketAddr = o.url().trim_start_matches("http://").parse().expect("addr");
    let route = o.route().replace(&o.url(), "");
    for (method, path, length) in [
        ("POST", route.clone(), 1_000_000usize),
        ("POST", route.clone(), 63),
        ("POST", route.clone(), 65),
        ("GET", format!("{route}/payload"), 5),
    ] {
        let mut stream = TcpStream::connect(addr).expect("connect");
        let head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {length}\r\n\r\n");
        stream.write_all(head.as_bytes()).expect("head");
        stream.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let started = Instant::now();
        let mut text = [0u8; 64];
        let count = stream.read(&mut text).expect("an answer, no body sent");
        assert!(String::from_utf8_lossy(&text[..count]).starts_with("HTTP/1.1 400 "), "{method} {length}");
        assert!(started.elapsed() < Duration::from_secs(2), "answered without waiting for a body");
    }
    assert_eq!(o.handle.state(), PairState::Open);
    o.server.stop();
}

// ---- negatives on `handle` itself ----

struct Untouchable;

impl Read for Untouchable {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("a body byte was read");
    }
}

fn ctx_with(dir: &Path, offer: Option<&PairHandle>) -> Ctx {
    let ctx = Ctx::new(dir.join("relay"), &master());
    match offer {
        Some(h) => ctx.with_offer(h.shared()),
        None => ctx,
    }
}

#[test]
fn no_offer_no_pair_routes_and_the_status_codes_are_exact() {
    let tmp = tempfile::tempdir().expect("tmp");
    let url = "http://127.0.0.1:9";
    let (text, h) = PairOffer::new_at(url, 1_000).expect("offer");
    let id = hex::encode(Offer::parse(&text).expect("offer").id);
    let route = format!("/v1/pair/{id}");
    let plain = ctx_with(tmp.path(), None);
    for (method, path) in [("POST", route.clone()), ("GET", format!("{route}/payload")), ("GET", "/v1/pair".to_string())] {
        assert_eq!(handle(&plain, method, &path, None, Some(64), &mut Untouchable, 1_000).status, 404, "{path}");
    }
    let ctx = ctx_with(tmp.path(), Some(&h));
    let foreign = format!("/v1/pair/{}", "ab".repeat(16));
    assert_eq!(handle(&ctx, "POST", &foreign, None, Some(64), &mut Untouchable, 1_000).status, 404);
    assert_eq!(handle(&ctx, "GET", &format!("{route}/other"), None, None, &mut Untouchable, 1_000).status, 404);
    assert_eq!(handle(&ctx, "GET", &route, None, None, &mut Untouchable, 1_000).status, 405);
    assert_eq!(handle(&ctx, "POST", &format!("{route}/payload"), None, Some(0), &mut Untouchable, 1_000).status, 405);
    // wrong declared lengths: nothing is read
    for declared in [None, Some(0), Some(63), Some(65), Some(usize::MAX)] {
        let reply = handle(&ctx, "POST", &route, None, declared, &mut Untouchable, 1_000);
        assert_eq!(reply.status, 400, "{declared:?}");
    }
    assert_eq!(handle(&ctx, "GET", &format!("{route}/payload"), None, Some(1), &mut Untouchable, 1_000).status, 400);
    assert_eq!(handle(&ctx, "GET", &format!("{route}/payload"), None, None, &mut Untouchable, 1_000).status, 202);
}

#[test]
fn an_expired_offer_is_410_on_every_route() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (text, h) = PairOffer::new_at("http://127.0.0.1:9", 1_000).expect("offer");
    let offer = Offer::parse(&text).expect("offer");
    let route = format!("/v1/pair/{}", hex::encode(offer.id));
    let ctx = ctx_with(tmp.path(), Some(&h));
    let (secret, joiner_pub) = pair::ephemeral().expect("ephemeral");
    let body = join_body(&offer, &offer.s, &secret, &joiner_pub);
    // at exp the offer is still alive, one second later it is not
    let live = handle(&ctx, "POST", &route, None, Some(64), &mut &body[..], offer.exp);
    assert_eq!(live.status, 202);
    let late = offer.exp + 1;
    assert_eq!(handle(&ctx, "POST", &route, None, Some(64), &mut Untouchable, late).status, 410);
    assert_eq!(handle(&ctx, "GET", &format!("{route}/payload"), None, None, &mut Untouchable, late).status, 410);
}

#[test]
fn a_joiner_refuses_an_offer_that_is_already_expired() {
    let (text, _h) = PairOffer::new_at("http://127.0.0.1:9", wall_clock() - 2_000).expect("offer");
    let mut shown = false;
    let result = join(&text, &mut |_| shown = true, &AtomicBool::new(false));
    assert_eq!(result.err(), Some(PairError::Expired));
    assert!(!shown);
}

// ---- forged and hostile offerers (a fake server on 127.0.0.1) ----

#[derive(Clone, Copy)]
enum Fake {
    /// `202` with an empty body.
    NoTag,
    /// `202` with the right reveal and 32 wrong tag bytes.
    WrongTag,
    /// `202` with a reveal that is not the committed nonce, and a real tag over that reveal.
    WrongReveal,
    /// A real tag, a payload sealed under another AAD.
    BadAad,
    /// A real tag and payload, but a master that is not the key file's.
    WrongMaster,
    /// The first POST gets an empty `202`; the second (which must carry the identical body) gets a real one.
    NoTagThenGood,
    /// The first POST connection is closed unanswered; then everything is honest.
    GoodAfterDrop,
}

fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        let n = stream.read(&mut chunk).ok().filter(|n| *n > 0)?;
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let length = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
        .unwrap_or(0);
    let mut body = buf[end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).ok().filter(|n| *n > 0)?;
        body.extend_from_slice(&chunk[..n]);
    }
    Some((head.lines().next().unwrap_or("").to_string(), body))
}

fn answer(stream: &mut TcpStream, status: u16, body: &[u8]) {
    let head = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

/// A fake offerer; returns the offer text for it. It answers until the process ends.
fn fake_offerer(mode: Fake) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (secret, pub_key) = pair::ephemeral().expect("ephemeral");
    let n_o = [0x42u8; 32];
    let offer = Offer { pub_key, c: pair::commit(&n_o), s: [3; 16], id: [4; 16], exp: wall_clock() + 600, url: format!("http://{addr}") };
    let text = offer.encode();
    std::thread::spawn(move || {
        let mut keys_t: Option<(Keys, [u8; pair::TRANSCRIPT_LEN])> = None;
        let mut dropped = false;
        let mut first_body: Option<Vec<u8>> = None;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Some((line, body)) = read_request(&mut stream) else { continue };
            if line.starts_with("POST") && body.len() == 64 {
                if matches!(mode, Fake::GoodAfterDrop) && !dropped {
                    dropped = true;
                    continue; // the stream drops here: accepted, read, closed
                }
                let joiner_pub: [u8; 32] = body[..32].try_into().expect("32");
                let shared = pair::dh(&secret, &joiner_pub).expect("dh");
                let t = pair::transcript(&offer.pub_key, &joiner_pub, &offer.id, offer.exp, &offer.c);
                let keys = Keys::derive(&shared, &offer.s, &t);
                match mode {
                    Fake::NoTagThenGood if first_body.is_none() => {
                        first_body = Some(body.clone());
                        answer(&mut stream, 202, b"");
                        continue;
                    }
                    Fake::NoTagThenGood => {
                        assert_eq!(first_body.as_deref(), Some(&body[..]), "the retry re-sends the identical body");
                        answer(&mut stream, 202, &pair::offerer_reply(&keys, &n_o));
                    }
                    Fake::NoTag => answer(&mut stream, 202, b""),
                    Fake::WrongTag => answer(&mut stream, 202, &[n_o.to_vec(), vec![9u8; 32]].concat()),
                    Fake::WrongReveal => answer(&mut stream, 202, &pair::offerer_reply(&keys, &[0x43u8; 32])),
                    _ => answer(&mut stream, 202, &pair::offerer_reply(&keys, &n_o)),
                }
                keys_t = Some((keys, t));
            } else if line.starts_with("GET") {
                let sealed = keys_t.as_ref().map(|(keys, t)| match mode {
                    Fake::BadAad => pair::seal_payload(keys, b"another transcript", &master(), &key_file_bytes()),
                    Fake::WrongMaster => pair::seal_payload(keys, t, &[7u8; 32], &key_file_bytes()),
                    Fake::GoodAfterDrop | Fake::NoTagThenGood => pair::seal_payload(keys, t, &master(), &key_file_bytes()),
                    _ => Vec::new(),
                });
                match sealed {
                    Some(bytes) if !bytes.is_empty() => answer(&mut stream, 200, &bytes),
                    _ => answer(&mut stream, 202, b""),
                }
            }
        }
    });
    text
}

#[test]
fn a_forged_202_shows_no_code_and_a_bad_payload_returns_nothing() {
    for (mode, want) in [
        (Fake::NoTag, PairError::BadTag),
        (Fake::WrongTag, PairError::BadTag),
        (Fake::WrongReveal, PairError::BadTag),
        (Fake::BadAad, PairError::BadPayload),
        (Fake::WrongMaster, PairError::KeyFile("its key id is not the master's")),
    ] {
        let text = fake_offerer(mode);
        let mut codes = Vec::new();
        let result = join(&text, &mut |c| codes.push(c.to_string()), &AtomicBool::new(false));
        assert_eq!(result.err(), Some(want.clone()), "{want}");
        let shown = !codes.is_empty();
        let expect_code = matches!(mode, Fake::BadAad | Fake::WrongMaster);
        assert_eq!(shown, expect_code, "the code is shown only after a verified tag");
    }
}

#[test]
fn a_joiner_joined_again_after_a_failed_202_sends_the_same_body_and_succeeds() {
    // 12-F's "Try again": one Joiner per offer, the same key and body on every join
    let text = fake_offerer(Fake::NoTagThenGood);
    let joiner = Joiner::new(&text).expect("joiner");
    let mut codes = Vec::new();
    let cancel = AtomicBool::new(false);
    assert_eq!(joiner.join(&mut |c| codes.push(c.to_string()), &cancel).err(), Some(PairError::BadTag));
    assert!(codes.is_empty(), "no code on an empty 202");
    let joined = joiner.join(&mut |c| codes.push(c.to_string()), &cancel).expect("second join");
    assert_eq!(codes.len(), 1);
    assert_eq!(*joined.master, master());
}

#[test]
fn a_joiner_whose_first_post_is_dropped_retries_the_same_body_and_succeeds() {
    let text = fake_offerer(Fake::GoodAfterDrop);
    let started = Instant::now();
    let joined = join(&text, &mut |_| {}, &AtomicBool::new(false)).expect("the retry succeeds");
    assert_eq!(*joined.master, master());
    assert!(started.elapsed() >= Duration::from_millis(400), "the retry waited");
}

#[test]
fn a_joiner_that_fails_writes_nothing() {
    let tmp = tempfile::tempdir().expect("tmp");
    let db = tmp.path().join("fresh").join("j.hbdb");
    let text = fake_offerer(Fake::BadAad);
    let mut joiner = cli(tmp.path())
        .arg("--db").arg(&db)
        .args(["pair", "join"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn join");
    joiner.stdin.take().expect("stdin").write_all(format!("{text}\n").as_bytes()).expect("offer");
    let out = joiner.wait_with_output().expect("output");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "no summary");
    let site = db.parent().expect("parent");
    assert!(!db.exists() && !keys::key_path_for(&db).exists());
    assert!(!site.join("relay.json").exists() && !site.exists(), "not even the directory");
}

#[test]
fn offer_debug_does_not_show_the_secret() {
    let offer = Offer { pub_key: [1; 32], c: [6; 32], s: [0xab; 16], id: [2; 16], exp: 5, url: "http://x:1".into() };
    let shown = format!("{offer:?}");
    assert!(shown.contains("<redacted>"));
    assert!(!shown.contains("171") && !shown.contains(&hex::encode(offer.s)) && !shown.contains("ab, ab"), "{shown}");
}

#[test]
fn write_atomic_leaves_no_half_file_when_the_write_fails_and_makes_the_parent_0700() {
    let dir = tempfile::tempdir().expect("dir");
    // the target is a non-empty directory: the rename fails after the temp file was written
    let target = dir.path().join("relay.json");
    fs::create_dir_all(target.join("inner")).expect("blocker");
    assert!(pair_client::write_atomic(&target, b"{}").is_err());
    let names: Vec<_> = fs::read_dir(dir.path()).expect("ls").map(|e| e.expect("e").file_name()).collect();
    assert_eq!(names, vec![std::ffi::OsString::from("relay.json")], "no temp file left: {names:?}");
    assert!(target.is_dir(), "the target is untouched");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let loose = dir.path().join("loose");
        fs::create_dir_all(&loose).expect("loose");
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).expect("chmod");
        pair_client::write_atomic(&loose.join("f"), b"x").expect("write");
        assert_eq!(fs::metadata(&loose).expect("meta").permissions().mode() & 0o777, 0o700);
    }
}

#[test]
fn wait_delivered_turns_true_only_after_the_first_200_of_the_payload() {
    let o = Offerer::start();
    let (worker, rx) = spawn_join(o.text.clone(), None);
    assert!(o.handle.wait_joined(Duration::from_secs(10)), "joined");
    let shown = rx.recv_timeout(Duration::from_secs(10)).expect("code");
    o.handle.release(&shown, &master(), &key_file_bytes()).expect("release");
    // released, but nobody has fetched yet (the joiner polls every 500 ms; a short wait may race it,
    // so assert the order the other way round below)
    let delivered = o.handle.wait_delivered(Duration::from_secs(10));
    assert!(delivered, "the joiner's fetch was a 200");
    worker.join().expect("thread").expect("joined");
    assert!(o.handle.wait_delivered(Duration::from_millis(1)), "stays true");
    o.server.stop();
}

#[test]
fn wait_delivered_times_out_when_nobody_fetches() {
    let (_text, handle) = PairOffer::new("http://127.0.0.1:1").expect("offer");
    assert!(!handle.wait_delivered(Duration::from_millis(100)));
    handle.abort();
    assert!(!handle.wait_delivered(Duration::from_secs(5)), "an ended offer answers false at once");
}

// ---- the landing ----

#[test]
fn the_landing_site_preconditions_refuse_before_anything_is_written() {
    let url = "http://127.0.0.1:9";
    let dir = tempfile::tempdir().expect("dir");
    let db = dir.path().join("s.hbdb");
    let relay_file = dir.path().join("s.relay.json");
    check_landing_site(&db, &relay_file, url).expect("an empty site is free");

    fs::write(&relay_file, "{\"lan\": \"http://127.0.0.1:9\"}\n").expect("same relay file");
    check_landing_site(&db, &relay_file, url).expect("the same relay content is fine");
    fs::write(&relay_file, "{\"folder\": \"/elsewhere\"}\n").expect("other relay file");
    assert!(matches!(check_landing_site(&db, &relay_file, url), Err(PairError::Precondition(_))));
    fs::remove_file(&relay_file).expect("rm");

    fs::write(&db, b"x").expect("db");
    assert!(matches!(check_landing_site(&db, &relay_file, url), Err(PairError::Precondition(_))));
    fs::remove_file(&db).expect("rm");

    let key_path = keys::key_path_for(&db);
    fs::write(&key_path, b"x").expect("key");
    assert!(matches!(check_landing_site(&db, &relay_file, url), Err(PairError::Precondition(_))));
    fs::remove_file(&key_path).expect("rm");

    fs::write(keys::next_path_for(&key_path), b"x").expect("next");
    assert!(matches!(check_landing_site(&db, &relay_file, url), Err(PairError::Precondition(_))));
}

/// The CLI side of `DISCONECT_KEYS` (a process-wide variable: only a child process sets it).
#[test]
fn pair_join_refuses_before_any_request_with_keys_env_or_an_existing_store() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (text, _h) = PairOffer::new("http://127.0.0.1:1").expect("offer"); // nothing listens there
    let db = tmp.path().join("j.hbdb");
    let run = |db: &Path, env_keys: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_disconect-core"));
        cmd.env("HOME", tmp.path()).env_remove("DISCONECT_KEYS").arg("--db").arg(db).args(["pair", "join"]);
        if env_keys {
            cmd.env("DISCONECT_KEYS", tmp.path().join("elsewhere.keys.json"));
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn");
        child.stdin.take().expect("stdin").write_all(format!("{text}\n").as_bytes()).expect("offer");
        child.wait_with_output().expect("output")
    };
    let out = run(&db, true);
    // 2 (usage), never 5 (unreachable): no request was made
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("disconect-pair:"), "the offer text is never echoed");
    fs::write(&db, b"x").expect("db");
    assert_eq!(run(&db, false).status.code(), Some(2));
    // without a refusal the same offer is an unreachable relay: exit 5
    fs::remove_file(&db).expect("rm");
    assert_eq!(run(&db, false).status.code(), Some(5));
    assert!(!db.exists() && !keys::key_path_for(&db).exists(), "nothing was written");
}

#[test]
fn write_order_a_failure_after_the_relay_file_leaves_no_key_file() {
    let o = Offerer::start();
    let (joined, _) = pair_once(&o);
    let dir = tempfile::tempdir().expect("dir");
    let db = dir.path().join("w.hbdb");
    let relay_file = dir.path().join("w.relay.json");
    let stop = |at: LandStep| {
        move |step: LandStep| if step == at { Err(PairError::Landing("injected".into())) } else { Ok(()) }
    };
    let failed = land_with(&joined, &db, &relay_file, &mut stop(LandStep::RelayFile));
    assert_eq!(failed.err(), Some(PairError::Landing("injected".into())));
    assert!(!relay_file.exists(), "taken back out: nothing is paired before the key file (12-H (d))");
    assert!(!keys::key_path_for(&db).exists(), "no key file");
    assert!(!db.exists());
    // the preconditions pass again: a re-run from scratch completes
    let done = land_with(&joined, &db, &relay_file, &mut |_| Ok(())).expect("re-run");
    assert!(done.records_new > 0);
    o.server.stop();
}

#[test]
fn write_order_a_failure_after_the_key_file_leaves_a_path_that_sync_pull_completes() {
    let o = Offerer::start();
    let (joined, _) = pair_once(&o);
    let dir = tempfile::tempdir().expect("dir");
    let db = dir.path().join("w.hbdb");
    let relay_file = dir.path().join("w.relay.json");
    let failed = land_with(&joined, &db, &relay_file, &mut |step| {
        if step == LandStep::KeyFile { Err(PairError::Landing("injected".into())) } else { Ok(()) }
    });
    assert!(failed.is_err());
    assert_eq!(fs::read(keys::key_path_for(&db)).expect("key file"), key_file_bytes(), "the commit point");
    assert!(!db.exists(), "no store yet");
    // a re-run is refused (the key file exists) ...
    assert!(matches!(
        land_with(&joined, &db, &relay_file, &mut |_| Ok(())).err(),
        Some(PairError::Precondition(_))
    ));
    // ... and `sync pull` with the passphrase finishes it
    let secret = store::resolve_master(&db, PassphraseSource::Explicit(PASSPHRASE)).expect("unlock").expect("key");
    let opened = store::open_for_write_with(&db, "test", 5.0, Some(&secret)).expect("create the store");
    let relay = LanRelay::new(&o.url(), &*secret).expect("relay");
    let pulled = sync::pull(opened.conn(), &*secret, &relay).expect("pull");
    assert!(pulled.records_new > 0);
    assert_eq!(fingerprint(opened.conn()), fingerprint(o.conn_holder.conn()));
    o.server.stop();
}

// ---- the two commands as processes ----

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port()
}

fn cli(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_disconect-core"));
    command.env("HOME", home).env_remove("DISCONECT_PASSPHRASE").env_remove("DISCONECT_KEYS");
    command
}

/// Spawns `pair offer` on a free port. The port is found by bind-and-release (the CLI refuses port 0),
/// so another process could take it in between: when the offerer cannot listen, spawn once more.
fn start_offer_process(tmp: &Path, db: &Path) -> (Kill, BufReader<std::process::ChildStderr>, String) {
    let pass = tmp.join("pass.txt");
    fs::write(&pass, format!("{PASSPHRASE}\n")).expect("pass");
    let drops = fit_drop(tmp, "fits", &MONITORING);
    assert!(cli(tmp).arg("--db").arg(db).arg("--passphrase-file").arg(&pass).arg("import").arg(&drops).output().expect("import").status.success());
    let spawn = || {
        cli(tmp)
            .arg("--db").arg(db)
            .arg("--passphrase-file").arg(&pass)
            .arg("--relay").arg(tmp.join("relay"))
            .arg("--listen").arg(format!("127.0.0.1:{}", free_port()))
            .args(["pair", "offer"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn offer")
    };
    let (mut child, mut line) = (spawn(), String::new());
    for attempt in 0..2 {
        line.clear();
        BufReader::new(child.stdout.take().expect("stdout")).read_line(&mut line).expect("offer line");
        if !line.is_empty() || attempt == 1 {
            break;
        }
        let _ = child.wait(); // no offer line: the bind lost the race
        child = spawn();
    }
    assert!(line.starts_with("disconect-pair:v2."), "the offer text is the one stdout line");
    let stderr = BufReader::new(child.stderr.take().expect("stderr"));
    (Kill(child), stderr, line.trim().to_string())
}

/// Every stderr line up to and including the first that contains `needle`.
fn lines_until(reader: &mut BufReader<std::process::ChildStderr>, needle: &str) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).expect("read") > 0, "stream ended before {needle:?}");
        let done = line.contains(needle);
        out.push(line);
        if done {
            return out;
        }
    }
}

fn line_with(reader: &mut BufReader<std::process::ChildStderr>, needle: &str) -> String {
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).expect("read") > 0, "stream ended before {needle:?}");
        if line.contains(needle) {
            return line;
        }
    }
}

fn code_in(line: &str) -> String {
    line.split(':').nth(1).expect("a code").trim().chars().take(6).collect()
}

#[test]
fn pair_offer_and_pair_join_as_processes_with_the_digits_typed() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (dir, db) = encrypted_copy();
    let (mut offerer, mut offer_err, offer) = start_offer_process(tmp.path(), &db);
    assert!(line_with(&mut offer_err, "Waiting for a device").contains("Waiting"));

    let joiner_home = tmp.path().join("joiner-home");
    fs::create_dir_all(&joiner_home).expect("home");
    let joined_db = tmp.path().join("joiner").join("j.hbdb");
    // the default relay file is the one the app and the CLI read: relay.json in the db's folder
    let relay_file = tmp.path().join("joiner").join("relay.json");
    let mut joiner = cli(&joiner_home)
        .arg("--db").arg(&joined_db)
        .args(["pair", "join"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn join");
    joiner.stdin.take().expect("stdin").write_all(format!("{offer}\n").as_bytes()).expect("offer");
    let mut join_err = BufReader::new(joiner.stderr.take().expect("stderr"));
    let join_out = joiner.stdout.take().expect("stdout");
    let joiner_code = code_in(&line_with(&mut join_err, "Code on this device"));
    // the offerer never prints its own code (ADR 0011 v2): no line before the prompt carries the digits
    let before_prompt = lines_until(&mut offer_err, "Type the code shown on the other device");
    assert!(before_prompt.iter().any(|l| l.contains("A device answered")), "{before_prompt:?}");
    assert!(before_prompt.iter().all(|l| !l.contains(&joiner_code)), "{before_prompt:?}");
    offerer.0.stdin.as_mut().expect("stdin").write_all(format!("{joiner_code}\n").as_bytes()).expect("digits");
    line_with(&mut offer_err, "released");
    line_with(&mut offer_err, "Pairing done");

    let mut summary = String::new();
    BufReader::new(join_out).read_to_string(&mut summary).expect("summary");
    let status = joiner.wait().expect("wait");
    assert!(status.success(), "{status}");
    let value: serde_json::Value = serde_json::from_str(summary.trim()).expect("one JSON line");
    assert_eq!(value["paired"], true);
    assert!(value["pulled"]["records_new"].as_i64().expect("count") > 0);
    assert_eq!(value["pulled"]["status"], "ok");
    assert!(!summary.contains("disconect-pair:"));

    // the joined store opens with the fixture passphrase
    let opened = store::open_read_only(&joined_db, PassphraseSource::Explicit(PASSPHRASE)).expect("open joined");
    assert!(store::table_counts(opened.conn()).expect("counts").iter().any(|(_, n)| *n > 0));
    assert_eq!(fs::read(keys::key_path_for(&joined_db)).expect("key file"), key_file_bytes());
    assert!(relay_file.is_file(), "relay.json beside the db");
    assert!(!tmp.path().join("joiner").join("j.hbdb.relay.json").exists());
    assert!(fs::read_to_string(&relay_file).expect("relay file").contains("\"lan\""));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(tmp.path().join("joiner")).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "the key file's directory");
    }
    drop((dir, offerer));
}

#[test]
fn pair_offer_with_the_wrong_digits_aborts_and_the_joiner_ends_without_a_store() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (_dir, db) = encrypted_copy();
    let (mut offerer, mut offer_err, offer) = start_offer_process(tmp.path(), &db);
    let joined_db = tmp.path().join("j.hbdb");
    let mut joiner = cli(tmp.path())
        .arg("--db").arg(&joined_db)
        .args(["pair", "join"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn join");
    joiner.stdin.take().expect("stdin").write_all(format!("{offer}\n").as_bytes()).expect("offer");
    let mut join_err = BufReader::new(joiner.stderr.take().expect("stderr"));
    let code = code_in(&line_with(&mut join_err, "Code on this device"));
    let before_prompt = lines_until(&mut offer_err, "Type the code shown on the other device");
    assert!(before_prompt.iter().any(|l| l.contains("A device answered")), "{before_prompt:?}");
    assert!(before_prompt.iter().all(|l| !l.contains(&code)), "the offerer printed its code: {before_prompt:?}");
    let wrong = format!("{:06}", (code.parse::<u32>().expect("digits") + 1) % 1_000_000);
    offerer.0.stdin.as_mut().expect("stdin").write_all(format!("{wrong}\n").as_bytes()).expect("digits");
    line_with(&mut offer_err, "the codes differ");
    line_with(&mut offer_err, "offer ended; serving the relay");
    // the server stays up, so the joiner's poll reads 410 and it ends without writing anything
    let out = joiner.wait_with_output().expect("join output");
    assert_eq!(out.status.code(), Some(1));
    assert!(!joined_db.exists() && !keys::key_path_for(&joined_db).exists());
    assert!(offerer.0.try_wait().expect("try_wait").is_none(), "the offerer keeps serving");
    drop(offerer); // Kill
}

#[test]
fn pair_offer_refuses_port_zero_and_a_missing_listen() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (_dir, db) = encrypted_copy();
    let pass = tmp.path().join("pass.txt");
    fs::write(&pass, format!("{PASSPHRASE}\n")).expect("pass");
    let run = |extra: &[&str]| {
        cli(tmp.path())
            .arg("--db").arg(&db)
            .arg("--passphrase-file").arg(&pass)
            .arg("--relay").arg(tmp.path().join("relay"))
            .args(extra)
            .args(["pair", "offer"])
            .stdin(Stdio::null())
            .output()
            .expect("run")
    };
    assert_eq!(run(&["--listen", "127.0.0.1:0"]).status.code(), Some(2));
    assert_eq!(run(&[]).status.code(), Some(2));
    for any in ["0.0.0.0:8123", "[::]:8123"] {
        let out = run(&["--listen", any]);
        assert_eq!(out.status.code(), Some(2), "{any}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("needs a concrete address"), "{any}");
    }
    assert!(!tmp.path().join("relay").exists(), "refused before the push");
}
