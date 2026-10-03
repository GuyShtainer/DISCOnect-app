// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 15 slice 4: the real egress on a real socket. Every test binds `127.0.0.1` only, accepts on a thread,
//! and checks what actually arrived on the wire: method, path, the exact header set, the body bytes, that no
//! proxy variable and no redirect moved the request, and that errors carry no provider text.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use disconect_app_lib::coach::egress::{Egress, EgressError, Endpoint, Outbound, Real, MAX_RESPONSE_BODY};
use url::Url;
use zeroize::Zeroizing;

const TEST_KEY: &str = "sk-test-wire-0123456789";

/// One request as it arrived: head lines in order (name, value) and the body.
#[derive(Debug, Clone)]
struct Wire {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Wire {
    fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
    }
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.headers.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
        names.sort();
        names
    }
}

struct Server {
    port: u16,
    accepts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<Wire>>>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    /// Answer every connection with `response` (raw bytes). Binds 127.0.0.1 only.
    fn start(response: Vec<u8>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (a, s, w) = (accepts.clone(), stop.clone(), seen.clone());
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        a.fetch_add(1, Ordering::SeqCst);
                        if let Some(wire) = read_request(&stream) {
                            w.lock().expect("lock").push(wire);
                        }
                        let mut stream = stream;
                        let _ = stream.write_all(&response);
                        let _ = stream.flush();
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Server { port, accepts, stop, seen, thread: Some(thread) }
    }

    fn url(&self, path: &str) -> Url {
        Url::parse(&format!("http://127.0.0.1:{}{path}", self.port)).expect("url")
    }

    fn finish(mut self) -> (usize, Vec<Wire>) {
        std::thread::sleep(Duration::from_millis(300)); // a second (redirected) connection would arrive by now
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        (self.accepts.load(Ordering::SeqCst), self.seen.lock().expect("lock").clone())
    }
}

fn read_request(stream: &TcpStream) -> Option<Wire> {
    let mut stream = stream.try_clone().ok()?;
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(n, v)| (n.trim().to_string(), v.trim().to_string())))
        .collect();
    let want = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < want {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Wire { request_line, headers, body })
}

fn ok_json(body: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        .into_bytes()
}

/// A proxy variable that points at a closed port: any client that honours it cannot reach the listener.
fn poison_proxy_env() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        for name in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy"] {
            std::env::set_var(name, "http://127.0.0.1:9");
        }
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
    });
}

fn real_for(url: &Url) -> Real {
    poison_proxy_env();
    let base = format!("{}://{}:{}/v1", url.scheme(), url.host_str().expect("host"), url.port().expect("port"));
    Real::new(Endpoint::parse(&base).expect("endpoint"))
}

fn post(real: &Real, url: Url, key: Option<&str>, body: &[u8]) -> Result<disconect_app_lib::coach::egress::Inbound, EgressError> {
    real.send(Outbound { url, bearer: key.map(|k| Zeroizing::new(k.to_string())), body: body.to_vec() })
}

#[test]
fn the_request_on_the_wire_is_the_body_a_bearer_and_nothing_else() {
    let server = Server::start(ok_json(r#"{"ok":true}"#));
    let url = server.url("/v1/chat/completions");
    let real = real_for(&url);
    let body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
    // HTTP_PROXY points at a closed port: arriving here at all proves the proxy variables are not read
    let answer = post(&real, url, Some(TEST_KEY), body).expect("the listener answers");
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, br#"{"ok":true}"#);
    let (accepts, seen) = server.finish();
    assert_eq!(accepts, 1);
    assert_eq!(seen.len(), 1);
    let wire = &seen[0];
    assert_eq!(wire.request_line, "POST /v1/chat/completions HTTP/1.1");
    assert_eq!(wire.header_values("authorization"), vec![format!("Bearer {TEST_KEY}").as_str()]);
    assert_eq!(wire.header_values("content-type"), vec!["application/json"]);
    assert_eq!(wire.header_values("content-length"), vec![body.len().to_string().as_str()]);
    assert_eq!(wire.body, body);
    assert_eq!(wire.header_values("user-agent"), vec![concat!("disconect-coach/", env!("CARGO_PKG_VERSION"))]);
    // the exact set: what ureq adds on its own (Host, User-Agent, Accept) plus ours (Content-Type, Content-Length,
    // Authorization). No cookie, no referer, no accept-encoding, no custom header.
    assert_eq!(
        wire.names(),
        vec!["accept", "authorization", "content-length", "content-type", "host", "user-agent"],
        "{:?}",
        wire.headers
    );
    assert_eq!(wire.header_values("accept"), vec!["*/*"]);
    assert_eq!(wire.header_values("host"), vec![format!("127.0.0.1:{}", server_port(&wire.headers)).as_str()]);
}

fn server_port(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("host"))
        .and_then(|(_, v)| v.rsplit_once(':').map(|(_, p)| p.to_string()))
        .unwrap_or_default()
}

#[test]
fn without_a_key_there_is_no_authorization_header_at_all() {
    let server = Server::start(ok_json("{}"));
    let url = server.url("/v1/chat/completions");
    let real = real_for(&url);
    post(&real, url, None, b"{}").expect("answer");
    let (_, seen) = server.finish();
    assert!(seen[0].header_values("authorization").is_empty(), "{:?}", seen[0].headers);
    assert_eq!(seen[0].names(), vec!["accept", "content-length", "content-type", "host", "user-agent"]);
}

#[test]
fn localhost_is_connected_as_127_0_0_1_with_host_localhost_kept() {
    let server = Server::start(ok_json("{}"));
    let port = server.port;
    let url = Url::parse(&format!("http://localhost:{port}/v1/chat/completions")).expect("url");
    let real = real_for(&url);
    post(&real, url, Some(TEST_KEY), b"{}").expect("answer");
    let (accepts, seen) = server.finish();
    assert_eq!(accepts, 1);
    assert_eq!(seen[0].header_values("host"), vec![format!("localhost:{port}").as_str()], "{:?}", seen[0].headers);
    assert_eq!(seen[0].header_values("authorization").len(), 1);
}

#[test]
fn a_redirect_is_an_error_status_and_is_never_followed() {
    let redirect = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let server = Server::start(redirect.as_bytes().to_vec());
    let url = server.url("/v1/chat/completions");
    let real = real_for(&url);
    let error = post(&real, url, Some(TEST_KEY), b"{}").expect_err("a 302 is not an answer");
    assert_eq!(error, EgressError::Status(302));
    let (accepts, seen) = server.finish();
    assert_eq!(accepts, 1, "no second connection");
    assert_eq!(seen.len(), 1);
}

#[test]
fn an_error_status_carries_its_number_and_never_the_providers_text() {
    let text = "invalid api key sk-test-wire-0123456789 for https://api.example";
    let response = format!("HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}", text.len());
    let server = Server::start(response.into_bytes());
    let url = server.url("/v1/chat/completions");
    let real = real_for(&url);
    let error = post(&real, url, Some(TEST_KEY), b"{}").expect_err("401");
    assert_eq!(error, EgressError::Status(401));
    assert_eq!(error.status(), Some(401));
    for shown in [error.message().to_string(), error.code().to_string(), format!("{error:?}")] {
        assert!(!shown.contains("sk-test") && !shown.contains("api.example") && !shown.contains("invalid api key"), "{shown}");
    }
    server.finish();
}

#[test]
fn a_response_over_the_cap_is_refused() {
    let big = "x".repeat(MAX_RESPONSE_BODY + 1);
    let server = Server::start(ok_json(&big));
    let url = server.url("/v1/chat/completions");
    let real = real_for(&url);
    assert_eq!(post(&real, url, None, b"{}").expect_err("too large"), EgressError::ResponseTooLarge);
    server.finish();
}

#[test]
fn nothing_listening_is_unreachable_and_says_nothing_else() {
    // a port that was just free: bind, note it, drop the listener
    let port = TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port();
    let url = Url::parse(&format!("http://127.0.0.1:{port}/v1/chat/completions")).expect("url");
    let real = real_for(&url);
    let started = Instant::now();
    let error = post(&real, url, Some(TEST_KEY), b"{}").expect_err("refused");
    assert_eq!(error, EgressError::Unreachable);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(!error.message().contains(&port.to_string()));
}
