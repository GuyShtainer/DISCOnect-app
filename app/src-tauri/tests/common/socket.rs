// SPDX-License-Identifier: AGPL-3.0-or-later
//! A loopback listener that answers scripted chat-completions bodies and records what arrived on the wire
//! (the pattern of `tests/coach_egress.rs`, with the answer chosen per request from a [`Step`] list). Binds
//! `127.0.0.1` only.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::fake_provider::{response_body, Step};

/// One request as it arrived: the request line, the headers in order (name, value) and the body.
#[derive(Debug, Clone)]
pub struct Wire {
    pub request_line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Wire {
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
    }

    /// The lowercase header names, sorted.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.headers.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
        names.sort();
        names
    }
}

pub struct Server {
    pub port: u16,
    accepts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<Wire>>>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    /// Answer the Nth connection with the Nth step (an error status step answers that status with no body).
    pub fn start(steps: Vec<Step>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (a, s, w) = (accepts.clone(), stop.clone(), seen.clone());
        let thread = std::thread::spawn(move || {
            let mut steps = std::collections::VecDeque::from(steps);
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let index = a.fetch_add(1, Ordering::SeqCst);
                        let wire = read_request(&stream);
                        let request_len = wire.as_ref().map_or(0, |w| w.body.len());
                        if let Some(wire) = wire {
                            w.lock().expect("lock").push(wire);
                        }
                        let response = match steps.pop_front() {
                            Some(Step::Status(code)) => format!("HTTP/1.1 {code} Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes(),
                            Some(step) => {
                                let body = response_body(&step, request_len, index).unwrap_or_default();
                                let mut out = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                )
                                .into_bytes();
                                out.extend_from_slice(&body);
                                out
                            }
                            None => b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                        };
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

    /// Stop and return (connections accepted, requests as they arrived).
    pub fn finish(mut self) -> (usize, Vec<Wire>) {
        std::thread::sleep(Duration::from_millis(200));
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
