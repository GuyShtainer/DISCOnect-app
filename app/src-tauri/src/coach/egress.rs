// SPDX-License-Identifier: AGPL-3.0-or-later
//! The product's only internet egress point (Bet 15, ADR 0010, pitch slice 4). Every byte that leaves the
//! machine for a model provider goes through [`Egress::send`]; `tests/egress_guards.rs` fails the build if
//! any other source file names a network type, and the dependency guard allows `ureq` (and so `rustls`)
//! in this crate only for this file.
//!
//! **Scheme rules are decided on the host, never on DNS.** `https://` is allowed for any host. `http://` is
//! allowed only when the URL's host is a *literal* IP that is loopback (127.0.0.0/8, ::1) or private
//! (10/8, 172.16/12, 192.168/16, fc00::/7, fe80::/10), or the exact name `localhost` (which [`Real`] connects
//! to as `127.0.0.1`, keeping `Host: localhost`). A DNS name over plain `http://` is refused
//! ([`EgressError::PlainHttpNeedsLocalIp`]): a name can resolve to a public address a moment after it
//! resolved to a private one (DNS rebinding), and refusing the name closes that without pinning an address.
//! Userinfo in a URL is refused; every other scheme is refused. WHATWG parsing (the `url` crate) has already
//! turned `127.1` or `2130706433` into a dotted quad, so those cannot dodge the host test.
//!
//! **What the client does:** no proxy (`HTTP_PROXY` and friends are never read), no redirects (a 3xx is an
//! error status, never followed), 4xx/5xx are answers not transport errors, TLS through `rustls` with the
//! operating system's trust store, a 10 s connect and a 120 s global timeout, a 1 MiB request body cap and a
//! 4 MiB response body cap. The request carries `Content-Type`, `Authorization: Bearer <key>` (only when a key
//! is given) and ureq's own `Host`, `User-Agent` (`disconect-coach/<version>`), `Accept` and nothing else.
//!
//! **Errors are a closed enum** ([`EgressError`]) with fixed messages: never the provider's body, the URL,
//! the host, the key, or ureq's error text. A non-2xx answer is [`EgressError::Status`] with the number only.

use std::collections::VecDeque;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

use url::{Host, Url};
use zeroize::Zeroizing;

use super::settings::{Mode, Settings};

/// The request body cap (the validated, byte-capped coach request is far below it).
pub const MAX_REQUEST_BODY: usize = 1024 * 1024;
/// The response body cap.
pub const MAX_RESPONSE_BODY: usize = 4 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(120);
/// The URL length cap (a base URL is a line, not a document).
const MAX_URL_LEN: usize = 2048;

/// Why a send did not happen or did not succeed. Closed: every message is fixed text (see the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressError {
    Off,
    BadUrl,
    PlainHttpNeedsLocalIp,
    UserinfoRefused,
    Unreachable,
    Timeout,
    Tls,
    Status(u16),
    BodyTooLarge,
    ResponseTooLarge,
    Io,
}

impl EgressError {
    /// A fixed sentence, safe to show and to store. Carries no URL, host, key or provider text.
    pub fn message(&self) -> &'static str {
        match self {
            EgressError::Off => "the coach is switched off",
            EgressError::BadUrl => "the endpoint address is not a usable web address",
            EgressError::PlainHttpNeedsLocalIp => {
                "plain http is only allowed for localhost or a local network address given as numbers"
            }
            EgressError::UserinfoRefused => "the endpoint address must not contain a user name or password",
            EgressError::Unreachable => "the endpoint could not be reached",
            EgressError::Timeout => "the endpoint did not answer in time",
            EgressError::Tls => "the secure connection to the endpoint failed",
            EgressError::Status(_) => "the endpoint answered with an error status",
            EgressError::BodyTooLarge => "the request is larger than the coach may send",
            EgressError::ResponseTooLarge => "the endpoint's answer is larger than the coach accepts",
            EgressError::Io => "the connection to the endpoint failed",
        }
    }

    /// A stable machine-readable name for the UI.
    pub fn code(&self) -> &'static str {
        match self {
            EgressError::Off => "off",
            EgressError::BadUrl => "bad_url",
            EgressError::PlainHttpNeedsLocalIp => "plain_http_needs_local_ip",
            EgressError::UserinfoRefused => "userinfo_refused",
            EgressError::Unreachable => "unreachable",
            EgressError::Timeout => "timeout",
            EgressError::Tls => "tls",
            EgressError::Status(_) => "status",
            EgressError::BodyTooLarge => "body_too_large",
            EgressError::ResponseTooLarge => "response_too_large",
            EgressError::Io => "io",
        }
    }

    /// The HTTP status of [`EgressError::Status`], the only number an error carries.
    pub fn status(&self) -> Option<u16> {
        match self {
            EgressError::Status(code) => Some(*code),
            _ => None,
        }
    }
}

impl From<ureq::Error> for EgressError {
    /// Maps by variant only: the inner error's text is dropped on the floor on purpose (it can hold the
    /// URL, the host or a certificate name).
    fn from(error: ureq::Error) -> Self {
        use std::io::ErrorKind;
        match error {
            ureq::Error::StatusCode(code) => EgressError::Status(code),
            ureq::Error::Timeout(_) => EgressError::Timeout,
            ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => EgressError::Unreachable,
            ureq::Error::Io(io) => match io.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => EgressError::Timeout,
                ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::NotConnected
                | ErrorKind::AddrNotAvailable
                | ErrorKind::HostUnreachable
                | ErrorKind::NetworkUnreachable
                | ErrorKind::NetworkDown => EgressError::Unreachable,
                _ => EgressError::Io,
            },
            ureq::Error::Tls(_) | ureq::Error::Rustls(_) | ureq::Error::Pem(_) => EgressError::Tls,
            ureq::Error::BodyExceedsLimit(_) => EgressError::ResponseTooLarge,
            ureq::Error::Http(_) | ureq::Error::BadUri(_) | ureq::Error::InvalidProxyUrl => EgressError::BadUrl,
            _ => EgressError::Io,
        }
    }
}

// ---- the URL rules ------------------------------------------------------------------------------

fn ipv4_allowed_plain(ip: Ipv4Addr) -> bool {
    // loopback 127/8, private 10/8, 172.16/12, 192.168/16 (link-local 169.254/16 is NOT allowed: that is
    // where cloud metadata services live)
    ip.is_loopback() || ip.is_private()
}

fn ipv6_allowed_plain(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return ipv4_allowed_plain(mapped);
    }
    let first = ip.segments()[0];
    ip.is_loopback() || (first & 0xfe00) == 0xfc00 /* fc00::/7 */ || (first & 0xffc0) == 0xfe80 /* fe80::/10 */
}

/// Is this host one a plain `http://` request may name? Decided on the host text alone.
fn host_allowed_plain(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(ip) => ipv4_allowed_plain(*ip),
        Host::Ipv6(ip) => ipv6_allowed_plain(*ip),
        Host::Domain(name) => *name == "localhost",
    }
}

/// The rules of the module doc, as a pure function: `Ok(())` when a request to `url` may be made.
pub fn check_url(url: &Url) -> Result<(), EgressError> {
    if url.as_str().len() > MAX_URL_LEN {
        return Err(EgressError::BadUrl);
    }
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(EgressError::BadUrl);
    }
    let Some(host) = url.host() else {
        return Err(EgressError::BadUrl);
    };
    if !url.username().is_empty() || url.password().is_some() {
        return Err(EgressError::UserinfoRefused);
    }
    if scheme == "http" && !host_allowed_plain(&host) {
        return Err(EgressError::PlainHttpNeedsLocalIp);
    }
    Ok(())
}

/// A validated provider address: the base every request URL must share an origin with.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    base: Url,
}

impl Endpoint {
    /// Parse and validate. Never carries the parser's text.
    pub fn parse(text: &str) -> Result<Endpoint, EgressError> {
        let text = text.trim();
        if text.is_empty() || text.len() > MAX_URL_LEN {
            return Err(EgressError::BadUrl);
        }
        let base = Url::parse(text).map_err(|_| EgressError::BadUrl)?;
        check_url(&base)?;
        Ok(Endpoint { base })
    }

    /// The endpoint the settings name: `Mode::Off` is [`EgressError::Off`], so a `Real` is never built then.
    pub fn from_settings(settings: &Settings) -> Result<Endpoint, EgressError> {
        match settings.mode {
            Mode::Off => Err(EgressError::Off),
            Mode::Local | Mode::Cloud => Endpoint::parse(&settings.base_url),
        }
    }

    /// The base URL plus `path` (`chat/completions`), keeping the base's own path (`/v1`).
    pub fn join(&self, path: &str) -> Result<Url, EgressError> {
        let mut base = self.base.clone();
        base.set_query(None);
        base.set_fragment(None);
        if !base.path().ends_with('/') {
            let with_slash = format!("{}/", base.path());
            base.set_path(&with_slash);
        }
        let url = base.join(path.trim_start_matches('/')).map_err(|_| EgressError::BadUrl)?;
        if !same_origin(&url, &self.base) {
            return Err(EgressError::BadUrl);
        }
        Ok(url)
    }

    /// Host text for the UI's "sending to <host>" indicator.
    pub fn host(&self) -> String {
        self.base.host_str().unwrap_or_default().to_string()
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Endpoint(<address withheld>)")
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && a.host() == b.host() && a.port_or_known_default() == b.port_or_known_default()
}

// ---- the choke point ----------------------------------------------------------------------------

/// One POST to the provider. The bearer is the user's key (zeroised on drop); `Debug` never shows it.
pub struct Outbound {
    pub url: Url,
    pub bearer: Option<Zeroizing<String>>,
    pub body: Vec<u8>,
}

impl fmt::Debug for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outbound")
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// A 2xx answer. (Anything else is [`EgressError::Status`], and its body is dropped.)
pub struct Inbound {
    pub status: u16,
    pub body: Vec<u8>,
}

impl fmt::Debug for Inbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inbound").field("status", &self.status).field("body_bytes", &self.body.len()).finish()
    }
}

/// The only way bytes leave: [`Real`] on the network, [`Fake`] in tests.
pub trait Egress: Send + Sync {
    fn send(&self, out: Outbound) -> Result<Inbound, EgressError>;
}

fn check_outbound(out: &Outbound) -> Result<(), EgressError> {
    check_url(&out.url)?;
    if out.body.len() > MAX_REQUEST_BODY {
        return Err(EgressError::BodyTooLarge);
    }
    Ok(())
}

/// The network implementation. Built from an [`Endpoint`]; a request to any other origin is refused.
pub struct Real {
    endpoint: Endpoint,
    agent: ureq::Agent,
}

impl Real {
    pub fn new(endpoint: Endpoint) -> Real {
        use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
        // The proxy is None on purpose (ureq would otherwise read HTTP_PROXY / ALL_PROXY from the
        // environment), redirects are never followed and a 3xx is an answer, 4xx/5xx are answers too.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(GLOBAL_TIMEOUT))
            .user_agent(concat!("disconect-coach/", env!("CARGO_PKG_VERSION")))
            .tls_config(TlsConfig::builder().provider(TlsProvider::Rustls).root_certs(RootCerts::PlatformVerifier).build())
            .build()
            .into();
        Real { endpoint, agent }
    }

    /// The `Real` for these settings, or why there is none (`Off` is never built).
    pub fn from_settings(settings: &Settings) -> Result<Real, EgressError> {
        Endpoint::from_settings(settings).map(Real::new)
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

impl Egress for Real {
    fn send(&self, out: Outbound) -> Result<Inbound, EgressError> {
        check_outbound(&out)?;
        if !same_origin(&out.url, &self.endpoint.base) {
            return Err(EgressError::BadUrl);
        }
        // `localhost` is connected to as 127.0.0.1 (no resolver involved), with `Host: localhost` kept.
        let mut url = out.url.clone();
        let mut host_header = None;
        if url.scheme() == "http" && url.host_str() == Some("localhost") {
            let host = match url.port() {
                Some(port) => format!("localhost:{port}"),
                None => "localhost".to_string(),
            };
            url.set_ip_host(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)).map_err(|()| EgressError::BadUrl)?;
            host_header = Some(host);
        }
        let mut request = self.agent.post(url.as_str()).header("Content-Type", "application/json");
        if let Some(host) = &host_header {
            request = request.header("Host", host.as_str());
        }
        let authorization = out.bearer.as_ref().map(|key| Zeroizing::new(format!("Bearer {}", key.as_str())));
        if let Some(value) = &authorization {
            request = request.header("Authorization", value.as_str());
        }
        let mut response = request.send(&out.body[..])?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(EgressError::Status(status));
        }
        let body = response.body_mut().with_config().limit(MAX_RESPONSE_BODY as u64).read_to_vec()?;
        Ok(Inbound { status, body })
    }
}

// ---- the test double ----------------------------------------------------------------------------

/// What [`Fake`] remembers of one send: never the key, only that there was one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub url: String,
    /// Lowercase names of the headers the real client would set from this request.
    pub header_names: Vec<&'static str>,
    pub body: Vec<u8>,
}

/// A deterministic stand-in with no network code: records each send, answers from a queue.
#[derive(Default)]
pub struct Fake {
    pub sent: Mutex<Vec<Sent>>,
    responses: Mutex<VecDeque<Result<Inbound, EgressError>>>,
}

impl Fake {
    pub fn new() -> Fake {
        Fake::default()
    }

    /// Queue the answer to the next send (a send with an empty queue is `Unreachable`).
    pub fn push(&self, response: Result<Inbound, EgressError>) {
        if let Ok(mut queue) = self.responses.lock() {
            queue.push_back(response);
        }
    }

    /// How many sends were made (refused ones included: they reached the choke point).
    pub fn count(&self) -> usize {
        self.sent.lock().map(|sent| sent.len()).unwrap_or(0)
    }
}

impl Egress for Fake {
    fn send(&self, out: Outbound) -> Result<Inbound, EgressError> {
        let mut header_names = vec!["content-type"];
        if out.bearer.is_some() {
            header_names.push("authorization");
        }
        if let Ok(mut sent) = self.sent.lock() {
            sent.push(Sent { url: out.url.to_string(), header_names, body: out.body.clone() });
        }
        check_outbound(&out)?;
        self.responses.lock().ok().and_then(|mut queue| queue.pop_front()).unwrap_or(Err(EgressError::Unreachable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(text: &str) -> Result<(), EgressError> {
        Endpoint::parse(text).map(|_| ())
    }

    #[test]
    fn the_scheme_and_host_rules() {
        let cases: [(&str, Result<(), EgressError>); 26] = [
            ("https://api.example/v1", Ok(())),
            ("https://localhost:8443/v1", Ok(())),
            ("http://127.0.0.1:11434/v1", Ok(())),
            ("http://127.8.9.10", Ok(())),
            ("http://localhost:11434", Ok(())),
            ("http://[::1]:8080", Ok(())),
            ("http://10.0.0.5", Ok(())),
            ("http://192.168.1.2:1234", Ok(())),
            ("http://172.16.0.1", Ok(())),
            ("http://172.31.255.255", Ok(())),
            ("http://[fd12:3456::1]:80", Ok(())),
            ("http://[fe80::1]", Ok(())),
            ("http://[::ffff:192.168.1.2]", Ok(())),
            ("http://127.1", Ok(())), // WHATWG: 127.0.0.1
            ("http://172.32.0.1", Err(EgressError::PlainHttpNeedsLocalIp)),
            ("http://169.254.169.254", Err(EgressError::PlainHttpNeedsLocalIp)),
            ("http://ollama.local", Err(EgressError::PlainHttpNeedsLocalIp)),
            ("http://example.com", Err(EgressError::PlainHttpNeedsLocalIp)),
            ("http://localhost.", Err(EgressError::PlainHttpNeedsLocalIp)),
            ("http://[2001:db8::1]", Err(EgressError::PlainHttpNeedsLocalIp)),
            ("https://user:pw@api.example", Err(EgressError::UserinfoRefused)),
            ("http://user@127.0.0.1", Err(EgressError::UserinfoRefused)),
            ("ftp://x", Err(EgressError::BadUrl)),
            ("file:///x", Err(EgressError::BadUrl)),
            ("not a url", Err(EgressError::BadUrl)),
            ("", Err(EgressError::BadUrl)),
        ];
        for (text, want) in cases {
            assert_eq!(verdict(text), want, "{text}");
        }
    }

    #[test]
    fn join_keeps_the_base_path_and_never_leaves_the_origin() {
        let e = Endpoint::parse("https://api.example/v1").unwrap();
        assert_eq!(e.join("chat/completions").unwrap().as_str(), "https://api.example/v1/chat/completions");
        let e = Endpoint::parse("http://127.0.0.1:11434/v1/?x=1#f").unwrap();
        assert_eq!(e.join("/chat/completions").unwrap().as_str(), "http://127.0.0.1:11434/v1/chat/completions");
        // leading slashes are stripped, so a protocol-relative path stays a path under the base; an absolute
        // URL that names another origin is refused
        assert_eq!(e.join("//evil.example/x").unwrap().as_str(), "http://127.0.0.1:11434/v1/evil.example/x");
        assert_eq!(e.join("http://evil.example/x").unwrap_err(), EgressError::BadUrl);
    }

    #[test]
    fn every_error_message_is_data_free() {
        let secrets = ["api.example", "sk-test-0123456789", "https://", "127.0.0.1", "ureq", "rustls", "Bearer"];
        let all = [
            EgressError::Off,
            EgressError::BadUrl,
            EgressError::PlainHttpNeedsLocalIp,
            EgressError::UserinfoRefused,
            EgressError::Unreachable,
            EgressError::Timeout,
            EgressError::Tls,
            EgressError::Status(401),
            EgressError::Status(502),
            EgressError::BodyTooLarge,
            EgressError::ResponseTooLarge,
            EgressError::Io,
        ];
        for error in all {
            for needle in secrets {
                assert!(!error.message().contains(needle), "{}", error.message());
                assert!(!error.code().contains(needle));
            }
            assert!(!error.message().chars().any(|c| c.is_ascii_digit()), "no number in {}", error.message());
        }
        assert_eq!(EgressError::Status(401).status(), Some(401));
        assert_eq!(EgressError::Io.status(), None);
    }

    #[test]
    fn ureq_errors_map_by_variant_and_carry_no_text() {
        use std::io::{Error as IoError, ErrorKind};
        let leaky = "https://api.example/v1?key=sk-test-0123456789";
        let cases = [
            (ureq::Error::StatusCode(429), EgressError::Status(429)),
            (ureq::Error::Timeout(ureq::Timeout::Global), EgressError::Timeout),
            (ureq::Error::HostNotFound, EgressError::Unreachable),
            (ureq::Error::ConnectionFailed, EgressError::Unreachable),
            (ureq::Error::Io(IoError::new(ErrorKind::ConnectionRefused, leaky)), EgressError::Unreachable),
            (ureq::Error::Io(IoError::new(ErrorKind::TimedOut, leaky)), EgressError::Timeout),
            (ureq::Error::Io(IoError::new(ErrorKind::InvalidData, leaky)), EgressError::Io),
            (ureq::Error::Tls("certificate for api.example is not trusted"), EgressError::Tls),
            (ureq::Error::BadUri(leaky.to_string()), EgressError::BadUrl),
            (ureq::Error::BodyExceedsLimit(1), EgressError::ResponseTooLarge),
            (ureq::Error::TooManyRedirects, EgressError::Io),
        ];
        for (error, want) in cases {
            let got = EgressError::from(error);
            assert_eq!(got, want);
            assert!(!got.message().contains("sk-test") && !got.message().contains("api.example"));
        }
    }

    fn settings(mode: Mode, url: &str) -> Settings {
        Settings { mode, base_url: url.to_string(), ..Settings::default() }
    }

    #[test]
    fn off_mode_builds_no_egress() {
        assert_eq!(Endpoint::from_settings(&settings(Mode::Off, "https://api.example/v1")).unwrap_err(), EgressError::Off);
        assert_eq!(Real::from_settings(&settings(Mode::Off, "https://api.example/v1")).err(), Some(EgressError::Off));
        assert!(Real::from_settings(&settings(Mode::Cloud, "https://api.example/v1")).is_ok());
        assert!(Real::from_settings(&settings(Mode::Local, "http://127.0.0.1:11434/v1")).is_ok());
        assert_eq!(Real::from_settings(&settings(Mode::Cloud, "http://example.com")).err(), Some(EgressError::PlainHttpNeedsLocalIp));
    }

    fn outbound(url: &str, body: Vec<u8>, key: Option<&str>) -> Outbound {
        Outbound { url: Url::parse(url).unwrap(), bearer: key.map(|k| Zeroizing::new(k.to_string())), body }
    }

    #[test]
    fn the_fake_counts_records_and_answers_from_its_queue() {
        let fake = Fake::new();
        assert_eq!(fake.count(), 0);
        fake.push(Ok(Inbound { status: 200, body: b"{}".to_vec() }));
        fake.push(Err(EgressError::Status(500)));
        let first = fake.send(outbound("https://api.example/v1/x", b"abc".to_vec(), Some("sk-test"))).unwrap();
        assert_eq!((first.status, first.body.as_slice()), (200, &b"{}"[..]));
        assert_eq!(fake.send(outbound("https://api.example/v1/x", vec![], None)).unwrap_err(), EgressError::Status(500));
        assert_eq!(fake.send(outbound("https://api.example/v1/x", vec![], None)).unwrap_err(), EgressError::Unreachable);
        assert_eq!(fake.count(), 3);
        let sent = fake.sent.lock().unwrap();
        assert_eq!(sent[0].header_names, vec!["content-type", "authorization"]);
        assert_eq!(sent[1].header_names, vec!["content-type"]);
        assert_eq!(sent[0].body, b"abc");
    }

    #[test]
    fn the_double_and_the_real_client_apply_the_same_url_and_size_rules() {
        let fake = Fake::new();
        assert_eq!(fake.send(outbound("http://example.com/x", vec![], None)).unwrap_err(), EgressError::PlainHttpNeedsLocalIp);
        let big = vec![0u8; MAX_REQUEST_BODY + 1];
        assert_eq!(fake.send(outbound("https://api.example/x", big.clone(), None)).unwrap_err(), EgressError::BodyTooLarge);
        let real = Real::new(Endpoint::parse("https://api.example/v1").unwrap());
        assert_eq!(real.send(outbound("https://api.example/x", big, None)).unwrap_err(), EgressError::BodyTooLarge);
        // another origin than the endpoint's is refused before anything is connected
        assert_eq!(real.send(outbound("https://other.example/x", vec![], None)).unwrap_err(), EgressError::BadUrl);
        assert_eq!(real.send(outbound("http://example.com/x", vec![], None)).unwrap_err(), EgressError::PlainHttpNeedsLocalIp);
    }

    #[test]
    fn debug_output_withholds_the_key_the_body_and_the_address() {
        let out = outbound("https://api.example/v1", b"secret body".to_vec(), Some("sk-test-0123456789"));
        let shown = format!("{out:?}");
        assert!(!shown.contains("sk-test") && !shown.contains("secret body") && !shown.contains("api.example"), "{shown}");
        let endpoint = format!("{:?}", Endpoint::parse("https://api.example/v1").unwrap());
        assert!(!endpoint.contains("api.example"));
    }
}
