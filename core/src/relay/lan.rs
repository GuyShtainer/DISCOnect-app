// SPDX-License-Identifier: AGPL-3.0-or-later
//! The LAN relay, client side and the token both sides share (Bet 12, slice B; ADR 0005's
//! "self-hosted" adapter: the user's own Mac serves its relay folder over the home network).
//!
//! Bodies are AEAD output already (`bundle.rs`), so the transport is plain HTTP and its only job is
//! to prove that the caller holds the master key: every request carries
//! `X-Disconect-Auth: v1.<unix seconds>.<pre>.<tag>` where `tag = hex HMAC-SHA256(token_key, method LF
//! path LF timestamp LF hex(sha256(body)))` and `pre = hex HMAC-SHA256(token_key, "pre" LF method LF
//! path LF timestamp LF content-length)`: the server checks `pre` before it reads a single body byte,
//! so a peer without the key cannot make it wait for a body (Bet 12 review F1). `token_key = HKDF-SHA256(master, salt = account, info = "disconect/lan/v1/token")`. The
//! server (`lan_server.rs`) never decrypts anything; it derives the same key from the same master.
//!
//! **Response tag (Bet 12-RA).** Every answer from `handle()` except `/v1/health` and `/v1/pair*` carries
//! `X-Disconect-Resp: v1.<server unix seconds>.<rtag>` with `rtag = hex HMAC-SHA256(token_key, "resp" LF
//! METHOD LF target LF <request auth value as the server received it, or empty> LF <seconds> LF status LF
//! hex(sha256(body)))`. The client verifies it, in constant time, before it interprets the status: a
//! fake server (or a network that rewrites answers) cannot make it book a push, trust a list or read a
//! refusal as real. Health and the pairing routes carry none.
//!
//! Wire format and what the server never does: `docs/relay-protocol.md`, "LAN relay".

use std::io::{Error as IoError, ErrorKind};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::bundle::{account_for, hkdf_expand};
use super::folder::{MAX_OBJECT, Relay, RelayError, is_object_name};

/// The request header carrying the token.
pub const AUTH_HEADER: &str = "X-Disconect-Auth";
/// The response header carrying the answer's tag (frozen, docs/kb/24-wire-constants.md).
pub const RESP_HEADER: &str = "X-Disconect-Resp";
/// The route prefix of the object API.
pub const OBJECTS: &str = "/v1/objects";
/// The unauthenticated health route.
pub const HEALTH: &str = "/v1/health";
/// The server rejects a timestamp further than this from its own clock (seconds).
pub const MAX_SKEW_SECS: u64 = 300;
/// The API version in the token (`v1.`) and in the health answer.
pub const API_VERSION: u32 = 1;

/// Frozen from now on (docs/kb/24-wire-constants.md): a new label is a new token key, and every
/// paired device would be refused.
const INFO_TOKEN: &[u8] = b"disconect/lan/v1/token";

/// `HKDF-SHA256(ikm = master, salt = the 64 hex characters of the account as ASCII, info = "disconect/lan/v1/token")`.
pub fn token_key(master: &[u8]) -> Zeroizing<[u8; 32]> {
    hkdf_expand(master, Some(account_for(master).as_bytes()), INFO_TOKEN)
}

fn mac_over(key: &[u8], method: &str, path: &str, timestamp: u64, body: &[u8]) -> Option<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    let digest = hex::encode(Sha256::digest(body));
    mac.update(format!("{method}\n{path}\n{timestamp}\n{digest}").as_bytes());
    Some(mac.finalize().into_bytes().to_vec())
}

/// The MAC behind the pre-tag: `"pre" LF method LF path LF timestamp LF content-length` (decimal;
/// `0` when the request declares no length, as for GET and DELETE).
fn pre_mac(
    key: &[u8],
    method: &str,
    path: &str,
    timestamp: u64,
    content_length: u64,
) -> Option<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(format!("pre\n{method}\n{path}\n{timestamp}\n{content_length}").as_bytes());
    Some(mac)
}

/// The header value for one request. `method` is upper case, `path` the request path without a
/// query (`/v1/objects/<account>/<name>`); the pre-tag covers `body.len()`. `None` only if the key
/// is unusable (it never is: 32 bytes).
pub fn auth_value(
    key: &[u8],
    method: &str,
    path: &str,
    timestamp: u64,
    body: &[u8],
) -> Option<String> {
    auth_value_declaring(key, method, path, timestamp, body.len() as u64, body)
}

/// [`auth_value`] with a `Content-Length` that need not match `body` (a client never does this;
/// tests use it to sign a header for a length the body does not have).
pub fn auth_value_declaring(
    key: &[u8],
    method: &str,
    path: &str,
    timestamp: u64,
    content_length: u64,
    body: &[u8],
) -> Option<String> {
    let tag = mac_over(key, method, path, timestamp, body)?;
    let pre = pre_mac(key, method, path, timestamp, content_length)?
        .finalize()
        .into_bytes();
    Some(format!(
        "v{API_VERSION}.{timestamp}.{}.{}",
        hex::encode(pre),
        hex::encode(tag)
    ))
}

/// Why a header was refused. The server answers 401 with no detail whatever the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    Malformed,
    Stale,
    Mismatch,
}

/// A parsed header: the timestamp, the pre-tag (over the declared length) and the tag (over the body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuth {
    pub timestamp: u64,
    pub pre: Vec<u8>,
    pub tag: Vec<u8>,
}

fn mac_bytes(text: &str) -> Result<Vec<u8>, AuthError> {
    match hex::decode(text) {
        Ok(bytes) if bytes.len() == 32 => Ok(bytes),
        _ => Err(AuthError::Malformed),
    }
}

/// A header's parts, checked for shape and for clock skew only (cheap: no key, no body needed).
pub fn parse_auth(header: &str, now: u64) -> Result<ParsedAuth, AuthError> {
    let mut parts = header.split('.');
    let (Some(version), Some(stamp), Some(pre), Some(tag), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(AuthError::Malformed);
    };
    if version != format!("v{API_VERSION}") || stamp.is_empty() || stamp.len() > 20 {
        return Err(AuthError::Malformed);
    }
    if !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AuthError::Malformed);
    }
    let timestamp: u64 = stamp.parse().map_err(|_| AuthError::Malformed)?;
    let (pre, tag) = (mac_bytes(pre)?, mac_bytes(tag)?);
    if now.abs_diff(timestamp) > MAX_SKEW_SECS {
        return Err(AuthError::Stale);
    }
    Ok(ParsedAuth {
        timestamp,
        pre,
        tag,
    })
}

/// Verify the pre-tag in constant time: method, path, timestamp and the declared content length,
/// before any body byte is read.
pub fn verify_pre(
    key: &[u8],
    method: &str,
    path: &str,
    timestamp: u64,
    content_length: u64,
    pre: &[u8],
) -> Result<(), AuthError> {
    pre_mac(key, method, path, timestamp, content_length)
        .ok_or(AuthError::Mismatch)?
        .verify_slice(pre)
        .map_err(|_| AuthError::Mismatch)
}

/// Verify a parsed header against the request, in constant time.
pub fn verify_tag(
    key: &[u8],
    method: &str,
    path: &str,
    timestamp: u64,
    tag: &[u8],
    body: &[u8],
) -> Result<(), AuthError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| AuthError::Mismatch)?;
    let digest = hex::encode(Sha256::digest(body));
    mac.update(format!("{method}\n{path}\n{timestamp}\n{digest}").as_bytes());
    mac.verify_slice(tag).map_err(|_| AuthError::Mismatch)
}

/// The MAC behind a response tag: `"resp" LF METHOD LF target LF auth LF server_secs LF status LF
/// hex(sha256(body))`. `auth` is the request's auth value as the server received it (SP/HTAB-trimmed),
/// empty when there was none.
fn resp_mac(
    key: &[u8],
    method: &str,
    target: &str,
    auth: &str,
    server_secs: u64,
    status: u16,
    body: &[u8],
) -> Option<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    let digest = hex::encode(Sha256::digest(body));
    let auth = auth.trim_matches([' ', '\t']);
    mac.update(
        format!("resp\n{method}\n{target}\n{auth}\n{server_secs}\n{status}\n{digest}").as_bytes(),
    );
    Some(mac)
}

/// The response tag for one answer. `None` only if the key is unusable (it never is).
pub fn resp_tag(
    key: &[u8],
    method: &str,
    target: &str,
    auth: &str,
    server_secs: u64,
    status: u16,
    body: &[u8],
) -> Option<[u8; 32]> {
    let tag = resp_mac(key, method, target, auth, server_secs, status, body)?
        .finalize()
        .into_bytes();
    Some(tag.into())
}

/// The `X-Disconect-Resp` value: `v1.<server secs>.<hex rtag>`.
pub fn resp_header_value(
    key: &[u8],
    method: &str,
    target: &str,
    auth: &str,
    server_secs: u64,
    status: u16,
    body: &[u8],
) -> Option<String> {
    let tag = resp_tag(key, method, target, auth, server_secs, status, body)?;
    Some(format!("v{API_VERSION}.{server_secs}.{}", hex::encode(tag)))
}

/// A response header's parts: the server's seconds and the tag. Exact shape only:
/// `v1.` + decimal + `.` + 64 lower-case hex.
pub fn parse_resp(header: &str) -> Result<(u64, [u8; 32]), AuthError> {
    let mut parts = header.split('.');
    let (Some(version), Some(stamp), Some(tag), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AuthError::Malformed);
    };
    if version != format!("v{API_VERSION}")
        || stamp.is_empty()
        || (stamp.len() > 1 && stamp.starts_with('0'))
        || stamp.len() > 20
        || !stamp.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(AuthError::Malformed);
    }
    let secs: u64 = stamp.parse().map_err(|_| AuthError::Malformed)?;
    let lower = tag.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let bytes: [u8; 32] = mac_bytes(tag)?.try_into().map_err(|_| AuthError::Malformed)?;
    if !lower {
        return Err(AuthError::Malformed);
    }
    Ok((secs, bytes))
}

/// Verify a response tag in constant time. `request` is `(method, target, auth value sent)`.
pub fn verify_resp(
    key: &[u8],
    request: (&str, &str, &str),
    server_secs: u64,
    status: u16,
    body: &[u8],
    tag: &[u8],
) -> Result<(), AuthError> {
    let (method, target, auth) = request;
    resp_mac(key, method, target, auth, server_secs, status, body)
        .ok_or(AuthError::Mismatch)?
        .verify_slice(tag)
        .map_err(|_| AuthError::Mismatch)
}

/// Unix seconds now. The wall clock itself, never the `DISCONECT_NOW` test pin: this is a security
/// check, and a pinned clock would make every token stale.
pub fn wall_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `http://host[:port]` (no path, query, user info or TLS): the base URL of a LAN relay, without a
/// trailing slash. The error text names the rule, never the URL.
pub fn parse_base_url(text: &str) -> Result<String, String> {
    let trimmed = text.trim();
    if trimmed.starts_with("https://") {
        return Err(
            "a LAN relay is plain http:// (the bodies are encrypted; https is not supported)"
                .into(),
        );
    }
    let Some(rest) = trimmed.strip_prefix("http://") else {
        return Err("a LAN relay URL looks like http://host:port".into());
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let valid = !rest.is_empty()
        && !rest.contains(['/', '?', '#', '@', ' '])
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
    if !valid {
        return Err("a LAN relay URL is http://host[:port] with no path".into());
    }
    Ok(format!("http://{rest}"))
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// A `Relay` over the Mac's LAN server. Holds the token key for its lifetime (zeroised on drop).
pub struct LanRelay {
    base: String,
    key: Zeroizing<[u8; 32]>,
    agent: ureq::Agent,
}

impl LanRelay {
    /// `url` is `http://host:port`; `master` is this device's master key (same account as the server).
    pub fn new(url: &str, master: &[u8]) -> Result<LanRelay, String> {
        let base = parse_base_url(url)?;
        // no proxy (a LAN address must never go through one), no redirects, 4xx/5xx are answers
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .proxy(None)
            .max_redirects(0)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Ok(LanRelay {
            base,
            key: token_key(master),
            agent,
        })
    }

    /// One authenticated request; the status and the body (capped at one bundle), returned only
    /// after the answer's response tag verified against this request. A missing, repeated,
    /// malformed or wrong tag is `Unverified`: nothing about the answer is interpreted.
    fn call(&self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), RelayError> {
        let ts = wall_clock();
        let header = auth_value(&*self.key, method, path, ts, body)
            .ok_or(RelayError::Unreachable)?;
        let url = format!("{}{path}", self.base);
        let outcome = match method {
            "GET" => self.agent.get(&url).header(AUTH_HEADER, &header).call(),
            "DELETE" => self.agent.delete(&url).header(AUTH_HEADER, &header).call(),
            _ => self.agent.put(&url).header(AUTH_HEADER, &header).send(body),
        };
        let mut response = outcome.map_err(|_| RelayError::Unreachable)?;
        let status = response.status().as_u16();
        let tag = single_resp_header(&response)?;
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_OBJECT)
            .read_to_vec()
            .map_err(|_| RelayError::Unreachable)?;
        let (secs, tag) = tag;
        verify_resp(&*self.key, (method, path, &header), secs, status, &bytes, &tag)
            .map_err(|_| RelayError::Unverified)?;
        if status == 401 {
            // A verified 401 is the real server refusing. Outside the skew window the clocks are
            // the cause; inside it nothing honest produces a 401 (a middlebox altered the request
            // and the server's refusal was replayed as a re-pair lure), so it stays `Unverified`.
            return Err(if ts.abs_diff(secs) > MAX_SKEW_SECS {
                RelayError::Unauthorized { skew_s: ts as i64 - secs as i64 }
            } else {
                RelayError::Unverified
            });
        }
        Ok((status, bytes))
    }
}

/// The one `X-Disconect-Resp` of an answer, parsed; none, two or a malformed one is `Unverified`.
fn single_resp_header<B>(response: &ureq::http::Response<B>) -> Result<(u64, [u8; 32]), RelayError> {
    let mut values = response.headers().get_all(RESP_HEADER).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(RelayError::Unverified);
    };
    let text = value.to_str().map_err(|_| RelayError::Unverified)?;
    parse_resp(text).map_err(|_| RelayError::Unverified)
}

/// An HTTP status as the `Relay` error the folder relay would have raised for the same thing.
fn status_error(status: u16) -> RelayError {
    match status {
        400 => RelayError::BadName,
        // `call` turns every verified 401 into `Unauthorized` or `Unverified` before this runs
        401 => RelayError::Unverified,
        404 => RelayError::Io(IoError::from(ErrorKind::NotFound)),
        413 => RelayError::TooLarge,
        other => RelayError::Status(other),
    }
}

impl Relay for LanRelay {
    fn put(&self, name: &str, data: &[u8]) -> Result<(), RelayError> {
        if !is_object_name(name) {
            return Err(RelayError::BadName);
        }
        match self.call("PUT", &format!("{OBJECTS}/{name}"), data)? {
            (200 | 204, _) => Ok(()),
            (status, _) => Err(status_error(status)),
        }
    }

    fn get(&self, name: &str) -> Result<Vec<u8>, RelayError> {
        if !is_object_name(name) {
            return Err(RelayError::BadName);
        }
        match self.call("GET", &format!("{OBJECTS}/{name}"), &[])? {
            (200, bytes) => Ok(bytes),
            (status, _) => Err(status_error(status)),
        }
    }

    fn list(&self, account: &str) -> Result<Vec<String>, RelayError> {
        let (status, bytes) = self.call("GET", OBJECTS, &[])?;
        if status != 200 {
            return Err(status_error(status));
        }
        let names: Vec<String> = serde_json::from_slice(&bytes)
            .map_err(|_| RelayError::Io(IoError::from(ErrorKind::InvalidData)))?;
        let prefix = format!("{account}/");
        let mut kept: Vec<String> = names
            .into_iter()
            .filter(|name| is_object_name(name) && name.starts_with(&prefix))
            .collect();
        kept.sort();
        kept.dedup();
        Ok(kept)
    }

    fn delete(&self, name: &str) -> Result<(), RelayError> {
        if !is_object_name(name) {
            return Err(RelayError::BadName);
        }
        match self.call("DELETE", &format!("{OBJECTS}/{name}"), &[])? {
            (200 | 204, _) => Ok(()),
            (status, _) => Err(status_error(status)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test master only (`1..=32`); no real key.
    fn master() -> Vec<u8> {
        (1u8..33).collect()
    }

    // header = v1.<timestamp>.<pre>.<tag>; the `tag` parts are the vectors that were committed with
    // slice 12-B and are unchanged, the `pre` parts were added by the review fix (F1); all four were
    // computed independently in Python (kb/24)
    const PUT_VECTOR: &str = "v1.1700000000.223c54881c588a7961c34cac621e4df08c54682e3501b340d3a8569f645895c7.2011a51d77be5327a5f5018eb22c266c5f137a1a3c4586f1f2617c8c51f6d060";
    const GET_VECTOR: &str = "v1.1700000000.74a9b34685ff14e016cec487a0b4e3b25b0bf43b4f346479a1c52bf7679c9373.71e67dc1ec1cefcf4692eabba5cbd8f4940fa4e97f7c4a18479fc7d15b194d62";

    #[test]
    fn the_token_label_is_frozen_verbatim() {
        assert_eq!(INFO_TOKEN, b"disconect/lan/v1/token");
    }

    #[test]
    fn known_answer_vectors() {
        // committed vectors (docs/kb/24-wire-constants.md), computed independently in Python
        // (hmac + hashlib, no shared code): any change here is a wire change
        let master = master();
        let account = account_for(&master);
        assert_eq!(
            account,
            "8c8b493bc5575edcd542351521fc997a89e727929b9bc4ecbfff8ec736ab0568"
        );
        let key = token_key(&master);
        assert_eq!(
            hex::encode(*key),
            "fb82fb73a463f5df7439df5e66c64e3731a8d8c7e7e6b07ea5715b54c7822350",
            "token key"
        );
        let name = format!("{account}/{}", "ab".repeat(16));
        assert_eq!(
            auth_value(
                &*key,
                "PUT",
                &format!("/v1/objects/{name}"),
                1_700_000_000,
                b"sealed bytes"
            )
            .as_deref(),
            Some(PUT_VECTOR)
        );
        assert_eq!(
            auth_value(&*key, "GET", "/v1/objects", 1_700_000_000, b"").as_deref(),
            Some(GET_VECTOR)
        );
    }

    #[test]
    fn a_header_round_trips_and_every_part_is_bound() {
        let key = token_key(&master());
        let value = auth_value(&*key, "PUT", "/v1/objects/a/b", 1_000, b"body").expect("value");
        let now = 1_100;
        let parsed = parse_auth(&value, now).expect("parse");
        let (stamp, tag, pre) = (parsed.timestamp, parsed.tag, parsed.pre);
        assert_eq!(stamp, 1_000);
        assert!(verify_tag(&*key, "PUT", "/v1/objects/a/b", stamp, &tag, b"body").is_ok());
        assert!(verify_pre(&*key, "PUT", "/v1/objects/a/b", stamp, 4, &pre).is_ok());
        for (method, path, body) in [
            ("GET", "/v1/objects/a/b", &b"body"[..]),
            ("PUT", "/v1/objects/a/c", &b"body"[..]),
            ("PUT", "/v1/objects/a/b", &b"bodY"[..]),
        ] {
            assert_eq!(
                verify_tag(&*key, method, path, stamp, &tag, body),
                Err(AuthError::Mismatch)
            );
        }
        assert_eq!(
            verify_tag(&*key, "PUT", "/v1/objects/a/b", 1_001, &tag, b"body"),
            Err(AuthError::Mismatch),
            "the timestamp is signed"
        );
        let other = token_key(&(2u8..34).collect::<Vec<_>>());
        assert_eq!(
            verify_tag(&*other, "PUT", "/v1/objects/a/b", stamp, &tag, b"body"),
            Err(AuthError::Mismatch)
        );
    }

    #[test]
    fn the_pre_tag_binds_method_path_timestamp_and_length_and_is_not_the_tag() {
        let key = token_key(&master());
        let value = auth_value(&*key, "PUT", "/v1/objects/a/b", 1_000, b"body").expect("value");
        let parsed = parse_auth(&value, 1_000).expect("parse");
        assert_ne!(parsed.pre, parsed.tag);
        let pre = |method, path, stamp, len| verify_pre(&*key, method, path, stamp, len, &parsed.pre);
        assert!(pre("PUT", "/v1/objects/a/b", 1_000, 4).is_ok());
        assert_eq!(pre("GET", "/v1/objects/a/b", 1_000, 4), Err(AuthError::Mismatch));
        assert_eq!(pre("PUT", "/v1/objects/a/c", 1_000, 4), Err(AuthError::Mismatch));
        assert_eq!(pre("PUT", "/v1/objects/a/b", 1_001, 4), Err(AuthError::Mismatch));
        assert_eq!(
            pre("PUT", "/v1/objects/a/b", 1_000, 1_000_000),
            Err(AuthError::Mismatch),
            "a replayed header with another length is refused"
        );
        // the tag cannot stand in for the pre-tag
        assert_eq!(
            verify_pre(&*key, "PUT", "/v1/objects/a/b", 1_000, 4, &parsed.tag),
            Err(AuthError::Mismatch)
        );
        let other = token_key(&(2u8..34).collect::<Vec<_>>());
        assert_eq!(
            verify_pre(&*other, "PUT", "/v1/objects/a/b", 1_000, 4, &parsed.pre),
            Err(AuthError::Mismatch)
        );
    }

    #[test]
    fn the_clock_window_and_the_shape_are_checked_before_the_body() {
        let key = token_key(&master());
        let at = |ts: u64| auth_value(&*key, "GET", "/v1/objects", ts, b"").expect("value");
        assert!(parse_auth(&at(1_000), 1_000 + MAX_SKEW_SECS).is_ok());
        assert!(parse_auth(&at(1_000), 1_000 - MAX_SKEW_SECS.min(1_000)).is_ok());
        assert_eq!(
            parse_auth(&at(1_000), 1_000 + MAX_SKEW_SECS + 1).unwrap_err(),
            AuthError::Stale
        );
        assert_eq!(
            parse_auth(&at(2_000), 2_000 - MAX_SKEW_SECS - 1).unwrap_err(),
            AuthError::Stale,
            "a timestamp from the future is as stale as one from the past"
        );
        let mac = "00".repeat(32);
        let short = "00".repeat(31);
        for bad in [
            String::new(),
            "v1".into(),
            "v1.1000".into(),
            format!("v1.1000.{mac}"),
            format!("v2.1000.{mac}.{mac}"),
            format!("v1.10x0.{mac}.{mac}"),
            format!("v1.1000.zz.{mac}"),
            format!("v1.1000.{mac}.zz"),
            format!("v1.1000.{short}.{mac}"),
            format!("v1.1000.{mac}.{short}"),
            format!("v1.1000.{mac}.{mac}.{mac}"),
            format!("v1..{mac}.{mac}"),
            format!("v1.1000..{mac}"),
        ] {
            assert_eq!(
                parse_auth(&bad, 1_000).unwrap_err(),
                AuthError::Malformed,
                "{bad}"
            );
        }
    }

    // response-tag vector (12-RA), computed independently in Python (hmac + hashlib): master 1..=32,
    // GET /v1/objects at ts 1000, server secs 1000, status 200, body `[]`
    const RESP_AUTH: &str = "v1.1000.eed0250402d3d138d4e77395553d05816469803b8a03dcac4811847d3d64e336.52e8ccfb4c2e95caa0ffa97acbfa52153b8ddf74a685275aabddba18689282ff";
    const RESP_VECTOR: &str = "v1.1000.6547026cb33f306df7bbbe0198be015aa23c3c756b5ef5c2ebe93bc191a8289c";

    #[test]
    fn the_response_tag_known_answer_vector() {
        let key = token_key(&master());
        assert_eq!(
            auth_value(&*key, "GET", "/v1/objects", 1_000, b"").as_deref(),
            Some(RESP_AUTH)
        );
        assert_eq!(
            resp_header_value(&*key, "GET", "/v1/objects", RESP_AUTH, 1_000, 200, b"[]").as_deref(),
            Some(RESP_VECTOR)
        );
        // the binder is trimmed of spaces and tabs, as the server's header parser does
        let padded = format!(" \t{RESP_AUTH}\t ");
        assert_eq!(
            resp_header_value(&*key, "GET", "/v1/objects", &padded, 1_000, 200, b"[]").as_deref(),
            Some(RESP_VECTOR)
        );
        assert_eq!(RESP_HEADER, "X-Disconect-Resp");
    }

    #[test]
    fn a_response_tag_round_trips_and_every_part_is_bound() {
        let key = token_key(&master());
        let value = resp_header_value(&*key, "GET", "/v1/objects", "hdr", 1_000, 200, b"[]").expect("value");
        let (secs, tag) = parse_resp(&value).expect("parse");
        assert_eq!(secs, 1_000);
        let check = |m: &str, t: &str, a: &str, s: u64, st: u16, b: &[u8]| verify_resp(&*key, (m, t, a), s, st, b, &tag);
        assert!(check("GET", "/v1/objects", "hdr", 1_000, 200, b"[]").is_ok());
        for bad in [
            check("PUT", "/v1/objects", "hdr", 1_000, 200, b"[]"),
            check("GET", "/v1/objects?x", "hdr", 1_000, 200, b"[]"),
            check("GET", "/v1/objects", "hdr2", 1_000, 200, b"[]"),
            check("GET", "/v1/objects", "hdr", 1_001, 200, b"[]"),
            check("GET", "/v1/objects", "hdr", 1_000, 204, b"[]"),
            check("GET", "/v1/objects", "hdr", 1_000, 200, b"[ ]"),
        ] {
            assert_eq!(bad, Err(AuthError::Mismatch));
        }
        let other = token_key(&(2u8..34).collect::<Vec<_>>());
        assert_eq!(
            verify_resp(&*other, ("GET", "/v1/objects", "hdr"), 1_000, 200, b"[]", &tag),
            Err(AuthError::Mismatch)
        );
    }

    #[test]
    fn the_response_header_shape_is_exact() {
        let mac = "ab".repeat(32);
        assert!(parse_resp(&format!("v1.5.{mac}")).is_ok());
        assert!(parse_resp(&format!("v1.0.{mac}")).is_ok());
        for bad in [
            String::new(),
            "v1".into(),
            format!("v2.5.{mac}"),
            format!("v1..{mac}"),
            format!("v1.5x.{mac}"),
            format!("v1.5.{mac}.{mac}"),
            format!("v1.5.{}", "ab".repeat(31)),
            format!("v1.5.{}", "AB".repeat(32)),
            format!("v1.5.{}", "zz".repeat(32)),
            format!("v1.{}.{mac}", "9".repeat(21)),
            format!("v1.5. {mac}"),
            format!("v1.05.{mac}"),
            format!("v1.00.{mac}"),
        ] {
            assert_eq!(parse_resp(&bad).unwrap_err(), AuthError::Malformed, "{bad}");
        }
    }

    #[test]
    fn base_urls_are_plain_http_hosts() {
        assert_eq!(
            parse_base_url("http://127.0.0.1:8080/").as_deref(),
            Ok("http://127.0.0.1:8080")
        );
        assert_eq!(
            parse_base_url(" http://mac.local:9 ").as_deref(),
            Ok("http://mac.local:9")
        );
        for bad in [
            "https://x:1",
            "ftp://x",
            "x:1",
            "http://",
            "http://x/y",
            "http://x?y=1",
            "http://u:p@x:1",
            "http://x y",
            "\u{1f}http://10.0.0.1:1", // `trim` removes White_Space only (BL-8: the Python oracle matches)
            "http://10.0.0.1:1\u{1c}",
        ] {
            assert!(parse_base_url(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_base_url("\u{3000}http://10.0.0.1:1\n").as_deref(), Ok("http://10.0.0.1:1"));
    }
}
