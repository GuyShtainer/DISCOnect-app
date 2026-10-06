// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 12-E slice 1, protocol v2 since 12-G: the pure pairing protocol (ADR 0011 as amended). No network,
//! no filesystem.
//!
//! Offer text (with the offerer's commitment to its SAS nonce), transcript, key schedule, both confirmation
//! tags, the offerer's reveal, the short authentication string and the payload seal/open. The labels and
//! layouts are frozen in `docs/kb/24-wire-constants.md` ("Pairing vectors (Bet 12-E, v2)"); changing one
//! breaks every paired device.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::keys::Secret32;

/// Prefix of the offer text (what the QR carries).
pub const OFFER_PREFIX: &str = "disconect-pair:v2.";
/// Transcript label and HKDF domain of the pairing protocol.
pub const LABEL: &str = "disconect/pair/v2";
pub const LABEL_CONFIRM: &str = "disconect/pair/v2/confirm";
pub const LABEL_OFFERER: &str = "disconect/pair/v2/offerer";
pub const LABEL_SAS: &str = "disconect/pair/v2/sas";
pub const LABEL_PAYLOAD: &str = "disconect/pair/v2/payload";
/// The commitment's domain: `c = SHA-256(LABEL_COMMIT || N_o)` (12-G).
pub const LABEL_COMMIT: &str = "disconect/pair/v2/commit";
/// HMAC messages (each under its own subkey; the offerer's and the SAS's are followed by `N_o`).
pub const MSG_CONFIRM: &[u8] = b"confirm";
pub const MSG_OFFERER: &[u8] = b"offerer";
pub const MSG_SAS: &[u8] = b"sas";
/// An offer lives 15 minutes (ADR 0004).
pub const EXPIRY_S: u64 = 900;
/// The joiner's POST body: `joiner_pub (32) || joiner_tag (32)`.
pub const JOIN_BODY_LEN: usize = 64;
/// The offerer's tag inside its `202` body.
pub const OFFERER_TAG_LEN: usize = 32;
/// The offerer's `202` body: `N_o (32) || HMAC(K_offerer, "offerer" || N_o) (32)`.
pub const OFFERER_REPLY_LEN: usize = 32 + OFFERER_TAG_LEN;
/// `LABEL (17) || 0x00 || offer_pub || joiner_pub || id || exp (8 B BE) || c (32)`: 138 bytes, `c` last.
pub const TRANSCRIPT_LEN: usize = LABEL.len() + 1 + 32 + 32 + 16 + 8 + 32;

/// Why a pairing step was refused. Never carries the offer text or any secret.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum PairError {
    #[error("bad offer text: {0}")]
    BadOffer(&'static str),
    #[error("the shared secret is not contributory (low-order public key)")]
    NonContributory,
    #[error("the offerer did not confirm")]
    BadTag,
    #[error("bad payload")]
    BadPayload,
    #[error("no random bytes available")]
    Random,
    #[error("the offer has not been joined yet")]
    NotBound,
    #[error("the offer expired")]
    Expired,
    #[error("the offer ended (another device answered, or it was aborted)")]
    OfferEnded,
    #[error("the codes differ")]
    CodesDiffer,
    #[error("cannot reach the offerer")]
    Network,
    #[error("the offerer refused the request (HTTP {0})")]
    Refused(u16),
    #[error("cancelled")]
    Cancelled,
    #[error("the paired key file does not match the key: {0}")]
    KeyFile(&'static str),
    /// A landing precondition failed before any request or write (nothing was changed).
    #[error("cannot pair here: {0}")]
    Precondition(&'static str),
    /// A write or the first pull failed after the landing began; the text states what is left.
    #[error("{0}")]
    Landing(String),
}

/// The offer: what the offerer shows (QR / pasted text) and the joiner parses.
#[derive(Clone, PartialEq, Eq)]
pub struct Offer {
    pub pub_key: [u8; 32],
    /// The offerer's commitment to its SAS nonce, [`commit`] of the `N_o` it reveals in the `202`.
    pub c: [u8; 32],
    pub s: [u8; 16],
    pub id: [u8; 16],
    pub exp: u64,
    pub url: String,
}

/// `s` is the offer's secret: it never reaches a log or a panic message.
impl std::fmt::Debug for Offer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Offer")
            .field("pub_key", &self.pub_key)
            .field("c", &self.c)
            .field("s", &"<redacted>")
            .field("id", &self.id)
            .field("exp", &self.exp)
            .field("url", &self.url)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOffer {
    v: u64,
    #[serde(rename = "pub")]
    pub_hex: String,
    c: String,
    s: String,
    id: String,
    exp: u64,
    url: String,
}

fn hex_exact<const N: usize>(text: &str) -> Result<[u8; N], PairError> {
    let ok = text.len() == 2 * N && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok {
        return Err(PairError::BadOffer("hex field is not lowercase hex of the exact length"));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out).map_err(|_| PairError::BadOffer("bad hex"))?;
    Ok(out)
}

/// kb/24 § offer URL grammar: exactly `http://` host `:` port — host an IPv4 address (four octets
/// 0..=255 without a leading zero), a bracketed IPv6 address (lowercase hex groups, one `::` at most,
/// no zone id) or a lowercase hostname (labels of `[a-z0-9-]`, no leading or trailing `-`, no trailing
/// dot); port `1..=65535` without a leading zero; no userinfo, path, slash, query, fragment or space.
/// The same grammar is `pair._check_url` in the Python oracle; the vectors are
/// `tests/fixtures/pair-offer-urls.json` (both cores, and the phone's parser when it comes).
fn check_offer_url(url: &str) -> Result<(), PairError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or(PairError::BadOffer("the relay URL is not http://host:port"))?;
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or(PairError::BadOffer("the relay URL needs an explicit port"))?;
    if !port_ok(port) {
        return Err(PairError::BadOffer(
            "the relay URL needs an explicit port in 1..=65535 without a leading zero",
        ));
    }
    if !host_ok(host) {
        return Err(PairError::BadOffer(
            "the relay URL host is not an IPv4 address, a bracketed IPv6 address or a lowercase hostname",
        ));
    }
    Ok(())
}

fn port_ok(port: &str) -> bool {
    (1..=5).contains(&port.len())
        && port.bytes().all(|b| b.is_ascii_digit())
        && !port.starts_with('0')
        && port.parse::<u32>().is_ok_and(|n| n <= 65535)
}

fn host_ok(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[') {
        return inner.strip_suffix(']').is_some_and(ipv6_ok);
    }
    if !host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return ipv4_ok(host);
    }
    (1..=253).contains(&host.len()) && host.split('.').all(label_ok)
}

fn ipv4_ok(host: &str) -> bool {
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.bytes().all(|b| b.is_ascii_digit())
                && (*octet == "0" || !octet.starts_with('0'))
                && octet.parse::<u32>().is_ok_and(|n| n <= 255)
        })
}

fn ipv6_ok(text: &str) -> bool {
    if text.contains(":::") {
        return false;
    }
    let halves: Vec<&str> = text.split("::").collect();
    if halves.len() > 2 {
        return false;
    }
    let groups: Vec<&str> = halves
        .iter()
        .filter(|half| !half.is_empty())
        .flat_map(|half| half.split(':'))
        .collect();
    let group_ok = |g: &&str| {
        (1..=4).contains(&g.len()) && g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    if !groups.iter().all(group_ok) {
        return false;
    }
    if halves.len() == 2 { groups.len() <= 7 } else { groups.len() == 8 }
}

fn label_ok(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

impl Offer {
    /// `disconect-pair:v2.` + base64url (no padding) of the compact JSON, keys in the order
    /// v, pub, c, s, id, exp, url.
    pub fn encode(&self) -> String {
        let url = serde_json::to_string(&self.url).unwrap_or_default();
        let json = format!(
            "{{\"v\":2,\"pub\":\"{}\",\"c\":\"{}\",\"s\":\"{}\",\"id\":\"{}\",\"exp\":{},\"url\":{}}}",
            hex::encode(self.pub_key),
            hex::encode(self.c),
            hex::encode(self.s),
            hex::encode(self.id),
            self.exp,
            url
        );
        format!("{OFFER_PREFIX}{}", URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    /// Strict parse: prefix, unpadded canonical base64url, exactly the seven keys (a duplicate or unknown
    /// key is refused by serde), `v == 2`, lowercase hex of exact lengths, integer `exp`, a
    /// `http://host:port` URL in the kb/24 grammar (see [`check_offer_url`]).
    pub fn parse(text: &str) -> Result<Offer, PairError> {
        let body = text
            .strip_prefix(OFFER_PREFIX)
            .ok_or(PairError::BadOffer("wrong prefix"))?;
        if body.contains('=') {
            return Err(PairError::BadOffer("padded base64url"));
        }
        let json = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| PairError::BadOffer("not base64url"))?;
        let raw: RawOffer = serde_json::from_slice(&json)
            .map_err(|_| PairError::BadOffer("not the seven-key offer object"))?;
        if raw.v != 2 {
            return Err(PairError::BadOffer("unsupported version"));
        }
        check_offer_url(&raw.url)?;
        Ok(Offer {
            pub_key: hex_exact::<32>(&raw.pub_hex)?,
            c: hex_exact::<32>(&raw.c)?,
            s: hex_exact::<16>(&raw.s)?,
            id: hex_exact::<16>(&raw.id)?,
            exp: raw.exp,
            url: raw.url,
        })
    }
}

/// `LABEL || 0x00 || offer_pub || joiner_pub || id || exp (8 B big-endian) || c` (`c` last, although it
/// follows `pub` in the offer JSON).
pub fn transcript(
    offer_pub: &[u8; 32],
    joiner_pub: &[u8; 32],
    id: &[u8; 16],
    exp: u64,
    c: &[u8; 32],
) -> [u8; TRANSCRIPT_LEN] {
    let mut out = [0u8; TRANSCRIPT_LEN];
    let mut at = 0;
    for part in [
        LABEL.as_bytes(),
        &[0u8],
        offer_pub,
        joiner_pub,
        id,
        &exp.to_be_bytes(),
        c,
    ] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    out
}

/// `c = SHA-256("disconect/pair/v2/commit" || N_o)`: the offerer's commitment to its 32-byte SAS nonce,
/// published in the offer; `N_o` itself is a secret until the join is bound.
pub fn commit(n_o: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LABEL_COMMIT.as_bytes());
    h.update(n_o);
    h.finalize().into()
}

/// A fresh 32-byte SAS nonce for an offer.
pub fn fresh_nonce() -> Result<Zeroizing<[u8; 32]>, PairError> {
    let mut n_o = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *n_o).map_err(|_| PairError::Random)?;
    Ok(n_o)
}

/// A fresh ephemeral X25519 key pair: the private half from `getrandom`.
pub fn ephemeral() -> Result<(StaticSecret, [u8; 32]), PairError> {
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *raw).map_err(|_| PairError::Random)?;
    let secret = StaticSecret::from(*raw);
    let public = PublicKey::from(&secret).to_bytes();
    Ok((secret, public))
}

/// X25519; refuses a low-order peer key (both sides call this).
pub fn dh(secret: &StaticSecret, their_pub: &[u8; 32]) -> Result<Secret32, PairError> {
    let shared = secret.diffie_hellman(&PublicKey::from(*their_pub));
    if !shared.was_contributory() {
        return Err(PairError::NonContributory);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

fn expand32(hk: &Hkdf<Sha256>, info: &[u8]) -> Secret32 {
    let mut out: Secret32 = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below the HKDF-SHA256 limit; expand cannot fail.
    if hk.expand(info, &mut *out).is_err() {
        out.fill(0);
    }
    out
}

/// The key schedule: `K` and its four subkeys.
pub struct Keys {
    pub k: Secret32,
    pub confirm: Secret32,
    pub offerer: Secret32,
    pub sas: Secret32,
    pub payload: Secret32,
}

impl Keys {
    /// `K = HKDF-SHA256(salt = s, ikm = dh, info = transcript, L = 32)`; each subkey is
    /// `HKDF-Expand(prk = K, info = label, L = 32)` (no second extract).
    pub fn derive(dh: &[u8; 32], s: &[u8; 16], transcript: &[u8]) -> Keys {
        let k = expand32(&Hkdf::<Sha256>::new(Some(s), dh), transcript);
        // `from_prk` only fails for a PRK shorter than the hash output; K is 32 bytes.
        let prk = Hkdf::<Sha256>::from_prk(&*k).unwrap_or_else(|_| Hkdf::<Sha256>::new(None, &*k));
        Keys {
            confirm: expand32(&prk, LABEL_CONFIRM.as_bytes()),
            offerer: expand32(&prk, LABEL_OFFERER.as_bytes()),
            sas: expand32(&prk, LABEL_SAS.as_bytes()),
            payload: expand32(&prk, LABEL_PAYLOAD.as_bytes()),
            k,
        }
    }
}

fn mac(key: &[u8; 32], msg: &[u8]) -> Hmac<Sha256> {
    // HMAC takes any key length: new_from_slice cannot fail; the empty-key arm keeps this total.
    let mut m = Hmac::<Sha256>::new_from_slice(key)
        .unwrap_or_else(|_| Hmac::<Sha256>::new_from_slice(&[]).expect("empty HMAC key"));
    m.update(msg);
    m
}

fn tag(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    mac(key, msg).finalize().into_bytes().into()
}

/// `HMAC-SHA256(K_confirm, "confirm")`, sent by the joiner.
pub fn joiner_tag(keys: &Keys) -> [u8; 32] {
    tag(&keys.confirm, MSG_CONFIRM)
}

fn offerer_msg(n_o: &[u8; 32]) -> [u8; MSG_OFFERER.len() + 32] {
    let mut m = [0u8; MSG_OFFERER.len() + 32];
    m[..MSG_OFFERER.len()].copy_from_slice(MSG_OFFERER);
    m[MSG_OFFERER.len()..].copy_from_slice(n_o);
    m
}

/// `HMAC-SHA256(K_offerer, "offerer" || N_o)` (a 39-byte message), the tag in the offerer's `202`.
pub fn offerer_tag(keys: &Keys, n_o: &[u8; 32]) -> [u8; 32] {
    tag(&keys.offerer, &offerer_msg(n_o))
}

/// The offerer's `202` body: `N_o || offerer_tag` (64 bytes).
pub fn offerer_reply(keys: &Keys, n_o: &[u8; 32]) -> [u8; OFFERER_REPLY_LEN] {
    let mut reply = [0u8; OFFERER_REPLY_LEN];
    reply[..32].copy_from_slice(n_o);
    reply[32..].copy_from_slice(&offerer_tag(keys, n_o));
    reply
}

/// The joiner's check of the offerer's `202` body, returning `N_o`: exactly 64 bytes, then the reveal
/// matches the offer's commitment `c`, then the tag verifies — in that order, each in constant time. The
/// joiner shows no code unless all three pass. The commitment check is the critical one (it is what keeps
/// the offerer's nonce unchangeable once the joiner's key is known) and is never dropped because the tag
/// also covers `N_o`.
pub fn open_offerer_reply(keys: &Keys, c: &[u8; 32], body: &[u8]) -> Result<[u8; 32], PairError> {
    if body.len() != OFFERER_REPLY_LEN {
        return Err(PairError::BadTag);
    }
    let n_o: [u8; 32] = body[..32].try_into().map_err(|_| PairError::BadTag)?;
    if !bool::from(commit(&n_o).ct_eq(c)) {
        return Err(PairError::BadTag);
    }
    verify_offerer_tag(keys, &n_o, &body[32..])?;
    Ok(n_o)
}

/// Constant-time check of the joiner's tag.
pub fn verify_joiner_tag(keys: &Keys, got: &[u8]) -> Result<(), PairError> {
    mac(&keys.confirm, MSG_CONFIRM)
        .verify_slice(got)
        .map_err(|_| PairError::BadTag)
}

/// Constant-time check of the offerer's tag over `N_o` (callers go through [`open_offerer_reply`]).
pub fn verify_offerer_tag(keys: &Keys, n_o: &[u8; 32], got: &[u8]) -> Result<(), PairError> {
    mac(&keys.offerer, &offerer_msg(n_o))
        .verify_slice(got)
        .map_err(|_| PairError::BadTag)
}

/// The raw SAS: first 4 bytes of `HMAC-SHA256(K_sas, "sas" || N_o)` (a 35-byte message) big-endian, mod 10^6.
pub fn sas(keys: &Keys, n_o: &[u8; 32]) -> u32 {
    let mut m = [0u8; MSG_SAS.len() + 32];
    m[..MSG_SAS.len()].copy_from_slice(MSG_SAS);
    m[MSG_SAS.len()..].copy_from_slice(n_o);
    let t = tag(&keys.sas, &m);
    u32::from_be_bytes([t[0], t[1], t[2], t[3]]) % 1_000_000
}

/// Six digits, zero-padded.
pub fn sas_text(sas: u32) -> String {
    format!("{sas:06}")
}

fn cipher(keys: &Keys) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new((&*keys.payload).into())
}

fn zero_nonce() -> Nonce {
    Nonce::default()
}

/// ChaCha20-Poly1305 under `K_payload`, nonce twelve zero bytes, AAD = transcript, plaintext =
/// `master || key file bytes`. Safe only if sealed once per `Keys`: the caller caches the result.
pub fn seal_payload(keys: &Keys, transcript: &[u8], master: &[u8; 32], key_file_bytes: &[u8]) -> Vec<u8> {
    let mut plain = Zeroizing::new(Vec::with_capacity(32 + key_file_bytes.len()));
    plain.extend_from_slice(master);
    plain.extend_from_slice(key_file_bytes);
    // Encryption of an in-memory buffer cannot fail except past the AEAD's length limit (256 GiB).
    cipher(keys)
        .encrypt(&zero_nonce(), Payload { msg: &plain, aad: transcript })
        .unwrap_or_default()
}

/// Opens a sealed payload: `(master, key file bytes)`. The key file bytes are validated by the caller.
pub fn open_payload(
    keys: &Keys,
    transcript: &[u8],
    sealed: &[u8],
) -> Result<(Secret32, Vec<u8>), PairError> {
    let plain = Zeroizing::new(
        cipher(keys)
            .decrypt(&zero_nonce(), Payload { msg: sealed, aad: transcript })
            .map_err(|_| PairError::BadPayload)?,
    );
    if plain.len() < 32 {
        return Err(PairError::BadPayload);
    }
    let mut master: Secret32 = Zeroizing::new([0u8; 32]);
    master.copy_from_slice(&plain[..32]);
    Ok((master, plain[32..].to_vec()))
}

#[cfg(test)]
mod wire_constants {
    //! Known-answer vectors (docs/kb/24-wire-constants.md "Pairing vectors (Bet 12-E, v2)"); the Python
    //! oracle is written from ADR 0011's text, not from this file.
    use super::*;
    use std::path::Path;

    const ALICE_PRIV: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUB: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_PRIV: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PUB: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const DH_HEX: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    const EXP: u64 = 1_700_000_900;
    const URL: &str = "http://127.0.0.1:8321";
    const C_HEX: &str = "2c08e0bd71af02fba14734f4b59043959d66c04a2e1a12defb09dbd127697930";
    const OFFER_TEXT: &str = "disconect-pair:v2.eyJ2IjoyLCJwdWIiOiI4NTIwZjAwOTg5MzBhNzU0NzQ4YjdkZGNiNDNlZjc1YTBkYmYzYTBkMjYzODFhZjRlYmE0YTk4ZWFhOWI0ZTZhIiwiYyI6IjJjMDhlMGJkNzFhZjAyZmJhMTQ3MzRmNGI1OTA0Mzk1OWQ2NmMwNGEyZTFhMTJkZWZiMDlkYmQxMjc2OTc5MzAiLCJzIjoiMDAwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYiLCJpZCI6IjEwMTExMjEzMTQxNTE2MTcxODE5MWExYjFjMWQxZTFmIiwiZXhwIjoxNzAwMDAwOTAwLCJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgzMjEifQ";
    const TRANSCRIPT_HEX: &str = "646973636f6e6563742f706169722f7632008520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6ade9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f101112131415161718191a1b1c1d1e1f000000006553f4842c08e0bd71af02fba14734f4b59043959d66c04a2e1a12defb09dbd127697930";
    const K_HEX: &str = "042ab2cd8fdd674d708af0e38242bca48e3d8223d769240fa5236596df173cae";
    const K_CONFIRM: &str = "ade5e5ac831e2c078ac5ff75e8f29fabaaf4b85b97ede4d782de3e7a014d1bd1";
    const K_OFFERER: &str = "5879aadcb2e23ffeab104838fa5324e5f3ae7183ca924fab9c433e6fa1ec1a26";
    const K_SAS: &str = "35dd953a91fbacfbfcf705fa7195101bbc84f949093fa6ff0e45d5a03eee4a14";
    const K_PAYLOAD: &str = "cf3239ae77e6b39c37128c877751f47f2bea3ca7190d50d0eddfdf9b710507f4";
    const JOINER_TAG: &str = "f75be896e432534bae6eaf9d00c55ea4b4a33deb5a9de7cbb38daad14aba009f";
    const OFFERER_TAG: &str = "5410268e5d3b5b62d787ef89c94d374e1b143bd57ff5b498f10e614b72f66d74";
    const SAS_RAW: u32 = 658_698;
    const SAS_TEXT: &str = "658698";
    const KEY_FILE_SHA: &str = "cd538c0cddf607a878a8424c3dcbbd58f9e2ba54529b550f18f813f446b01190";
    const SEALED_LEN: usize = 683;
    const SEALED_SHA: &str = "aabbdb81b8207c224001bd2906c4e98eca196c7f65adc52b54d797e36e7b754b";
    const LEAD_ID: &str = "2a2122232425262728292a2b2c2d2e2f";
    const LEAD_SAS: u32 = 47_069;
    const LEAD_TEXT: &str = "047069";

    fn h<const N: usize>(x: &str) -> [u8; N] {
        hex::decode(x).expect("hex").try_into().expect("length")
    }
    fn s() -> [u8; 16] {
        std::array::from_fn(|i| i as u8)
    }
    fn id() -> [u8; 16] {
        std::array::from_fn(|i| 0x10 + i as u8)
    }
    fn n_o() -> [u8; 32] {
        std::array::from_fn(|i| 0x30 + i as u8)
    }
    fn offer() -> Offer {
        Offer { pub_key: h(ALICE_PUB), c: h(C_HEX), s: s(), id: id(), exp: EXP, url: URL.into() }
    }
    fn keys_for(id: &[u8; 16]) -> (Keys, [u8; TRANSCRIPT_LEN]) {
        let a = StaticSecret::from(h::<32>(ALICE_PRIV));
        let d = dh(&a, &h(BOB_PUB)).expect("dh");
        let t = transcript(&h(ALICE_PUB), &h(BOB_PUB), id, EXP, &h(C_HEX));
        (Keys::derive(&d, &s(), &t), t)
    }
    fn key_file() -> Vec<u8> {
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test.keys.json"))
            .expect("fixture")
    }
    fn master() -> [u8; 32] {
        std::array::from_fn(|i| 1 + i as u8)
    }
    fn offer_text_of(json: &str) -> String {
        format!("{OFFER_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }
    const GOOD_FIELDS: &str = r#""pub":"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a","c":"2c08e0bd71af02fba14734f4b59043959d66c04a2e1a12defb09dbd127697930","s":"000102030405060708090a0b0c0d0e0f","id":"101112131415161718191a1b1c1d1e1f","exp":1700000900,"url":"http://127.0.0.1:8321""#;

    #[test]
    fn labels_are_frozen_verbatim() {
        assert_eq!(OFFER_PREFIX, "disconect-pair:v2.");
        assert_eq!(LABEL, "disconect/pair/v2");
        assert_eq!(LABEL_CONFIRM, "disconect/pair/v2/confirm");
        assert_eq!(LABEL_OFFERER, "disconect/pair/v2/offerer");
        assert_eq!(LABEL_SAS, "disconect/pair/v2/sas");
        assert_eq!(LABEL_PAYLOAD, "disconect/pair/v2/payload");
        assert_eq!(LABEL_COMMIT, "disconect/pair/v2/commit");
        assert_eq!((MSG_CONFIRM, MSG_OFFERER, MSG_SAS), (&b"confirm"[..], &b"offerer"[..], &b"sas"[..]));
        assert_eq!(EXPIRY_S, 900);
        assert_eq!((JOIN_BODY_LEN, OFFERER_TAG_LEN, OFFERER_REPLY_LEN, TRANSCRIPT_LEN), (64, 32, 64, 138));
    }

    #[test]
    fn rfc7748_public_keys_and_dh() {
        let a = StaticSecret::from(h::<32>(ALICE_PRIV));
        let b = StaticSecret::from(h::<32>(BOB_PRIV));
        assert_eq!(hex::encode(PublicKey::from(&a).to_bytes()), ALICE_PUB);
        assert_eq!(hex::encode(PublicKey::from(&b).to_bytes()), BOB_PUB);
        assert_eq!(hex::encode(*dh(&a, &h(BOB_PUB)).expect("dh")), DH_HEX);
        assert_eq!(hex::encode(*dh(&b, &h(ALICE_PUB)).expect("dh")), DH_HEX);
    }

    #[test]
    fn offer_vector_and_round_trip() {
        assert_eq!(offer().encode(), OFFER_TEXT);
        assert_eq!(Offer::parse(OFFER_TEXT).expect("parse"), offer());
        let (_, public) = ephemeral().expect("ephemeral");
        let o = Offer { pub_key: public, c: [8; 32], s: [7; 16], id: [9; 16], exp: 5, url: "http://[::1]:1".into() };
        assert_eq!(Offer::parse(&o.encode()).expect("round trip"), o);
        assert_eq!(OFFER_TEXT.len(), 388);
    }

    #[test]
    fn commitment_vector_and_fresh_nonces() {
        assert_eq!(hex::encode(commit(&n_o())), C_HEX);
        assert_eq!(commit(&n_o()), <[u8; 32]>::from(Sha256::digest([LABEL_COMMIT.as_bytes(), &n_o()[..]].concat())));
        let (a, b) = (fresh_nonce().expect("nonce"), fresh_nonce().expect("nonce"));
        assert_ne!(*a, *b);
        assert_ne!(commit(&a), commit(&b));
    }

    #[test]
    fn the_offerer_reply_opens_to_the_nonce_and_every_forgery_is_refused() {
        let (k, _) = keys_for(&id());
        let good = offerer_reply(&k, &n_o());
        assert_eq!(hex::encode(&good[32..]), OFFERER_TAG);
        assert_eq!(open_offerer_reply(&k, &h(C_HEX), &good), Ok(n_o()));
        let other: [u8; 32] = std::array::from_fn(|i| 0x50 + i as u8);
        let (k2, _) = keys_for(&h(LEAD_ID));
        let mut wrong_tag = good;
        wrong_tag[32] ^= 1;
        let mut wrong_reveal_right_tag = good;
        wrong_reveal_right_tag[..32].copy_from_slice(&other);
        for (name, body) in [
            ("32 bytes", good[..32].to_vec()),
            ("96 bytes", [good.to_vec(), vec![0u8; 32]].concat()),
            ("empty", Vec::new()),
            ("wrong reveal, tag over it", offerer_reply(&k, &other).to_vec()),
            ("wrong reveal, right tag", wrong_reveal_right_tag.to_vec()),
            ("right reveal, wrong tag", wrong_tag.to_vec()),
            ("another session's reply", offerer_reply(&k2, &n_o()).to_vec()),
        ] {
            assert_eq!(open_offerer_reply(&k, &h(C_HEX), &body), Err(PairError::BadTag), "{name}");
        }
        // the offer promised another nonce
        assert_eq!(open_offerer_reply(&k, &commit(&other), &good), Err(PairError::BadTag));
    }

    #[test]
    fn key_schedule_vectors() {
        let (k, t) = keys_for(&id());
        assert_eq!(hex::encode(t), TRANSCRIPT_HEX);
        assert_eq!(hex::encode(*k.k), K_HEX);
        assert_eq!(hex::encode(*k.confirm), K_CONFIRM);
        assert_eq!(hex::encode(*k.offerer), K_OFFERER);
        assert_eq!(hex::encode(*k.sas), K_SAS);
        assert_eq!(hex::encode(*k.payload), K_PAYLOAD);
        assert_eq!(hex::encode(joiner_tag(&k)), JOINER_TAG);
        assert_eq!(hex::encode(offerer_tag(&k, &n_o())), OFFERER_TAG);
        assert_eq!(sas(&k, &n_o()), SAS_RAW);
        assert_eq!(sas_text(sas(&k, &n_o())), SAS_TEXT);
        assert!(verify_joiner_tag(&k, &h::<32>(JOINER_TAG)).is_ok());
        assert!(verify_offerer_tag(&k, &n_o(), &h::<32>(OFFERER_TAG)).is_ok());
        assert_eq!(verify_joiner_tag(&k, &h::<32>(OFFERER_TAG)), Err(PairError::BadTag));
        assert_eq!(verify_offerer_tag(&k, &n_o(), &h::<32>(JOINER_TAG)), Err(PairError::BadTag));
        assert_eq!(verify_offerer_tag(&k, &[0u8; 32], &h::<32>(OFFERER_TAG)), Err(PairError::BadTag));
        assert_eq!(verify_joiner_tag(&k, &[0u8; 31]), Err(PairError::BadTag));
    }

    #[test]
    fn leading_zero_sas() {
        let (k, _) = keys_for(&h(LEAD_ID));
        assert_eq!(sas(&k, &n_o()), LEAD_SAS);
        assert_eq!(sas_text(sas(&k, &n_o())), LEAD_TEXT);
        assert_eq!(sas_text(0), "000000");
    }

    #[test]
    fn sealed_payload_vector_and_round_trip() {
        let kf = key_file();
        assert_eq!(hex::encode(Sha256::digest(&kf)), KEY_FILE_SHA);
        let (k, t) = keys_for(&id());
        let sealed = seal_payload(&k, &t, &master(), &kf);
        assert_eq!(sealed.len(), SEALED_LEN);
        assert_eq!(hex::encode(Sha256::digest(&sealed)), SEALED_SHA);
        let (m, back) = open_payload(&k, &t, &sealed).expect("open");
        assert_eq!(*m, master());
        assert_eq!(back, kf);
    }

    #[test]
    fn open_refuses_tampering() {
        let (k, t) = keys_for(&id());
        let sealed = seal_payload(&k, &t, &master(), b"kf");
        let mut flipped = sealed.clone();
        flipped[3] ^= 1;
        assert_eq!(open_payload(&k, &t, &flipped).err(), Some(PairError::BadPayload));
        let mut other_t = t;
        other_t[40] ^= 1;
        assert_eq!(open_payload(&k, &other_t, &sealed).err(), Some(PairError::BadPayload));
        let (k2, _) = keys_for(&h(LEAD_ID));
        assert_eq!(open_payload(&k2, &t, &sealed).err(), Some(PairError::BadPayload));
        assert_eq!(open_payload(&k, &t, &[]).err(), Some(PairError::BadPayload));
        // a valid seal of fewer than 32 plaintext bytes is refused too
        let short = cipher(&k)
            .encrypt(&zero_nonce(), Payload { msg: &[1u8; 31], aad: &t })
            .expect("seal");
        assert_eq!(open_payload(&k, &t, &short).err(), Some(PairError::BadPayload));
    }

    #[test]
    fn dh_refuses_low_order_keys() {
        let a = StaticSecret::from(h::<32>(ALICE_PRIV));
        assert_eq!(dh(&a, &[0u8; 32]).err(), Some(PairError::NonContributory));
        let order8 = h::<32>("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        assert_eq!(dh(&a, &order8).err(), Some(PairError::NonContributory));
    }

    /// kb/24 § offer URL grammar: the vectors every parser of the offer text shares
    /// (`projects/disconect/tests/fixtures/pair-offer-urls.json`).
    #[test]
    fn offer_url_vectors_are_shared_with_the_python_oracle() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../disconect/tests/fixtures/pair-offer-urls.json");
        let vectors: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("fixture")).expect("json");
        let fields = |url: &str| GOOD_FIELDS.replace("http://127.0.0.1:8321", url);
        let obj = |fields: &str| format!("{{\"v\":2,{fields}}}");
        let accepted = vectors["accepted"].as_array().expect("accepted");
        assert!(accepted.len() >= 12);
        for url in accepted {
            let url = url.as_str().expect("url");
            let offer = Offer::parse(&offer_text_of(&obj(&fields(url)))).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(offer.url, url);
        }
        let refused = vectors["refused"].as_object().expect("refused");
        assert!(refused.len() >= 44);
        for (name, url) in refused {
            let url = url.as_str().expect("url");
            assert!(
                matches!(Offer::parse(&offer_text_of(&obj(&fields(url)))), Err(PairError::BadOffer(_))),
                "{name} ({url}) must be refused"
            );
        }
    }

    /// Python's `urlsafe_b64decode` once accepted non-zero trailing bits; both cores refuse them now.
    #[test]
    fn non_canonical_base64url_trailing_bits_are_refused() {
        let body_len = OFFER_TEXT.len() - OFFER_PREFIX.len();
        assert!(!body_len.is_multiple_of(4), "the frozen vector ends in a partial group");
        let mut text = OFFER_TEXT.to_string();
        let last = text.pop().expect("last");
        // index 1 or 2: non-zero low bits in a partial group
        text.push(if last == 'B' { 'C' } else { 'B' });
        assert!(matches!(Offer::parse(&text), Err(PairError::BadOffer(m)) if m.contains("base64url")));
    }

    #[test]
    fn negative_offers_are_refused() {
        let bad = |json: String| assert!(matches!(Offer::parse(&offer_text_of(&json)), Err(PairError::BadOffer(_))), "{json}");
        let obj = |fields: &str| format!("{{\"v\":2,{fields}}}");
        // the good object parses (guards the helper)
        assert!(Offer::parse(&offer_text_of(&obj(GOOD_FIELDS))).is_ok());
        bad(obj(&GOOD_FIELDS.replace("8520f0098930", "8520F0098930")));
        bad(obj(&format!("{GOOD_FIELDS},\"pub\":\"{}\"", ALICE_PUB)));
        bad(obj(&format!("{GOOD_FIELDS},\"extra\":1")));
        bad(format!("{{\"v\":1,{GOOD_FIELDS}}}"));
        // the commitment: upper case, short, missing
        bad(obj(&GOOD_FIELDS.replace("2c08e0bd71af", "2C08E0BD71AF")));
        bad(obj(&GOOD_FIELDS.replace("2c08e0bd71af", "2c08e0bd71")));
        bad(obj(&GOOD_FIELDS.replace(",\"c\":\"2c08e0bd71af02fba14734f4b59043959d66c04a2e1a12defb09dbd127697930\"", "")));
        bad(obj(&GOOD_FIELDS.replace("8321", "0")));
        bad(obj(&GOOD_FIELDS.replace(":8321", "")));
        bad(obj(&GOOD_FIELDS.replace("http://", "https://")));
        bad(obj(&GOOD_FIELDS.replace("1700000900", "1700000900.0")));
        bad(obj(&GOOD_FIELDS.replace("1700000900", "-1")));
        bad(obj(&GOOD_FIELDS.replace("000102030405060708090a0b0c0d0e0f", "0001")));
        bad(obj(&GOOD_FIELDS.replace("http://127.0.0.1:8321", "http://127.0.0.1:8321/")));
        // padded base64url, wrong prefix, plain junk
        let padded = format!("{OFFER_TEXT}=");
        assert!(matches!(Offer::parse(&padded), Err(PairError::BadOffer(_))));
        let mut padded_len = OFFER_TEXT.to_string();
        while !(padded_len.len() - OFFER_PREFIX.len()).is_multiple_of(4) {
            padded_len.push('=');
        }
        assert!(matches!(Offer::parse(&padded_len), Err(PairError::BadOffer(_))));
        assert!(Offer::parse(&OFFER_TEXT.replace("v2", "v1")).is_err());
        assert!(Offer::parse("").is_err());
    }
}
