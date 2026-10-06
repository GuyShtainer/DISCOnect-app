// SPDX-License-Identifier: AGPL-3.0-or-later
//! The offer slot and the pairing routes of the LAN server (Bet 12-E, ADR 0011, `docs/relay-protocol.md`
//! "Pairing routes"). The routes carry no token: possession of the offer's secret `s` is the proof.
//!
//! * `POST /v1/pair/<id>`: the joiner's 64-byte body. The declared length is checked before any body
//!   byte is read (anything but exactly 64 is `400`, nothing read). Wrong tag `401` (the slot is
//!   untouched), the first valid join binds and answers `202` with the offerer's 64-byte reply (its revealed
//!   SAS nonce and its tag), the same public key again gets the identical `202`, a different one aborts the slot (`410`).
//! * `GET /v1/pair/<id>/payload`: `202` until the offerer released, then `200` + the cached sealed
//!   payload on every request; `410` once aborted or expired.
//!
//! No slot, or another id: `404` (so a plain `relay-serve` exposes nothing). Nothing here logs; the
//! server's logger sees method and status only.

use std::io::Read;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use x25519_dalek::StaticSecret;

use super::lan::wall_clock;
use super::lan_server::Reply;
use crate::pair::{
    self, EXPIRY_S, JOIN_BODY_LEN, Keys, OFFERER_REPLY_LEN, Offer, PairError, TRANSCRIPT_LEN, sas_text,
};
use zeroize::Zeroizing;

/// The route prefix of the pairing API.
pub const PAIR: &str = "/v1/pair";
const PAYLOAD_TAIL: &str = "payload";

struct Bound {
    joiner_pub: [u8; 32],
    transcript: [u8; TRANSCRIPT_LEN],
    keys: Keys,
    sas: u32,
    /// The `202` body (`N_o || tag`), answered again to the same joiner key.
    reply: [u8; OFFERER_REPLY_LEN],
    /// Sealed exactly once, on release; served on every later GET.
    sealed: Option<Vec<u8>>,
}

enum SlotState {
    Open,
    Bound(Box<Bound>),
    Aborted,
    /// Seen past `exp`: the keys are dropped, only what a `410` needs stays.
    Expired,
}

/// What a caller may observe of the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    Open,
    Bound,
    Released,
    Aborted,
    Expired,
}

/// The offer, the offerer's ephemeral secret and the state machine.
pub struct OfferSlot {
    offer: Offer,
    /// Dropped (`None`) once the offer ended, aborted or expired.
    secret: Option<StaticSecret>,
    /// The SAS nonce the offer committed to: a secret until the bind reveals it in the `202`; wiped with
    /// the ephemeral secret when the offer ends. Never in an event, a log or a status answer.
    n_o: Zeroizing<[u8; 32]>,
    state: SlotState,
    /// Set by the payload route on the first `200`.
    delivered: bool,
}

impl OfferSlot {
    /// The offer ended: drop the offerer's ephemeral secret and every derived key.
    fn end(&mut self, state: SlotState) {
        self.secret = None;
        *self.n_o = [0u8; 32];
        self.state = state;
    }

    /// Past `exp`: drop the keys of an offer that did not end by itself.
    fn retire_if_expired(&mut self, now: u64) -> bool {
        if now <= self.offer.exp {
            return false;
        }
        if !matches!(self.state, SlotState::Aborted | SlotState::Expired) {
            self.end(SlotState::Expired);
        }
        true
    }
}

/// The slot with its condition variable (shared by the server threads and the [`PairHandle`]).
pub struct PairShared {
    slot: Mutex<OfferSlot>,
    changed: Condvar,
}

impl PairShared {
    fn lock(&self) -> MutexGuard<'_, OfferSlot> {
        self.slot.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Builds an offer.
pub struct PairOffer;

impl PairOffer {
    /// A fresh offer for the relay at `listen_url` (`http://host:port`, explicit non-zero port),
    /// expiring [`EXPIRY_S`] after now: the text to show, and the handle that drives it.
    #[allow(clippy::new_ret_no_self)] // a builder: the product is the (text, handle) pair
    pub fn new(listen_url: &str) -> Result<(String, PairHandle), PairError> {
        PairOffer::new_at(listen_url, wall_clock())
    }

    /// [`PairOffer::new`] with an explicit clock (tests).
    pub fn new_at(listen_url: &str, now: u64) -> Result<(String, PairHandle), PairError> {
        let (secret, pub_key) = pair::ephemeral()?;
        let n_o = pair::fresh_nonce()?;
        let (mut s, mut id) = ([0u8; 16], [0u8; 16]);
        getrandom::fill(&mut s).map_err(|_| PairError::Random)?;
        getrandom::fill(&mut id).map_err(|_| PairError::Random)?;
        let offer = Offer {
            pub_key,
            c: pair::commit(&n_o),
            s,
            id,
            exp: now + EXPIRY_S,
            url: listen_url.to_string(),
        };
        let text = offer.encode();
        // the same strict check the joiner applies: never print an offer nobody can parse
        Offer::parse(&text)?;
        let shared = Arc::new(PairShared {
            slot: Mutex::new(OfferSlot {
                offer,
                secret: Some(secret),
                n_o,
                state: SlotState::Open,
                delivered: false,
            }),
            changed: Condvar::new(),
        });
        Ok((text, PairHandle { shared }))
    }
}

/// The offerer's side of a live offer.
#[derive(Clone)]
pub struct PairHandle {
    shared: Arc<PairShared>,
}

impl PairHandle {
    /// What the server routes read and write (`Ctx::with_offer`).
    pub fn shared(&self) -> Arc<PairShared> {
        Arc::clone(&self.shared)
    }

    /// The offer's expiry (Unix seconds).
    pub fn expires_at(&self) -> u64 {
        self.shared.lock().offer.exp
    }

    pub fn state(&self) -> PairState {
        let slot = self.shared.lock();
        match &slot.state {
            SlotState::Aborted => PairState::Aborted,
            SlotState::Expired => PairState::Expired,
            _ if wall_clock() > slot.offer.exp => PairState::Expired,
            SlotState::Open => PairState::Open,
            SlotState::Bound(b) if b.sealed.is_some() => PairState::Released,
            SlotState::Bound(_) => PairState::Bound,
        }
    }

    /// Block until a joiner is bound (`true`), or the slot is aborted or expired, or `timeout` passes
    /// (`false`; [`PairHandle::state`] says which). The offerer's own code never leaves the slot: the
    /// offerer compares typed digits ([`PairHandle::release`]) and displays nothing (ADR 0011 v2).
    pub fn wait_joined(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut slot = self.shared.lock();
        loop {
            match &slot.state {
                SlotState::Bound(_) => return true,
                SlotState::Aborted | SlotState::Expired => return false,
                SlotState::Open => {}
            }
            if slot.retire_if_expired(wall_clock()) {
                return false;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let step = left.min(Duration::from_secs(1));
            slot = self
                .shared
                .changed
                .wait_timeout(slot, step)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// The user typed `typed_digits`. Re-checked under the lock, at this moment: the slot must be
    /// bound, not aborted and not expired, and the digits must equal the code. A wrong code aborts
    /// the offer. Then the payload is sealed once and cached (an already released slot stays as it is).
    pub fn release(
        &self,
        typed_digits: &str,
        master: &[u8; 32],
        key_file_bytes: &[u8],
    ) -> Result<(), PairError> {
        let mut slot = self.shared.lock();
        let expired = slot.retire_if_expired(wall_clock());
        let result = match &mut slot.state {
            SlotState::Aborted => Err(PairError::OfferEnded),
            SlotState::Expired => Err(PairError::Expired),
            _ if expired => Err(PairError::Expired),
            SlotState::Open => Err(PairError::NotBound),
            SlotState::Bound(b) if b.sealed.is_some() => Ok(()),
            SlotState::Bound(b) => {
                if typed_digits == sas_text(b.sas) {
                    b.sealed = Some(pair::seal_payload(&b.keys, &b.transcript, master, key_file_bytes));
                    Ok(())
                } else {
                    Err(PairError::CodesDiffer)
                }
            }
        };
        if matches!(result, Err(PairError::CodesDiffer)) {
            slot.end(SlotState::Aborted);
        }
        drop(slot);
        self.shared.changed.notify_all();
        result
    }

    /// End the offer: every pair route answers `410` from now on.
    pub fn abort(&self) {
        self.shared.lock().end(SlotState::Aborted);
        self.shared.changed.notify_all();
    }

    /// Block until the payload was served with a `200` once (`true`), or `timeout` passes, or the
    /// offer ended without delivery (`false`).
    pub fn wait_delivered(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut slot = self.shared.lock();
        loop {
            if slot.delivered {
                return true;
            }
            if matches!(slot.state, SlotState::Aborted | SlotState::Expired) {
                return false;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            slot = self
                .shared
                .changed
                .wait_timeout(slot, left.min(Duration::from_secs(1)))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

fn bare(status: u16) -> Reply {
    Reply {
        status,
        body: Vec::new(),
        json: false,
        resp: None,
    }
}

fn bytes(status: u16, body: Vec<u8>) -> Reply {
    Reply {
        status,
        body,
        json: false,
        resp: None,
    }
}

/// Answer one request under `/v1/pair`. `shared` is `None` for a server without an offer.
pub fn handle(
    shared: Option<&PairShared>,
    method: &str,
    url: &str,
    declared_len: Option<usize>,
    body: &mut dyn Read,
    now: u64,
) -> Reply {
    let Some(shared) = shared else {
        return bare(404);
    };
    let Some(rest) = url.strip_prefix(PAIR).and_then(|r| r.strip_prefix('/')) else {
        return bare(404);
    };
    let (id_hex, tail) = match rest.split_once('/') {
        Some((id, tail)) => (id, Some(tail)),
        None => (rest, None),
    };
    if tail.is_some_and(|t| t != PAYLOAD_TAIL) {
        return bare(404);
    }
    if id_hex != hex::encode(shared.lock().offer.id) {
        return bare(404);
    }
    match tail {
        None if method == "POST" => join(shared, declared_len, body, now),
        Some(_) if method == "GET" => payload(shared, declared_len, now),
        _ => bare(405),
    }
}

fn join(shared: &PairShared, declared_len: Option<usize>, body: &mut dyn Read, now: u64) -> Reply {
    // before any body byte: exactly 64 (absent, shorter and longer are all a bare 400)
    if declared_len != Some(JOIN_BODY_LEN) {
        return bare(400);
    }
    {
        let mut slot = shared.lock();
        if slot.retire_if_expired(now) || matches!(slot.state, SlotState::Aborted | SlotState::Expired) {
            return bare(410);
        }
    }
    let mut buf = [0u8; JOIN_BODY_LEN];
    if body.read_exact(&mut buf).is_err() {
        return bare(408);
    }
    let (joiner_pub, tag) = buf.split_at(32);
    let joiner_pub: [u8; 32] = joiner_pub.try_into().unwrap_or([0u8; 32]);
    let mut slot = shared.lock();
    // the state may have moved while the body arrived
    if slot.retire_if_expired(now) || matches!(slot.state, SlotState::Aborted | SlotState::Expired) {
        return bare(410);
    }
    let Some(secret) = slot.secret.as_ref() else {
        return bare(410);
    };
    let Ok(shared_secret) = pair::dh(secret, &joiner_pub) else {
        return bare(401); // a low-order key is a wrong tag
    };
    let transcript = pair::transcript(&slot.offer.pub_key, &joiner_pub, &slot.offer.id, slot.offer.exp, &slot.offer.c);
    let keys = Keys::derive(&shared_secret, &slot.offer.s, &transcript);
    if pair::verify_joiner_tag(&keys, tag).is_err() {
        return bare(401); // the slot is untouched
    }
    match &slot.state {
        SlotState::Bound(bound) if bound.joiner_pub == joiner_pub => {
            return bytes(202, bound.reply.to_vec());
        }
        SlotState::Bound(_) => {
            slot.end(SlotState::Aborted);
            drop(slot);
            shared.changed.notify_all();
            return bare(410);
        }
        _ => {}
    }
    // the bind reveals N_o: from here it is in the reply, not a secret
    let reply = pair::offerer_reply(&keys, &slot.n_o);
    let sas = pair::sas(&keys, &slot.n_o);
    slot.state = SlotState::Bound(Box::new(Bound {
        joiner_pub,
        transcript,
        keys,
        sas,
        reply,
        sealed: None,
    }));
    drop(slot);
    shared.changed.notify_all();
    bytes(202, reply.to_vec())
}

fn payload(shared: &PairShared, declared_len: Option<usize>, now: u64) -> Reply {
    if declared_len.is_some_and(|len| len != 0) {
        return bare(400);
    }
    let mut slot = shared.lock();
    if slot.retire_if_expired(now) || matches!(slot.state, SlotState::Aborted | SlotState::Expired) {
        return bare(410);
    }
    let sealed = match &slot.state {
        SlotState::Bound(b) => b.sealed.clone(),
        _ => None,
    };
    let Some(sealed) = sealed else {
        return bare(202);
    };
    slot.delivered = true;
    drop(slot);
    shared.changed.notify_all();
    bytes(200, sealed)
}
