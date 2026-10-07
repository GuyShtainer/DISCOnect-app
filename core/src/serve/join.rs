// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 12-F row 3: `pair.join` and `pair.land`, the phone as the pairing *joiner* (ADR 0011, protocol v2).
//!
//! `pair.join {"offer"}` runs a prefix on the request loop, takes the import slot and starts a worker. The
//! worker waits until the Mac's address accepts a TCP connection, runs [`Joiner::join`], emits the six digits
//! once (`{"event":"pair","phase":"code","code":"…"}`, the one serve line that may carry a code), emits
//! `{"event":"pair","phase":"released"}` when the payload opened, then waits for `pair.land {"confirm"}`. A yes
//! lands through [`land_with`] and the worker's final answer is `{"state":"landed","pull":{…}}`; every failure
//! is a `pair_failed` error with a fixed message. Nothing here echoes an address, key, tag, code or offer text.
//!
//! The session cannot be reached from the worker thread, so the worker talks to it through one shared
//! [`JoinHub`]: the control block of the join in flight (`pair.cancel`, `pair.land`), the joiner map (one
//! [`Joiner`] per SHA-256 of the *canonically re-encoded parsed offer*) and the master hand-back (see [`JoinHub`]).
//!
//! Only an iOS build runs the worker; every other core refuses after the same prefix.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "ios")]
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
#[cfg(target_os = "ios")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;
#[cfg(any(target_os = "ios", test))]
use std::time::{Instant, SystemTime};

#[cfg(target_os = "ios")]
use serde_json::json;
use serde_json::Value;
#[cfg(target_os = "ios")]
use sha2::{Digest, Sha256};

#[cfg(target_os = "ios")]
use super::{Channel, result_line, sync_event};
use super::{Call, Failure, Json, Session};
use crate::keys::Secret32;
use crate::pair::Offer;
#[cfg(target_os = "ios")]
use crate::pair::PairError;
#[cfg(target_os = "ios")]
use crate::pair_client::Joined;
use crate::pair_client::{self, Joiner, LandStep};
use crate::relay::lan::wall_clock;
#[cfg(target_os = "ios")]
use crate::wirejson;

/// The longest offer text `pair.join` reads. A real offer is about 500 bytes (the seven-key object in
/// base64url, an IPv6 address being the longest URL); anything above this is not one.
pub const MAX_OFFER_TEXT: usize = 1024;
/// An offerer sets `exp = now + 900`; the phone allows the relay's own 300 s clock window on top.
const EXP_AHEAD_MAX: u64 = 900 + 300;
/// Joiners kept at once (one per parsed offer); the soonest to expire goes first.
#[cfg(target_os = "ios")]
const MAX_JOINERS: usize = 4;

const CLOCK_EXPIRED: &str = "This offer expired by this phone's clock. Check the date and time.";
const CLOCK_AHEAD: &str = "This offer is too far ahead of this phone's clock. Check the date and time.";
const ALREADY_PAIRED: &str = "This phone is already paired";
const BAD_ADDRESS: &str = "the offer's address cannot be a pairing address";
const FORGET_PENDING: &str = "This phone has not finished forgetting its last pairing. Close and reopen the app, then try again.";
#[cfg(target_os = "ios")]
const NOT_ON_LINK: &str = "This offer's address is not on this phone's network. Join the same Wi-Fi as your Mac and start a new offer on it.";
#[cfg(target_os = "ios")]
const CANCEL_ON_MAC: &str = "Cancel on your Mac and start a new offer.";

/// Test doors (never a flag or an environment variable): the landing wait, the reachability backoff and a
/// failure injected after a landing step.
#[derive(Clone, Copy, Debug)]
pub struct JoinHooks {
    /// How long the worker waits for `pair.land` after "released" before it gives up (a no).
    pub land_wait: Duration,
    /// The first pause of the reachability wait (it doubles to two seconds).
    pub reach_backoff: Duration,
    /// Fail right after this landing step completed, as a crash or a full disk would.
    pub fail_after: Option<LandStep>,
    /// Pause after each landing step (widens the window the hand-back test looks into).
    pub step_pause: Duration,
}

impl Default for JoinHooks {
    fn default() -> Self {
        JoinHooks { land_wait: Duration::from_secs(600), reach_backoff: Duration::from_millis(250), fail_after: None, step_pause: Duration::ZERO }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The control block of the join in flight.
struct JoinCtl {
    /// Set by `pair.cancel` (before release) or by the session's end; read by [`Joiner::join`]'s polls.
    cancel: AtomicBool,
    state: Mutex<CtlState>,
    wake: Condvar,
}

struct CtlState {
    /// The payload opened: from here `pair.cancel` is refused and only `pair.land` decides.
    released: bool,
    decision: Option<bool>,
    /// The session ended, the key was locked or the wait ran out: wake the landing wait with a no.
    over: bool,
}

/// Everything the request loop and the worker share. Set up once per session.
///
/// **The hand-back (12-F M4).** On a yes the worker sets `landing` *before* `land_with` writes anything, and
/// after the first pull it puts the master in `handed` and then finishes (slot, final answer). The session
/// takes `handed` into its own `unlocked` at the start of its next request ([`Session::take_handed`]) and
/// only then clears `landing`. So between the key file existing and the master being in the session,
/// `is_unlocked` is true (never `locked`, which would send the UI to the passphrase screen) and
/// `require_unlocked` answers `busy` ("a pairing is landing") instead of letting a reader run without a master.
/// A landing that fails clears `landing` itself and hands nothing back: a key file with no master reads as
/// locked, which is the truth (Unlock, then Pull now).
///
/// **The revocation (12-F row 3 review, M1).** `key.lock` calls [`JoinHub::revoke`]. A master must not come
/// back after the app was told to drop it, so the flag is set under the `handed` mutex: a worker that
/// finishes afterwards zeroizes its master instead of handing it back (the pairing still lands, locked), and a
/// master already handed is dropped. The flag is reset when the next join starts.
pub struct JoinHub {
    active: Mutex<Option<Arc<JoinCtl>>>,
    joiners: Mutex<Vec<([u8; 32], Arc<Joiner>)>>,
    handed: Mutex<Option<Secret32>>,
    landing: AtomicBool,
    /// `key.lock` ran since the current join started (set and read under `handed`).
    revoked: AtomicBool,
    /// The import slot is held by a join (so a refused caller can be told why).
    holds_slot: AtomicBool,
    hooks: Mutex<JoinHooks>,
}

impl JoinHub {
    pub fn new() -> JoinHub {
        JoinHub {
            active: Mutex::new(None),
            joiners: Mutex::new(Vec::new()),
            handed: Mutex::new(None),
            landing: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            holds_slot: AtomicBool::new(false),
            hooks: Mutex::new(JoinHooks::default()),
        }
    }

    pub fn landing(&self) -> bool {
        self.landing.load(Ordering::SeqCst)
    }

    pub fn set_hooks(&self, hooks: JoinHooks) {
        *lock(&self.hooks) = hooks;
    }

    /// The `busy` text for a caller that found the import slot taken: a join holds it (or is stopping) or not.
    pub fn busy_message(&self, other_holder: &'static str) -> &'static str {
        if self.holds_slot.load(Ordering::SeqCst) {
            "a pairing is still running or stopping; try again in a moment"
        } else {
            other_holder
        }
    }

    /// The master the worker handed back, once. Clears `landing`: the master is now the session's. A
    /// revoked hand-back is dropped (zeroized) instead.
    pub fn take_handed(&self) -> Option<Secret32> {
        let mut handed = lock(&self.handed);
        let master = handed.take();
        if master.is_some() {
            self.landing.store(false, Ordering::SeqCst);
        }
        if self.revoked.load(Ordering::SeqCst) {
            return None;
        }
        master
    }

    /// `key.lock`: the master must not come back. Under the `handed` mutex the flag goes up and a master
    /// already waiting is dropped; a join still waiting for `pair.land` ends as a no.
    pub fn revoke(&self) {
        {
            let mut handed = lock(&self.handed);
            self.revoked.store(true, Ordering::SeqCst);
            if handed.take().is_some() {
                self.landing.store(false, Ordering::SeqCst);
            }
        }
        if let Some(ctl) = lock(&self.active).clone() {
            let mut state = lock(&ctl.state);
            if state.released && state.decision.is_none() {
                state.over = true;
                ctl.wake.notify_all();
            }
        }
    }

    /// The worker's success: hand the master to the session, or, when `key.lock` ran, drop it (the pairing is
    /// landed, the phone is paired and locked). Returns whether it was handed.
    #[cfg(target_os = "ios")]
    fn hand_back(&self, master: &Secret32) -> bool {
        let mut handed = lock(&self.handed);
        if self.revoked.load(Ordering::SeqCst) {
            *handed = None;
            self.landing.store(false, Ordering::SeqCst);
            return false;
        }
        *handed = Some(master.clone());
        true
    }

    /// A new join starts: an earlier `key.lock` does not apply to it.
    #[cfg(target_os = "ios")]
    fn begin(&self) {
        let _handed = lock(&self.handed);
        self.revoked.store(false, Ordering::SeqCst);
    }

    /// The session ends: a join before release is cancelled, a wait for `pair.land` becomes a no. A landing in
    /// progress is not interrupted.
    pub fn shutdown(&self) {
        if let Some(ctl) = lock(&self.active).clone() {
            let mut state = lock(&ctl.state);
            if !state.released {
                ctl.cancel.store(true, Ordering::SeqCst);
            }
            state.over = true;
            ctl.wake.notify_all();
        }
    }

    #[cfg(target_os = "ios")]
    fn joiner_for(&self, offer: &Offer, make: impl Fn() -> Result<Joiner, PairError>) -> Result<([u8; 32], Arc<Joiner>), PairError> {
        let key = offer_key(offer);
        let mut joiners = lock(&self.joiners);
        let now = wall_clock();
        joiners.retain(|(_, j)| j.offer().exp >= now);
        if let Some((_, found)) = joiners.iter().find(|(k, _)| *k == key) {
            return Ok((key, Arc::clone(found)));
        }
        let made = Arc::new(make()?);
        while joiners.len() >= MAX_JOINERS {
            // the one that expires first
            if let Some(at) = joiners.iter().enumerate().min_by_key(|(_, (_, j))| j.offer().exp).map(|(at, _)| at) {
                joiners.remove(at);
            }
        }
        joiners.push((key, Arc::clone(&made)));
        Ok((key, made))
    }

    #[cfg(target_os = "ios")]
    fn drop_joiner(&self, key: &[u8; 32]) {
        lock(&self.joiners).retain(|(k, _)| k != key);
    }

    /// Joiners kept (tests).
    #[doc(hidden)]
    pub fn joiner_count(&self) -> usize {
        lock(&self.joiners).len()
    }
}

impl Default for JoinHub {
    fn default() -> Self {
        JoinHub::new()
    }
}

/// SHA-256 of the offer re-encoded canonically ([`Offer::encode`]): the joiner map's key, never the offer id.
/// Two texts that parse to the same offer (whitespace in the JSON, say) are one joiner, as the ADR pins the
/// joiner to the parsed offer.
#[cfg(target_os = "ios")]
fn offer_key(offer: &Offer) -> [u8; 32] {
    let digest = Sha256::digest(offer.encode().as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn bad(message: &str) -> Failure {
    Failure::serve("bad_params", message)
}

fn pair_failed(message: &str) -> Failure {
    Failure::serve("pair_failed", message)
}

/// `offer`: a non-empty string (shape errors fixed, never echoing it).
fn offer_param(call: &Call) -> Result<String, Failure> {
    match call.params.get("offer") {
        Some(Json::Str(text)) if !text.is_empty() => {
            text.to_text().ok_or_else(|| bad("that is not a pairing offer"))
        }
        _ => Err(bad("offer must be a non-empty string")),
    }
}

/// The URL's host as an IP address: four dotted decimals or a bracketed IPv6 address. The URL itself was
/// checked against the kb/24 grammar by `Offer::parse`, so anything else here is a hostname.
fn offer_ip(url: &str) -> Option<IpAddr> {
    let host = url
        .strip_prefix("http://")
        .and_then(|rest| rest.rsplit_once(':'))
        .map_or("", |(host, _)| host);
    if let Some(inner) = host.strip_prefix('[') {
        return inner.strip_suffix(']').and_then(|text| text.parse::<Ipv6Addr>().ok()).map(IpAddr::V6);
    }
    if !host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return host.parse::<Ipv4Addr>().ok().map(IpAddr::V4);
    }
    None
}

/// An IPv4-mapped IPv6 address is judged as the IPv4 address it carries.
fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Stage 1 (shared prefix, both cores): addresses that are never a pairing address. Unspecified (0.0.0.0/8,
/// `::`), limited broadcast, multicast (224.0.0.0/4, ff00::/8), reserved (240.0.0.0/4) and link-local
/// (169.254.0.0/16, fe80::/10; the Mac never offers one, `relay/serving.rs` excludes it).
fn never_a_pairing_address(ip: IpAddr) -> bool {
    match unmapped(ip) {
        // 224.0.0.0/4 and 240.0.0.0/4 (with 255.255.255.255) are everything from 224 up
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0 || o[0] >= 224 || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => v6.is_unspecified() || v6.octets()[0] == 0xff || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// One up interface address and its prefix length (from `getifaddrs`).
#[cfg(any(target_os = "ios", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Iface {
    addr: IpAddr,
    prefix: u8,
}

#[cfg(any(target_os = "ios", test))]
fn is_private(ip: IpAddr) -> bool {
    match unmapped(ip) {
        // 10/8, 172.16/12, 192.168/16, CGNAT 100.64/10
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168) || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        // ULA fc00::/7
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

#[cfg(any(target_os = "ios", test))]
fn is_loopback(ip: IpAddr) -> bool {
    unmapped(ip).is_loopback()
}

/// `ip` inside the subnet of one of `ifaces` (same family; a prefix of 0 would make everything on-link, so
/// it counts for nothing).
#[cfg(any(target_os = "ios", test))]
fn on_link(ip: IpAddr, ifaces: &[Iface]) -> bool {
    let ip = unmapped(ip);
    ifaces.iter().any(|iface| {
        if iface.prefix == 0 {
            return false;
        }
        match (ip, iface.addr) {
            (IpAddr::V4(a), IpAddr::V4(b)) if iface.prefix <= 32 => {
                let mask = u32::MAX << (32 - u32::from(iface.prefix));
                u32::from(a) & mask == u32::from(b) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(b)) if iface.prefix <= 128 => {
                let mask = u128::MAX << (128 - u32::from(iface.prefix));
                u128::from(a) & mask == u128::from(b) & mask
            }
            _ => false,
        }
    })
}

/// Stage 2 (iOS only): is `ip` a plausible address for the Mac on this phone's network? Loopback only when
/// the build allows it (simulator or debug); private ranges (RFC1918, CGNAT, ULA) yes; anything else only
/// when it is on-link.
#[cfg(any(target_os = "ios", test))]
fn reachable_class(ip: IpAddr, loopback_ok: bool, ifaces: &[Iface]) -> bool {
    if is_loopback(ip) {
        return loopback_ok;
    }
    is_private(ip) || on_link(ip, ifaces)
}

/// The up interfaces of this phone with their prefix lengths (`getifaddrs`). Empty when the call fails.
#[cfg(target_os = "ios")]
fn up_interfaces() -> Vec<Iface> {
    let mut found = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `head` with a list that stays valid until `freeifaddrs` below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return found;
    }
    let mut node = head;
    while !node.is_null() {
        // SAFETY: `node` is a live element of the list `getifaddrs` returned.
        let ifa = unsafe { &*node };
        node = ifa.ifa_next;
        if ifa.ifa_flags & (libc::IFF_UP as u32) == 0 || ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: both sockaddrs are non-null and of the family their `sa_family` names; each cast below
        // is to the struct of that family.
        unsafe {
            match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let mask = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                    found.push(Iface {
                        addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr))),
                        prefix: u32::from_be(mask.sin_addr.s_addr).leading_ones() as u8,
                    });
                }
                libc::AF_INET6 => {
                    let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let mask = &*(ifa.ifa_netmask as *const libc::sockaddr_in6);
                    found.push(Iface {
                        addr: IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)),
                        prefix: u128::from_be_bytes(mask.sin6_addr.s6_addr).leading_ones() as u8,
                    });
                }
                _ => {}
            }
        }
    }
    // SAFETY: `head` came from `getifaddrs` and nothing points into the list any more.
    unsafe { libc::freeifaddrs(head) };
    found
}

/// Stage 2 of the address check, before any network call.
#[cfg(target_os = "ios")]
fn check_reachable_class(url: &str) -> Result<(), Failure> {
    let Some(ip) = offer_ip(url) else {
        return Err(bad("the offer's address must be an IP address, not a name"));
    };
    let loopback_ok = cfg!(any(target_abi = "sim", debug_assertions));
    if reachable_class(ip, loopback_ok, &up_interfaces()) {
        Ok(())
    } else {
        Err(pair_failed(NOT_ON_LINK))
    }
}

/// The prefix of `pair.join`, in order, before any network call (and so before a key is drawn): the shape,
/// an IP-literal host, an address class that is never a pairing address, `exp` not too far ahead, the expiry by
/// this phone's clock, the landing site, an unfinished forget. The same order and the same messages as the
/// Python twin (`serve.py` `_join_prefix`).
pub fn join_prefix(text: &str, db: &Path) -> Result<Offer, Failure> {
    prefix_at(text, db, wall_clock())
}

fn prefix_at(text: &str, db: &Path, now: u64) -> Result<Offer, Failure> {
    let text = text.trim();
    if text.len() > MAX_OFFER_TEXT {
        return Err(bad("that is not a pairing offer"));
    }
    let offer = Offer::parse(text).map_err(|_| bad("that is not a pairing offer"))?;
    let Some(ip) = offer_ip(&offer.url) else {
        return Err(bad("the offer's address must be an IP address, not a name"));
    };
    if never_a_pairing_address(ip) {
        return Err(bad(BAD_ADDRESS));
    }
    if offer.exp > now.saturating_add(EXP_AHEAD_MAX) {
        return Err(pair_failed(CLOCK_AHEAD));
    }
    // the joiner itself refuses `now > exp` too (Joiner::new, join_with): no tolerance past `exp`
    if now > offer.exp {
        return Err(pair_failed(CLOCK_EXPIRED));
    }
    pair_client::check_landing_site(db, &crate::home::relay_config_beside(db), &offer.url)
        .map_err(|_| pair_failed(ALREADY_PAIRED))?;
    let marker = crate::pair_forget::Paths::beside(db, &crate::keys::key_path_for(db)).marker;
    if marker.exists() {
        return Err(pair_failed(FORGET_PENDING));
    }
    Ok(offer)
}

/// `pair.join`. A phone-only method: any other core answers `unsupported_transport` after the prefix.
pub(super) fn pair_join(session: &mut Session, call: &Call) -> Result<(), Failure> {
    let text = offer_param(call)?;
    let offer = join_prefix(&text, &session.db_path)?;
    #[cfg(not(target_os = "ios"))]
    {
        let _ = (text, offer);
        Err(Failure::serve("unsupported_transport", "this core is not a phone; it does not join a pairing"))
    }
    #[cfg(target_os = "ios")]
    {
        check_reachable_class(&offer.url)?;
        start_join(session, call, &text, offer)
    }
}

#[cfg(target_os = "ios")]
fn start_join(session: &mut Session, call: &Call, text: &str, offer: Offer) -> Result<(), Failure> {
    let hub = Arc::clone(&session.join);
    if session
        .import_slot
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(Failure::serve("busy", hub.busy_message("an import or a sync is already running")));
    }
    hub.holds_slot.store(true, Ordering::SeqCst);
    let slot = Arc::clone(&session.import_slot);
    let release = |failure: Failure| {
        // the hub's flag first, so a stale "a pairing holds it" is never read against a slot someone else took
        hub.holds_slot.store(false, Ordering::SeqCst);
        slot.store(false, Ordering::SeqCst);
        failure
    };
    let (key, joiner) = hub
        .joiner_for(&offer, || Joiner::new(text))
        .map_err(|error| release(match error {
            PairError::Expired => pair_failed(CLOCK_EXPIRED),
            _ => Failure::serve("internal", "cannot start the pairing"),
        }))?;
    hub.begin();
    let ctl = Arc::new(JoinCtl {
        cancel: AtomicBool::new(false),
        state: Mutex::new(CtlState { released: false, decision: None, over: false }),
        wake: Condvar::new(),
    });
    *lock(&hub.active) = Some(Arc::clone(&ctl));
    let job = JoinJob {
        id: call.id.clone(),
        db_path: session.db_path.clone(),
        channel: Arc::clone(&session.channel),
        slot: Arc::clone(&session.import_slot),
        hub: Arc::clone(&hub),
        ctl,
        joiner,
        key,
        offer_url: offer.url,
        hooks: *lock(&hub.hooks),
    };
    match std::thread::Builder::new().name("join".into()).spawn(move || join_worker(job)) {
        Ok(handle) => {
            session.workers.push(handle);
            Ok(())
        }
        Err(error) => {
            *lock(&hub.active) = None;
            Err(release(Failure::Io(error)))
        }
    }
}

/// `pair.land {"confirm": true|false}`: the decision after "released". A phone-only method.
pub(super) fn pair_land(session: &mut Session, call: &Call) -> Result<Value, Failure> {
    let confirm = match call.params.get("confirm") {
        Some(Json::Bool(value)) => *value,
        _ => return Err(bad("confirm must be true or false")),
    };
    #[cfg(not(target_os = "ios"))]
    {
        let _ = (session, confirm);
        Err(Failure::serve("unsupported_transport", "this core is not a phone; it does not join a pairing"))
    }
    #[cfg(target_os = "ios")]
    {
        let Some(ctl) = lock(&session.join.active).clone() else {
            return Err(Failure::serve("not_found", "there is no pairing waiting for an answer"));
        };
        let mut state = lock(&ctl.state);
        if !state.released {
            return Err(Failure::serve("busy", "the Mac has not released this pairing yet"));
        }
        if state.decision.is_some() || state.over {
            return Err(Failure::serve("busy", "this pairing was already answered"));
        }
        state.decision = Some(confirm);
        ctl.wake.notify_all();
        Ok(json!({"state": if confirm { "landing" } else { "declined" }}))
    }
}

/// `pair.cancel` on the phone: only the joiner's cancel flag, never the relay's `serving::cancel`.
/// Before the payload opens: cancelled, nothing written. After: refused, landing continues.
#[cfg(target_os = "ios")]
pub(super) fn cancel_join(session: &Session) -> Result<Value, Failure> {
    let Some(ctl) = lock(&session.join.active).clone() else {
        return Err(Failure::serve("not_found", "there is no offer to cancel"));
    };
    let state = lock(&ctl.state);
    if state.released {
        return Err(Failure::serve(
            "busy",
            "the Mac already released this pairing; answer the check on this phone",
        ));
    }
    ctl.cancel.store(true, Ordering::SeqCst);
    drop(state);
    Ok(json!({"state": "aborted"}))
}

#[cfg(target_os = "ios")]
struct JoinJob {
    id: super::Id,
    db_path: PathBuf,
    channel: Arc<Channel>,
    slot: Arc<AtomicBool>,
    hub: Arc<JoinHub>,
    ctl: Arc<JoinCtl>,
    joiner: Arc<Joiner>,
    key: [u8; 32],
    offer_url: String,
    hooks: JoinHooks,
}

/// How far the landing got, for the failure message.
#[cfg(target_os = "ios")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reached {
    Nothing,
    RelayFile,
    KeyFile,
}

#[cfg(target_os = "ios")]
enum Outcome {
    Landed(Value),
    Failed { failure: Failure, drop_joiner: bool },
}

#[cfg(target_os = "ios")]
fn event_line(value: &Value) -> String {
    let mut line = String::new();
    wirejson::write_value(&mut line, value);
    line
}

#[cfg(target_os = "ios")]
fn join_worker(job: JoinJob) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_join(&job)))
        .unwrap_or_else(|_| Outcome::Failed {
            failure: Failure::serve("internal", "unexpected panic in the join worker"),
            drop_joiner: true,
        });
    let line = match outcome {
        Outcome::Landed(result) => {
            job.hub.drop_joiner(&job.key);
            result_line(&job.id, &result)
        }
        Outcome::Failed { failure, drop_joiner } => {
            if drop_joiner {
                job.hub.drop_joiner(&job.key);
            }
            job.hub.landing.store(false, Ordering::SeqCst);
            // a master a failed landing left in `handed` must not outlive it
            *lock(&job.hub.handed) = None;
            super::failure_line(&job.id, &failure)
        }
    };
    *lock(&job.hub.active) = None;
    // the hub's flag before the slot (see `start_join`)
    job.hub.holds_slot.store(false, Ordering::SeqCst);
    job.slot.store(false, Ordering::SeqCst);
    let _ = job.channel.write_line(&line);
}

/// The reachability wait before the first POST (attack S6; Apple TN3179: the local-network prompt refuses
/// the first connect before the user answers). A plain TCP connect with backoff until it connects, the user
/// cancels, or `exp` passes: bounded by the clock, never by a count of failures.
#[cfg(target_os = "ios")]
fn wait_reachable(url: &str, exp: u64, cancel: &AtomicBool, first_pause: Duration) -> Result<(), PairError> {
    let addr: SocketAddr = url
        .strip_prefix("http://")
        .and_then(|rest| rest.parse().ok())
        .ok_or(PairError::Network)?;
    let mut pause = first_pause;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(PairError::Cancelled);
        }
        if wall_clock() > exp {
            return Err(PairError::Expired);
        }
        if TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
            return Ok(());
        }
        let end = Instant::now() + pause;
        while Instant::now() < end {
            if cancel.load(Ordering::SeqCst) {
                return Err(PairError::Cancelled);
            }
            std::thread::sleep(Duration::from_millis(20).min(pause));
        }
        pause = (pause * 2).min(Duration::from_secs(2));
    }
}

/// The fixed message for a failure of the join itself (never the error's own text).
#[cfg(target_os = "ios")]
fn join_message(error: &PairError, code_shown: bool) -> Failure {
    let text = match error {
        PairError::Expired => "This offer expired. Cancel on your Mac and start a new offer.".to_string(),
        PairError::OfferEnded => format!("Your Mac closed this offer. {CANCEL_ON_MAC}"),
        PairError::Network if !code_shown => "This phone cannot reach your Mac. Check that you are on the same Wi-Fi and that DISCOnect is allowed under Settings, Privacy and Security, Local Network. Then try again.".to_string(),
        PairError::Network => format!("This phone lost your Mac. Check the Wi-Fi and the Local Network permission. {CANCEL_ON_MAC}"),
        PairError::Refused(_) => format!("Your Mac refused this request. {CANCEL_ON_MAC}"),
        // BadTag covers a tag mismatch and a reveal that does not match the commitment: they read the same
        PairError::BadTag | PairError::NonContributory | PairError::CodesDiffer | PairError::NotBound => {
            format!("Your Mac's answer did not check out. {CANCEL_ON_MAC}")
        }
        PairError::BadPayload | PairError::KeyFile(_) | PairError::BadOffer(_) => {
            format!("Your Mac sent something this phone cannot use. {CANCEL_ON_MAC}")
        }
        PairError::Cancelled => "Cancelled. Cancel on your Mac too.".to_string(),
        PairError::Precondition(_) => ALREADY_PAIRED.to_string(),
        PairError::Random | PairError::Landing(_) => format!("Pairing failed. {CANCEL_ON_MAC}"),
    };
    pair_failed(&text)
}

#[cfg(target_os = "ios")]
fn landing_message(error: &PairError, reached: Reached) -> Failure {
    match error {
        PairError::Precondition(_) => pair_failed(ALREADY_PAIRED),
        _ => pair_failed(&match reached {
            Reached::Nothing | Reached::RelayFile => {
                format!("Pairing stopped before the key was saved. {CANCEL_ON_MAC}")
            }
            Reached::KeyFile => "The key was saved, but the first pull did not finish. Open Sync and choose Pull now; if the app asks for the passphrase, enter it.".to_string(),
        }),
    }
}

#[cfg(target_os = "ios")]
fn run_join(job: &JoinJob) -> Outcome {
    let exp = job.joiner.offer().exp;
    let fail = |error: &PairError, shown: bool| Outcome::Failed {
        failure: join_message(error, shown),
        drop_joiner: matches!(error, PairError::Cancelled | PairError::Expired),
    };
    if let Err(error) = wait_reachable(&job.offer_url, exp, &job.ctl.cancel, job.hooks.reach_backoff) {
        return fail(&error, false);
    }
    let code_shown = AtomicBool::new(false);
    let channel = Arc::clone(&job.channel);
    let mut on_sas = |code: &str| {
        // the code event is written under the control lock and only if no cancel was answered: a cancel that
        // raced the offerer's `202` gets "aborted" and then no code (12-F row 3 review, S1)
        let state = lock(&job.ctl.state);
        if job.ctl.cancel.load(Ordering::SeqCst) {
            return;
        }
        code_shown.store(true, Ordering::SeqCst);
        // the one serve line that carries a six-digit code (12-F M3; serve-protocol.md's written exception)
        let _ = channel.write_line(&event_line(&json!({"event": "pair", "phase": "code", "code": code})));
        drop(state);
    };
    let joined = match job.joiner.join(&mut on_sas, &job.ctl.cancel) {
        Ok(joined) => joined,
        Err(error) => return fail(&error, code_shown.load(Ordering::SeqCst)),
    };
    // release gate: a cancel that was answered "aborted" wins over a payload that opened a moment later
    {
        let mut state = lock(&job.ctl.state);
        if job.ctl.cancel.load(Ordering::SeqCst) {
            return fail(&PairError::Cancelled, true);
        }
        state.released = true;
        // `key.lock` ran before the release: the wait is a no from the start
        if job.hub.revoked.load(Ordering::SeqCst) {
            state.over = true;
        }
    }
    let _ = job.channel.write_line(&event_line(&json!({"event": "pair", "phase": "released"})));
    if !wait_decision(&job.ctl, job.hooks.land_wait) {
        return Outcome::Failed { failure: pair_failed("Not paired. Cancel on your Mac too."), drop_joiner: true };
    }
    land(job, &joined)
}

/// True when a wait that began with `limit` is over on the monotonic clock *or* on the wall clock, whichever
/// ends first (Darwin's monotonic clock stops while the phone sleeps).
#[cfg(any(target_os = "ios", test))]
fn wait_expired(mono_end: Instant, wall_end: Option<SystemTime>, now_mono: Instant, now_wall: SystemTime) -> bool {
    now_mono >= mono_end || wall_end.is_some_and(|end| now_wall >= end)
}

/// Wait for `pair.land`: true for a yes. A no, the session's end, `key.lock` or the wait running out is a no;
/// on the wait running out `over` is set, so a `pair.land` just after it is refused instead of "landing".
#[cfg(target_os = "ios")]
fn wait_decision(ctl: &JoinCtl, limit: Duration) -> bool {
    let mono_end = Instant::now() + limit;
    let wall_end = SystemTime::now().checked_add(limit);
    let mut state = lock(&ctl.state);
    loop {
        if let Some(decision) = state.decision {
            return decision;
        }
        let now = Instant::now();
        if state.over {
            return false;
        }
        if wait_expired(mono_end, wall_end, now, SystemTime::now()) {
            state.over = true;
            return false;
        }
        // wake at least every second: the wall clock is looked at again each time
        let slice = (mono_end - now).min(Duration::from_secs(1));
        state = ctl
            .wake
            .wait_timeout(state, slice)
            .map(|(guard, _)| guard)
            .unwrap_or_else(|poisoned| poisoned.into_inner().0);
    }
}

#[cfg(target_os = "ios")]
fn land(job: &JoinJob, joined: &Joined) -> Outcome {
    let relay_file = crate::home::relay_config_beside(&job.db_path);
    let key_path = crate::keys::key_path_for(&job.db_path);
    let mut reached = Reached::Nothing;
    let mut protected: Option<bool> = None;
    // `landing` goes up before the first write and comes down in `take_handed` (success) or on failure
    job.hub.landing.store(true, Ordering::SeqCst);
    let emit = |phase: &str| {
        let _ = job.channel.write_line(&sync_event("pair", phase, "done", None));
    };
    let result = pair_client::land_with(joined, &job.db_path, &relay_file, &mut |step| {
        match step {
            LandStep::RelayFile => {
                reached = Reached::RelayFile;
                emit("relay_file");
            }
            LandStep::KeyFile => {
                reached = Reached::KeyFile;
                protected = after_key_file(&key_path);
                emit("key_file");
            }
            LandStep::Store => emit("store"),
            LandStep::Pull => emit("pull"),
        }
        if !job.hooks.step_pause.is_zero() {
            std::thread::sleep(job.hooks.step_pause);
        }
        if job.hooks.fail_after == Some(step) {
            return Err(PairError::Landing(String::new()));
        }
        Ok(())
    });
    match result {
        Ok(pulled) => {
            let counts = json!({
                "applied": pulled.applied.len(),
                "rejected": pulled.rejected.len(),
                "records_new": pulled.records_new,
                "records_duplicate": pulled.records_duplicate,
                "records_invalid": pulled.records_invalid,
                "conflicts": pulled.conflicts,
                "ranges_new": pulled.ranges_new,
                "records_repaired": pulled.records_repaired,
                "records_kept": pulled.records_kept,
                "gaps": pulled.gaps.len(),
                "status": pulled.status,
            });
            // the hand-back: master and unlocked state to the session in one step (see JoinHub); after a
            // `key.lock` the master is dropped here instead and the phone stays paired and locked
            job.hub.hand_back(&joined.master);
            Outcome::Landed(json!({"state": "landed", "pull": counts, "key_file_protected": protected}))
        }
        Err(error) => Outcome::Failed { failure: landing_message(&error, reached), drop_joiner: true },
    }
}

/// The hook after `LandStep::KeyFile`: read the key file's protection class back on a device and re-apply
/// class A when it is not set. Never an error. Returns what the platform reported (`Some(true)` for class A).
/// The simulator reports no classes (12-D measured), so it answers `None` (unknown) there.
#[cfg(all(target_os = "ios", not(target_abi = "sim")))]
fn after_key_file(key_path: &Path) -> Option<bool> {
    Some(pair_client::verify_class_a(key_path))
}

#[cfg(all(target_os = "ios", target_abi = "sim"))]
fn after_key_file(_key_path: &Path) -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> IpAddr {
        IpAddr::V4(text.parse().expect("v4"))
    }

    fn v6(text: &str) -> IpAddr {
        IpAddr::V6(text.parse().expect("v6"))
    }

    fn iface(addr: IpAddr, prefix: u8) -> Iface {
        Iface { addr, prefix }
    }

    #[test]
    fn stage_one_refuses_every_class_that_is_never_a_pairing_address() {
        for text in [
            "0.0.0.0", "0.1.2.3", "255.255.255.255", "224.0.0.1", "239.255.255.250", "240.0.0.1", "254.1.1.1",
            "169.254.0.1", "169.254.169.254",
        ] {
            assert!(never_a_pairing_address(v4(text)), "{text}");
        }
        for text in ["::", "ff02::1", "ff00::", "fe80::1", "febf::1", "::ffff:0.0.0.0", "::ffff:169.254.1.1", "::ffff:224.0.0.1"] {
            assert!(never_a_pairing_address(v6(text)), "{text}");
        }
        for text in ["127.0.0.1", "10.0.0.5", "192.168.1.20", "172.16.0.1", "100.64.0.1", "8.8.8.8", "169.253.1.1", "223.255.255.255"] {
            assert!(!never_a_pairing_address(v4(text)), "{text}");
        }
        for text in ["::1", "fd00::5", "2001:4860:4860::8888", "fec0::1", "::ffff:192.168.1.2"] {
            assert!(!never_a_pairing_address(v6(text)), "{text}");
        }
    }

    #[test]
    fn the_host_of_an_offer_url_is_an_ip_or_nothing() {
        assert_eq!(offer_ip("http://192.168.1.20:24816"), Some(v4("192.168.1.20")));
        assert_eq!(offer_ip("http://[fd00::5]:24816"), Some(v6("fd00::5")));
        assert_eq!(offer_ip("http://mac.local:24816"), None);
    }

    #[test]
    fn stage_two_classes_with_a_fake_interface_list() {
        let wifi4 = iface(v4("203.0.113.40"), 24); // a globally routable range on-link (documentation net)
        let wifi6 = iface(v6("2001:db8:1:2::40"), 64);
        let list = [wifi4, wifi6, iface(v4("127.0.0.1"), 8), iface(v4("0.0.0.0"), 0)];
        // private ranges pass with no interface at all
        for text in ["10.0.0.1", "172.16.5.5", "172.31.255.255", "192.168.0.9", "100.64.0.1", "100.127.255.254"] {
            assert!(reachable_class(v4(text), false, &[]), "{text}");
        }
        for text in ["fc00::1", "fd12:3456::9"] {
            assert!(reachable_class(v6(text), false, &[]), "{text}");
        }
        // just outside the private ranges and not on-link: refused
        for text in ["172.32.0.1", "172.15.255.255", "100.63.255.255", "100.128.0.1", "11.0.0.1", "8.8.8.8", "193.168.0.1"] {
            assert!(!reachable_class(v4(text), false, &list), "{text}");
        }
        for text in ["2001:4860:4860::8888", "fe00::1", "2001:db8:1:3::1"] {
            assert!(!reachable_class(v6(text), false, &list), "{text}");
        }
        // on-link: inside the subnet of an up interface, by its mask (IPv4 /24 and IPv6 /64)
        assert!(reachable_class(v4("203.0.113.1"), false, &list));
        assert!(reachable_class(v4("203.0.113.254"), false, &list));
        assert!(!reachable_class(v4("203.0.114.1"), false, &list));
        assert!(!reachable_class(v4("203.0.112.255"), false, &list));
        assert!(reachable_class(v6("2001:db8:1:2::1"), false, &list));
        assert!(reachable_class(v6("2001:db8:1:2:ffff:ffff:ffff:ffff"), false, &list));
        assert!(!reachable_class(v6("2001:db8:1:3::1"), false, &list));
        // other masks: /20 and /17 (v4), /48 (v6), /32 and /128 edges
        assert!(on_link(v4("198.51.111.255"), &[iface(v4("198.51.96.7"), 20)]));
        assert!(!on_link(v4("198.51.112.0"), &[iface(v4("198.51.96.7"), 20)]));
        assert!(on_link(v4("198.51.127.255"), &[iface(v4("198.51.0.9"), 17)]));
        assert!(!on_link(v4("198.51.128.0"), &[iface(v4("198.51.0.9"), 17)]));
        assert!(on_link(v4("198.51.100.200"), &[iface(v4("198.51.0.9"), 16)]));
        assert!(on_link(v4("198.51.100.7"), &[iface(v4("198.51.100.7"), 32)]));
        assert!(!on_link(v4("198.51.100.8"), &[iface(v4("198.51.100.7"), 32)]));
        assert!(on_link(v6("2001:db8:aa:ffff::1"), &[iface(v6("2001:db8:aa::1"), 48)]));
        assert!(!on_link(v6("2001:db8:ab::1"), &[iface(v6("2001:db8:aa::1"), 48)]));
        assert!(on_link(v6("2001:db8::7"), &[iface(v6("2001:db8::7"), 128)]));
        assert!(!on_link(v6("2001:db8::8"), &[iface(v6("2001:db8::7"), 128)]));
        // families never mix, and a prefix of 0 (or one past the width) is on-link to nothing
        assert!(!on_link(v4("203.0.113.1"), &[iface(v6("2001:db8:1:2::40"), 64)]));
        assert!(!on_link(v6("2001:db8:1:2::1"), &[iface(v4("203.0.113.40"), 24)]));
        assert!(!on_link(v4("8.8.8.8"), &[iface(v4("10.0.0.2"), 0)]));
        assert!(!on_link(v4("8.8.8.8"), &[iface(v4("8.8.8.1"), 33)]));
        // an IPv4-mapped IPv6 address is judged as its IPv4 address
        assert!(reachable_class(v6("::ffff:192.168.1.2"), false, &[]));
        assert!(!reachable_class(v6("::ffff:8.8.8.8"), false, &list));
        // loopback only where the build allows it, whatever the list says
        assert!(!reachable_class(v4("127.0.0.1"), false, &list));
        assert!(!reachable_class(v6("::1"), false, &[iface(v6("::1"), 128)]));
        assert!(reachable_class(v4("127.0.0.1"), true, &[]));
        assert!(reachable_class(v6("::1"), true, &[]));
        assert!(reachable_class(v4("127.5.5.5"), true, &[]));
    }

    #[test]
    fn the_landing_wait_ends_on_whichever_clock_ends_first() {
        let (mono, wall) = (Instant::now(), SystemTime::now());
        let ten = Duration::from_secs(600);
        let (mono_end, wall_end) = (mono + ten, wall.checked_add(ten));
        // neither clock is there yet
        assert!(!wait_expired(mono_end, wall_end, mono + Duration::from_secs(1), wall + Duration::from_secs(1)));
        // the monotonic clock stopped (sleep) but the wall clock moved on: over
        assert!(wait_expired(mono_end, wall_end, mono + Duration::from_secs(1), wall + ten));
        // the wall clock was set back but the monotonic one ran out: over
        assert!(wait_expired(mono_end, wall_end, mono_end, wall));
        // no wall deadline (an overflow): the monotonic one decides alone
        assert!(!wait_expired(mono_end, None, mono, wall + ten));
    }

    #[cfg(target_os = "ios")]
    #[test]
    fn the_phone_lists_its_loopback_interface() {
        let list = up_interfaces();
        assert!(list.iter().any(|i| i.addr == v4("127.0.0.1") && i.prefix == 8), "{list:?}");
    }
}
