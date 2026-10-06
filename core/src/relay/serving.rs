// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay as the desktop app runs it (pitch 7b-2, `docs/relay-protocol.md` "Serve mode"): at most one
//! LAN server per serve session, an offer that comes and goes on it, and the threads that watch both.
//! `serve.rs` owns the protocol (parameters, error shapes, the worker that pushes the store); this module
//! owns the state machine and never learns a protocol id.
//!
//! * **Lifetime of the server.** With `keep` off the server lives until the offer's `exp` or an explicit
//!   "stop" once the offer is over: the joiner's first pull comes from the same URL right after the
//!   payload's `200`, so delivery must not end serving. It stops at once only on abort, cancel or
//!   expiry, after a short linger so the joiner reads `410` rather than a refused connection. With `keep`
//!   on it lives until `relay.serve {"on": false}` or the session ends.
//! * **Address watcher.** A server is bound to one address the user picked from a fresh list; if that
//!   address leaves the machine (a laptop that changed networks) the server stops and says so.
//! * **Locks.** `RelayState` before the server's offer slot before `PairShared`; the `Events` lock of an
//!   offer is taken before `PairShared` and never while `RelayState` is held for a wait.
//!   [`LanServer::stop`] (up to 5 s) always runs outside the `RelayState` lock, behind `stopping`.
//! * **Privacy.** Nothing here emits a SAS, a joiner key, a tag or a peer address; the server's logger
//!   is a no-op.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::lan::wall_clock;
use super::lan_server::{Limits, LanServer, Logger};
use super::pair_routes::{PairHandle, PairOffer, PairState};
use crate::keys::Secret32;
use crate::pair::{EXPIRY_S, PairError};
use crate::wirejson;

/// The port `relay.addresses` suggests when this session never served one (kb/24, born 2026-10-06).
pub const DEFAULT_RELAY_PORT: u16 = 24816;

/// How long the server keeps answering `410` after an offer ended by abort, cancel or expiry.
pub const LINGER: Duration = Duration::from_secs(2);
/// How often the address watcher looks at the machine's addresses.
pub const ADDRESS_CHECK: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(50);
const NAP: Duration = Duration::from_millis(25);

/// Writes one already-encoded protocol line (an event).
pub type Emit = Arc<dyn Fn(String) + Send + Sync>;
/// The addresses currently assigned to this machine (loopback included).
pub type AddressList = Arc<dyn Fn() -> Vec<IpAddr> + Send + Sync>;

/// Timing and address-list knobs; the defaults are the shipped behaviour, tests shorten them
/// (a `Session` hook like `hold_next_import`, never an environment variable).
#[derive(Clone)]
pub struct Hooks {
    pub linger: Duration,
    /// Seconds an offer lives (default [`EXPIRY_S`]); only shorter values are honoured.
    pub offer_ttl: Option<u64>,
    pub address_check: Duration,
    pub addresses: AddressList,
}

impl Default for Hooks {
    fn default() -> Hooks {
        Hooks {
            linger: LINGER,
            offer_ttl: None,
            address_check: ADDRESS_CHECK,
            addresses: Arc::new(current_ips),
        }
    }
}

/// A refusal with its protocol code; `serve.rs` turns it into a `Failure`.
#[derive(Debug)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

fn refuse(code: &'static str, message: &str) -> Refusal {
    Refusal {
        code,
        message: message.to_string(),
    }
}

struct Running {
    server: LanServer,
    id: u64,
    addr: SocketAddr,
}

/// What was already said about one offer (each transition is emitted once).
#[derive(Default)]
struct Events {
    bound: bool,
    delivered: bool,
    ended: bool,
}

struct OfferRec {
    handle: PairHandle,
    serial: u64,
    events: Arc<Mutex<Events>>,
}

/// Everything about the relay that one serve session holds (process memory only).
pub struct RelayState {
    server: Option<Running>,
    keep: bool,
    offer: Option<OfferRec>,
    /// A `pair.offer` is pushing: the offer is reserved, not yet attached.
    reserved: bool,
    reserved_cancelled: bool,
    stopping: bool,
    last_port: Option<u16>,
    /// The session is over: nothing binds any more.
    ended: bool,
    next_id: u64,
    threads: Vec<JoinHandle<()>>,
}

/// The state shared by the request loop, the workers and the watchers.
pub type Shared = Arc<Mutex<RelayState>>;

pub fn new_state() -> Shared {
    Arc::new(Mutex::new(RelayState {
        server: None,
        keep: false,
        offer: None,
        reserved: false,
        reserved_cancelled: false,
        stopping: false,
        last_port: None,
        ended: false,
        next_id: 1,
        threads: Vec::new(),
    }))
}

fn lock(shared: &Shared) -> MutexGuard<'_, RelayState> {
    shared.lock().unwrap_or_else(|e| e.into_inner())
}

fn lock_events(events: &Mutex<Events>) -> MutexGuard<'_, Events> {
    events.lock().unwrap_or_else(|e| e.into_inner())
}

/// What the workers and watchers need besides the state.
#[derive(Clone)]
pub struct Env {
    pub shared: Shared,
    pub hooks: Hooks,
    pub emit: Emit,
}

/// The folder served and the master whose account it serves.
pub struct Site {
    pub folder: PathBuf,
    pub master: Secret32,
}

fn emit_event(env: &Env, event: &Value) {
    let mut line = String::new();
    wirejson::write_value(&mut line, event);
    (env.emit)(line);
}

// ---- addresses ----

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// The addresses assigned to this machine right now, up interfaces only, never link-local, never
/// unspecified; loopback is included (the list a bound address is checked against).
pub fn current_ips() -> Vec<IpAddr> {
    let mut found: Vec<IpAddr> = Vec::new();
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        let ip = interface.ip();
        if interface.is_oper_up() && !ip.is_unspecified() && !is_link_local(&ip) && !found.contains(&ip) {
            found.push(ip);
        }
    }
    found
}

/// `relay.addresses`: `{"addresses": [{"ip", "label"}], "port"}`; loopback last. An IPv6 `ip` is the
/// bare address (the caller brackets it in a `listen` or a URL).
pub fn addresses_value(env: &Env) -> Value {
    let mut ips = (env.hooks.addresses)();
    ips.retain(|ip| !ip.is_unspecified() && !is_link_local(ip));
    let (loopback, network): (Vec<IpAddr>, Vec<IpAddr>) = ips.into_iter().partition(IpAddr::is_loopback);
    let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = network.into_iter().partition(IpAddr::is_ipv4);
    let rows: Vec<Value> = v4
        .iter()
        .chain(v6.iter())
        .map(|ip| json!({"ip": ip.to_string(), "label": "this network"}))
        .chain(
            loopback
                .iter()
                .map(|ip| json!({"ip": ip.to_string(), "label": "this Mac only, for testing"})),
        )
        .collect();
    let st = lock(&env.shared);
    let port = st
        .server
        .as_ref()
        .map(|r| r.addr.port())
        .or(st.last_port)
        .unwrap_or(DEFAULT_RELAY_PORT);
    json!({"addresses": rows, "port": port})
}

/// `listen`: an IP literal (IPv4, or IPv6 in brackets) with an explicit port 1..65535, not
/// unspecified, not link-local, no zone id. The error text never repeats the input.
pub fn parse_listen(text: &str) -> Result<SocketAddr, String> {
    let shape = || "listen must be an IP address and a port, like 192.168.1.20:24816".to_string();
    let (host, port, bracketed) = match text.strip_prefix('[') {
        Some(rest) => {
            let (host, port) = rest.split_once("]:").ok_or_else(shape)?;
            (host, port, true)
        }
        None => {
            let (host, port) = text.rsplit_once(':').ok_or_else(shape)?;
            (host, port, false)
        }
    };
    if host.contains('%') {
        return Err("listen cannot carry a zone id or a link-local address".to_string());
    }
    let ip: IpAddr = if bracketed {
        IpAddr::V6(host.parse::<Ipv6Addr>().map_err(|_| shape())?)
    } else {
        IpAddr::V4(host.parse::<Ipv4Addr>().map_err(|_| shape())?)
    };
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && !port.starts_with('0');
    let port: u16 = port
        .parse()
        .ok()
        .filter(|_| port_ok)
        .ok_or_else(|| "listen needs an explicit port from 1 to 65535".to_string())?;
    if ip.is_unspecified() {
        return Err("listen needs a concrete address, not 0.0.0.0".to_string());
    }
    if is_link_local(&ip) {
        return Err("listen cannot carry a zone id or a link-local address".to_string());
    }
    Ok(SocketAddr::new(ip, port))
}

// ---- server ----

fn url_of(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

/// Poll `alive` every few milliseconds for `total`; `false` as soon as it says no.
fn nap(total: Duration, alive: impl Fn() -> bool) -> bool {
    let end = Instant::now() + total;
    loop {
        if !alive() {
            return false;
        }
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(NAP));
    }
}

fn server_alive(shared: &Shared, id: u64) -> bool {
    let st = lock(shared);
    !st.ended && st.server.as_ref().is_some_and(|r| r.id == id)
}

fn offer_alive(shared: &Shared, serial: u64) -> bool {
    let st = lock(shared);
    !st.ended && st.offer.as_ref().is_some_and(|o| o.serial == serial)
}

/// Take the server out of the state (marking the stop); the caller stops it with [`finish_stop`] once
/// it holds no lock.
fn take_server(st: &mut RelayState) -> Option<Running> {
    let taken = st.server.take();
    if taken.is_some() {
        st.stopping = true;
    }
    taken
}

fn finish_stop(shared: &Shared, taken: Option<Running>) {
    if let Some(running) = taken {
        running.server.stop();
        lock(shared).stopping = false;
    }
}

/// Start the server on `listen` if none runs; a running one must serve the same address. Returns
/// whether this call started it.
fn ensure_server(env: &Env, st: &mut RelayState, listen: SocketAddr, site: &Site) -> Result<bool, Refusal> {
    if st.ended {
        return Err(refuse("internal", "the session ended"));
    }
    if st.stopping {
        return Err(refuse("busy", "the relay is stopping; try again in a moment"));
    }
    if let Some(running) = &st.server {
        if running.addr == listen {
            return Ok(false);
        }
        return Err(refuse("bad_params", "the relay already serves another address"));
    }
    let log: Logger = Arc::new(|_, _| {});
    let server = LanServer::start_with(
        &listen.to_string(),
        site.folder.clone(),
        &site.master[..],
        log,
        Limits::default(),
    )
    .map_err(|_| refuse("internal", "cannot listen on that address"))?;
    let addr = server.local_addr();
    let id = st.next_id;
    st.next_id += 1;
    let watcher = spawn_address_watcher(env, id, addr.ip());
    match watcher {
        Ok(handle) => st.threads.push(handle),
        Err(_) => {
            server.stop();
            return Err(refuse("internal", "cannot start the address watcher"));
        }
    }
    st.last_port = Some(addr.port());
    st.server = Some(Running { server, id, addr });
    Ok(true)
}

fn spawn_address_watcher(env: &Env, id: u64, ip: IpAddr) -> std::io::Result<JoinHandle<()>> {
    let env = env.clone();
    std::thread::Builder::new()
        .name("relay-address".into())
        .spawn(move || {
            loop {
                if !nap(env.hooks.address_check, || server_alive(&env.shared, id)) {
                    return;
                }
                if (env.hooks.addresses)().contains(&ip) {
                    continue;
                }
                let taken = {
                    let mut st = lock(&env.shared);
                    if st.ended || st.server.as_ref().is_none_or(|r| r.id != id) {
                        return;
                    }
                    // an open offer dies with its address: its URL leads nowhere now
                    if let Some(offer) = st.offer.take() {
                        offer.handle.abort();
                    }
                    take_server(&mut st)
                };
                emit_event(
                    &env,
                    &json!({"event": "relay", "state": "stopped", "reason": "address_gone"}),
                );
                finish_stop(&env.shared, taken);
                return;
            }
        })
}

/// `relay.serve {"on": true}`: start (or keep) the server on `listen`; `keep` becomes true.
pub fn serve_on(env: &Env, listen: SocketAddr, site: &Site) -> Result<String, Refusal> {
    let mut st = lock(&env.shared);
    ensure_server(env, &mut st, listen, site)?;
    st.keep = true;
    Ok(st.server.as_ref().map(|r| url_of(r.addr)).unwrap_or_default())
}

/// Is an offer still needing the server: reserved, open, bound, or released and not yet fetched.
fn offer_needs_server(st: &RelayState) -> bool {
    if st.reserved {
        return true;
    }
    let Some(offer) = &st.offer else {
        return false;
    };
    match offer.handle.state() {
        PairState::Open | PairState::Bound => true,
        PairState::Released => !offer.handle.wait_delivered(Duration::ZERO),
        PairState::Aborted | PairState::Expired => false,
    }
}

/// `relay.serve {"on": false}`: `keep` becomes false; the server stops unless an offer still needs it.
/// Returns the URL while it still serves.
pub fn serve_off(env: &Env) -> Option<String> {
    let taken = {
        let mut st = lock(&env.shared);
        st.keep = false;
        if st.server.is_none() || offer_needs_server(&st) {
            return st.server.as_ref().map(|r| url_of(r.addr));
        }
        if let Some(offer) = st.offer.take() {
            offer.handle.abort();
        }
        take_server(&mut st)
    };
    finish_stop(&env.shared, taken);
    None
}

/// `sync.status.serving`: null, or `{"url", "keep", "offer": null|"open"|"bound"|"released"}`.
pub fn serving_value(shared: &Shared) -> Value {
    let st = lock(shared);
    let Some(running) = &st.server else {
        return Value::Null;
    };
    let offer = st.offer.as_ref().and_then(|o| match o.handle.state() {
        PairState::Open => Some("open"),
        PairState::Bound => Some("bound"),
        PairState::Released => Some("released"),
        PairState::Aborted | PairState::Expired => None,
    });
    json!({"url": url_of(running.addr), "keep": st.keep, "offer": offer})
}

// ---- offers ----

/// Reserve the offer before the push (`pair.offer` on the request loop): refuses a second offer and a
/// server on another address.
pub fn reserve_offer(env: &Env, listen: SocketAddr) -> Result<(), Refusal> {
    let mut st = lock(&env.shared);
    if st.ended {
        return Err(refuse("internal", "the session ended"));
    }
    if offer_needs_server(&st) {
        return Err(refuse("busy", "an offer is open"));
    }
    if st.server.as_ref().is_some_and(|r| r.addr != listen) {
        return Err(refuse("bad_params", "the relay already serves another address"));
    }
    st.reserved = true;
    st.reserved_cancelled = false;
    Ok(())
}

/// A reservation that never became an offer (the push failed, the slot was busy).
pub fn drop_reservation(env: &Env) {
    let mut st = lock(&env.shared);
    st.reserved = false;
    st.reserved_cancelled = false;
}

/// The offer a finished push turns into: the server is started if none runs, the offer attached and
/// watched. Returns `(offer text, url, expires_at)`.
pub fn finish_offer(env: &Env, listen: SocketAddr, site: &Site) -> Result<(String, String, u64), Refusal> {
    let mut st = lock(&env.shared);
    let cancelled = st.reserved_cancelled;
    st.reserved = false;
    st.reserved_cancelled = false;
    if st.ended {
        return Err(refuse("internal", "the session ended"));
    }
    if cancelled {
        return Err(refuse("pair_failed", "the offer ended"));
    }
    let started = ensure_server(env, &mut st, listen, site)?;
    let Some(addr) = st.server.as_ref().map(|r| r.addr) else {
        return Err(refuse("internal", "cannot listen on that address"));
    };
    let url = url_of(addr);
    let now = match env.hooks.offer_ttl {
        Some(ttl) if ttl < EXPIRY_S => wall_clock().saturating_sub(EXPIRY_S - ttl),
        _ => wall_clock(),
    };
    let (text, handle) = match PairOffer::new_at(&url, now) {
        Ok(made) => made,
        Err(_) => {
            let taken = if started && !st.keep { take_server(&mut st) } else { None };
            drop(st);
            finish_stop(&env.shared, taken);
            return Err(refuse("internal", "cannot make an offer"));
        }
    };
    if let Some(running) = &st.server {
        running.server.attach_offer(handle.shared());
    }
    if let Some(old) = st.offer.take() {
        old.handle.abort();
    }
    let serial = st.next_id;
    st.next_id += 1;
    let events = Arc::new(Mutex::new(Events::default()));
    let expires_at = handle.expires_at();
    let watcher_env = env.clone();
    let (watch_handle, watch_events) = (handle.clone(), Arc::clone(&events));
    let spawned = std::thread::Builder::new()
        .name("relay-pair".into())
        .spawn(move || watch_offer(&watcher_env, serial, &watch_handle, &watch_events));
    match spawned {
        Ok(thread) => st.threads.push(thread),
        Err(_) => {
            handle.abort();
            let taken = if started && !st.keep { take_server(&mut st) } else { None };
            drop(st);
            finish_stop(&env.shared, taken);
            return Err(refuse("internal", "cannot start the offer watcher"));
        }
    }
    st.offer = Some(OfferRec { handle, serial, events });
    Ok((text, url, expires_at))
}

/// Emit `pair` event `state` (with an optional `reason`) unless this offer's life was already told.
/// `end` marks a terminal state.
fn say(env: &Env, events: &mut Events, state: &str, reason: Option<&str>, end: bool) {
    let mut event = json!({"event": "pair", "state": state});
    if let (Some(reason), Some(object)) = (reason, event.as_object_mut()) {
        object.insert("reason".into(), Value::from(reason));
    }
    emit_event(env, &event);
    if end {
        events.ended = true;
    }
}

fn watch_offer(env: &Env, serial: u64, handle: &PairHandle, events: &Mutex<Events>) {
    loop {
        if !nap(POLL, || offer_alive(&env.shared, serial)) {
            return;
        }
        let state = handle.state();
        let delivered = handle.wait_delivered(Duration::ZERO);
        let mut ev = lock_events(events);
        match state {
            PairState::Open => {}
            PairState::Bound | PairState::Released => {
                if !ev.bound {
                    ev.bound = true;
                    say(env, &mut ev, "bound", None, false);
                }
                if delivered && !ev.delivered {
                    ev.delivered = true;
                    say(env, &mut ev, "delivered", None, false);
                }
            }
            PairState::Aborted => {
                if !ev.ended && !ev.delivered {
                    say(env, &mut ev, "aborted", Some("another_device"), true);
                }
                drop(ev);
                end_of_offer(env, serial, true);
                return;
            }
            PairState::Expired => {
                if delivered || ev.delivered {
                    drop(ev);
                    end_of_offer(env, serial, false);
                } else {
                    if !ev.ended {
                        say(env, &mut ev, "expired", None, true);
                    }
                    drop(ev);
                    end_of_offer(env, serial, true);
                }
                return;
            }
        }
    }
}

/// The offer is over (aborted or expired): after the linger (when the joiner may still be asking) the
/// server stops unless the user keeps it.
fn end_of_offer(env: &Env, serial: u64, linger: bool) {
    if linger && !nap(env.hooks.linger, || offer_alive(&env.shared, serial)) {
        return;
    }
    let taken = {
        let mut st = lock(&env.shared);
        if st.ended || st.offer.as_ref().is_none_or(|o| o.serial != serial) || st.keep {
            return;
        }
        take_server(&mut st)
    };
    finish_stop(&env.shared, taken);
}

/// `pair.confirm`: release with the typed digits. Wrong digits abort the offer (the event says why).
pub fn confirm(env: &Env, digits: &str, master: &[u8; 32], key_file_bytes: &[u8]) -> Result<(), Refusal> {
    let (handle, events) = {
        let st = lock(&env.shared);
        match &st.offer {
            Some(offer) => (offer.handle.clone(), Arc::clone(&offer.events)),
            None if st.reserved => return Err(refuse("pair_failed", "no device has answered")),
            None => return Err(refuse("not_found", "there is no offer")),
        }
    };
    // held across the release: the watcher cannot name the abort before this call knows its reason
    let mut ev = lock_events(&events);
    match handle.release(digits, master, key_file_bytes) {
        Ok(()) => Ok(()),
        Err(PairError::CodesDiffer) => {
            if !ev.ended {
                say(env, &mut ev, "aborted", Some("codes_differ"), true);
            }
            Err(refuse("pair_failed", "the codes differ"))
        }
        Err(PairError::NotBound) => Err(refuse("pair_failed", "no device has answered")),
        Err(PairError::OfferEnded | PairError::Expired) => Err(refuse("pair_failed", "the offer ended")),
        Err(_) => Err(refuse("internal", "unexpected error")),
    }
}

/// `pair.cancel`: end the offer (idempotent). `not_found` when there is none.
pub fn cancel(env: &Env) -> Result<(), Refusal> {
    let (handle, events) = {
        let mut st = lock(&env.shared);
        match &st.offer {
            Some(offer) => (offer.handle.clone(), Arc::clone(&offer.events)),
            None if st.reserved => {
                st.reserved_cancelled = true;
                return Ok(());
            }
            None => return Err(refuse("not_found", "there is no offer to cancel")),
        }
    };
    let mut ev = lock_events(&events);
    let live = matches!(
        handle.state(),
        PairState::Open | PairState::Bound | PairState::Released
    );
    let delivered = handle.wait_delivered(Duration::ZERO);
    if live && !delivered && !ev.ended {
        handle.abort();
        say(env, &mut ev, "aborted", Some("cancelled"), true);
    } else if live {
        // already delivered: the keys are gone with the abort, nothing more to tell
        handle.abort();
    }
    Ok(())
}

/// The session is over: end the offer, stop the server, join the watchers. Runs before the loop waits for
/// the import workers; a worker that has not bound yet will see `ended` and not bind.
pub fn end_session(env: &Env) {
    let (taken, threads) = {
        let mut st = lock(&env.shared);
        st.ended = true;
        if let Some(offer) = st.offer.take() {
            offer.handle.abort();
        }
        (take_server(&mut st), std::mem::take(&mut st.threads))
    };
    finish_stop(&env.shared, taken);
    for thread in threads {
        let _ = thread.join();
    }
}
