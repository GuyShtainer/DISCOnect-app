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
//! [`Joiner`] per SHA-256 of the offer *text*) and the master hand-back (see [`JoinHub`]).
//!
//! Only an iOS build runs the worker; every other core refuses after the same prefix.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![cfg_attr(not(target_os = "ios"), allow(dead_code))]

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Call, Channel, Failure, Json, Session, result_line, sync_event};
use crate::keys::Secret32;
use crate::pair::{Offer, PairError};
use crate::pair_client::{self, Joined, Joiner, LandStep};
use crate::relay::lan::wall_clock;
use crate::wirejson;

/// The longest offer text `pair.join` reads. A real offer is about 500 bytes (the seven-key object in
/// base64url, an IPv6 address being the longest URL); anything above this is not one.
pub const MAX_OFFER_TEXT: usize = 1024;
/// An offerer sets `exp = now + 900`; the phone allows the relay's own 300 s clock window on top.
const EXP_AHEAD_MAX: u64 = 900 + 300;
/// How far past `exp` the phone's clock may be before the offer is refused as expired.
const EXP_TOLERANCE: u64 = 300;
/// Joiners kept at once (one per offer text); the soonest to expire goes first.
const MAX_JOINERS: usize = 4;

const CLOCK_EXPIRED: &str = "This offer expired by this phone's clock. Check the date and time.";
const CLOCK_AHEAD: &str = "This offer is too far ahead of this phone's clock. Check the date and time.";
const ALREADY_PAIRED: &str = "This phone is already paired";
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
    /// The session ended: wake the landing wait with a no.
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
pub struct JoinHub {
    active: Mutex<Option<Arc<JoinCtl>>>,
    joiners: Mutex<Vec<([u8; 32], Arc<Joiner>)>>,
    handed: Mutex<Option<Secret32>>,
    landing: AtomicBool,
    hooks: Mutex<JoinHooks>,
}

impl JoinHub {
    pub fn new() -> JoinHub {
        JoinHub {
            active: Mutex::new(None),
            joiners: Mutex::new(Vec::new()),
            handed: Mutex::new(None),
            landing: AtomicBool::new(false),
            hooks: Mutex::new(JoinHooks::default()),
        }
    }

    pub fn landing(&self) -> bool {
        self.landing.load(Ordering::SeqCst)
    }

    pub fn set_hooks(&self, hooks: JoinHooks) {
        *lock(&self.hooks) = hooks;
    }

    /// The master the worker handed back, once. Clears `landing`: the master is now the session's.
    pub fn take_handed(&self) -> Option<Secret32> {
        let master = lock(&self.handed).take();
        if master.is_some() {
            self.landing.store(false, Ordering::SeqCst);
        }
        master
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

    fn joiner_for(&self, text: &str, make: impl Fn() -> Result<Joiner, PairError>) -> Result<([u8; 32], Arc<Joiner>), PairError> {
        let key = text_key(text);
        let mut joiners = lock(&self.joiners);
        let now = wall_clock();
        joiners.retain(|(_, j)| j.offer().exp.saturating_add(EXP_TOLERANCE) >= now);
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

/// SHA-256 of the offer text (trimmed): the joiner map's key, never the offer id.
fn text_key(text: &str) -> [u8; 32] {
    let digest = Sha256::digest(text.trim().as_bytes());
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

/// A URL host that is an IP literal: four dotted decimals, or a bracketed IPv6 address. The URL itself was
/// checked against the kb/24 grammar by `Offer::parse`, so anything else here is a hostname.
fn host_is_ip_literal(url: &str) -> bool {
    let host = url
        .strip_prefix("http://")
        .and_then(|rest| rest.rsplit_once(':'))
        .map_or("", |(host, _)| host);
    host.starts_with('[') || (!host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

/// The prefix of `pair.join`, in order, before any network call (and so before a key is drawn): the shape,
/// an IP-literal host, `exp` not too far ahead, the expiry by this phone's clock, the landing site. The same
/// order and the same messages as the Python twin (`serve.py` `pair_join`).
pub fn join_prefix(text: &str, db: &Path) -> Result<Offer, Failure> {
    prefix_at(text, db, wall_clock())
}

fn prefix_at(text: &str, db: &Path, now: u64) -> Result<Offer, Failure> {
    let text = text.trim();
    if text.len() > MAX_OFFER_TEXT {
        return Err(bad("that is not a pairing offer"));
    }
    let offer = Offer::parse(text).map_err(|_| bad("that is not a pairing offer"))?;
    if !host_is_ip_literal(&offer.url) {
        return Err(bad("the offer's address must be an IP address, not a name"));
    }
    if offer.exp > now.saturating_add(EXP_AHEAD_MAX) {
        return Err(pair_failed(CLOCK_AHEAD));
    }
    if now > offer.exp.saturating_add(EXP_TOLERANCE) {
        return Err(pair_failed(CLOCK_EXPIRED));
    }
    pair_client::check_landing_site(db, &crate::home::relay_config_beside(db), &offer.url)
        .map_err(|_| pair_failed(ALREADY_PAIRED))?;
    Ok(offer)
}

/// `pair.join`. A phone-only method: any other core answers `unsupported_transport` after the prefix.
pub(super) fn pair_join(session: &mut Session, call: &Call) -> Result<(), Failure> {
    let text = offer_param(call)?;
    let offer = join_prefix(&text, &session.db_path)?;
    if cfg!(not(target_os = "ios")) {
        return Err(Failure::serve("unsupported_transport", "this core is not a phone; it does not join a pairing"));
    }
    let hub = Arc::clone(&session.join);
    if session
        .import_slot
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(Failure::serve("busy", "an import or a sync is already running"));
    }
    let slot = Arc::clone(&session.import_slot);
    let release = |failure: Failure| {
        slot.store(false, Ordering::SeqCst);
        failure
    };
    let (key, joiner) = hub
        .joiner_for(&text, || Joiner::new(&text))
        .map_err(|error| release(match error {
            PairError::Expired => pair_failed(CLOCK_EXPIRED),
            _ => Failure::serve("internal", "cannot start the pairing"),
        }))?;
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
    if cfg!(not(target_os = "ios")) {
        return Err(Failure::serve("unsupported_transport", "this core is not a phone; it does not join a pairing"));
    }
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

/// `pair.cancel` on the phone: only the joiner's cancel flag, never the relay's `serving::cancel`.
/// Before the payload opens: cancelled, nothing written. After: refused, landing continues.
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
    Ok(json!({"state": "aborted"}))
}

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
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reached {
    Nothing,
    RelayFile,
    KeyFile,
}

enum Outcome {
    Landed(Value),
    Failed { failure: Failure, drop_joiner: bool },
}

fn event_line(value: &Value) -> String {
    let mut line = String::new();
    wirejson::write_value(&mut line, value);
    line
}

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
    job.slot.store(false, Ordering::SeqCst);
    let _ = job.channel.write_line(&line);
}

/// The reachability wait before the first POST (attack S6; Apple TN3179: the local-network prompt refuses
/// the first connect before the user answers). A plain TCP connect with backoff until it connects, the user
/// cancels, or `exp` passes: bounded by the clock, never by a count of failures.
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
        code_shown.store(true, Ordering::SeqCst);
        // the one serve line that carries a six-digit code (12-F M3; serve-protocol.md's written exception)
        let _ = channel.write_line(&event_line(&json!({"event": "pair", "phase": "code", "code": code})));
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
    }
    let _ = job.channel.write_line(&event_line(&json!({"event": "pair", "phase": "released"})));
    if !wait_decision(&job.ctl, job.hooks.land_wait) {
        return Outcome::Failed { failure: pair_failed("Not paired. Cancel on your Mac too."), drop_joiner: true };
    }
    land(job, &joined)
}

/// Wait for `pair.land`: true for a yes. A no, the session's end or the wait running out is a no.
fn wait_decision(ctl: &JoinCtl, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    let mut state = lock(&ctl.state);
    loop {
        if let Some(decision) = state.decision {
            return decision;
        }
        let now = Instant::now();
        if state.over || now >= end {
            return false;
        }
        state = ctl
            .wake
            .wait_timeout(state, end - now)
            .map(|(guard, _)| guard)
            .unwrap_or_else(|poisoned| poisoned.into_inner().0);
    }
}

fn land(job: &JoinJob, joined: &Joined) -> Outcome {
    let relay_file = crate::home::relay_config_beside(&job.db_path);
    let key_path = crate::keys::key_path_for(&job.db_path);
    let mut reached = Reached::Nothing;
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
                after_key_file(&key_path);
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
            // the hand-back: master and unlocked state to the session in one step (see JoinHub)
            *lock(&job.hub.handed) = Some(joined.master.clone());
            Outcome::Landed(json!({"state": "landed", "pull": counts}))
        }
        Err(error) => Outcome::Failed { failure: landing_message(&error, reached), drop_joiner: true },
    }
}

/// The hook after `LandStep::KeyFile`: read the key file's protection class back on a device and re-apply
/// class A when it is not set. Never an error. The simulator reports no classes (12-D measured), so it does
/// nothing there.
#[cfg(all(target_os = "ios", not(target_abi = "sim")))]
fn after_key_file(key_path: &Path) {
    let _ = pair_client::verify_class_a(key_path);
}

#[cfg(not(all(target_os = "ios", not(target_abi = "sim"))))]
fn after_key_file(_key_path: &Path) {}
