// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 12-E slice 2: the joiner. A [`Joiner`] holds one ephemeral key for one offer and [`Joiner::join`]
//! runs the client side of the pairing dance against the offerer (ADR 0011, v2 since 12-G); [`join`] is
//! the one-shot wrapper; [`land`] puts what it returned on disk in a crash-safe order; [`check_landing_site`]
//! is the refusal that runs before any request. The offerer is `relay::pair_routes`.
//!
//! The joiner shows the short code only after the offerer's `202` opened: the right length, a reveal that
//! matches the commitment in the offer, a tag that verifies (the offerer proved it bound *this* joiner's
//! key). A joiner key is drawn once per [`Joiner`], after the offer is in hand, and is never used with any
//! other offer: a retry re-sends the identical body. Nothing here prints; the caller shows the code
//! through a callback.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::canon;
use crate::keys::{self, Secret32};
use crate::pair::{self, JOIN_BODY_LEN, Keys, Offer, PairError, TRANSCRIPT_LEN, sas, sas_text};
use crate::relay::config::{self as relay_cfg, RelayConfig};
use crate::relay::lan::{LanRelay, wall_clock};
use crate::relay::pair_routes::PAIR;
use crate::relay::sync::{self, PullResult};
use crate::store;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the joiner asks whether the offerer released.
const POLL_EVERY: Duration = Duration::from_millis(500);
/// A sealed payload is a master and a key file: far below this.
const MAX_PAYLOAD: u64 = 1024 * 1024;
/// Total tries of the joiner's POST (a reset is retried with the identical body, 500 ms apart).
const POST_ATTEMPTS: u32 = 3;
const POST_RETRY_EVERY: Duration = Duration::from_millis(500);
/// Consecutive failed polls before giving up (a reset between two polls is not the end).
const POLL_FAILURES: u32 = 5;

/// What a successful join hands back: the master (in memory only), the key file bytes verbatim, and
/// the relay URL from the offer.
pub struct Joined {
    pub master: Secret32,
    pub key_file_bytes: Vec<u8>,
    pub url: String,
}

fn agent() -> ureq::Agent {
    // no proxy (a LAN address must never go through one), no redirects, 4xx/5xx are answers
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .proxy(None)
        .max_redirects(0)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build()
        .into()
}

fn finish(mut response: ureq::http::Response<ureq::Body>, limit: u64) -> Result<(u16, Vec<u8>), PairError> {
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|_| PairError::Network)?;
    Ok((status, body))
}

/// Sleep `total`, waking early when `cancel` is set. `true` when cancelled.
fn pause(total: Duration, cancel: &AtomicBool) -> bool {
    let step = Duration::from_millis(50);
    let mut left = total;
    while !left.is_zero() {
        if cancel.load(Ordering::SeqCst) {
            return true;
        }
        let slice = left.min(step);
        std::thread::sleep(slice);
        left -= slice;
    }
    cancel.load(Ordering::SeqCst)
}

/// One joiner key for one offer. Made once per offer text (the key is drawn after the offer, and so its
/// commitment, is in hand); every [`Joiner::join`] on it sends the identical body, so a retry after a lost
/// `202` gets the same `202` back instead of aborting the offerer's slot. The derived keys are zeroized on
/// drop; nothing exports or imports the private key (it is dropped as soon as `K` exists).
pub struct Joiner {
    offer: Offer,
    joiner_pub: [u8; 32],
    keys: Keys,
    transcript: [u8; TRANSCRIPT_LEN],
    body: [u8; JOIN_BODY_LEN],
}

impl Joiner {
    /// Parse `offer_text` (trimmed), refuse an expired offer, draw the key, derive the keys and the body.
    pub fn new(offer_text: &str) -> Result<Joiner, PairError> {
        let offer = Offer::parse(offer_text.trim())?;
        if wall_clock() > offer.exp {
            return Err(PairError::Expired);
        }
        let (secret, joiner_pub) = pair::ephemeral()?;
        let shared = pair::dh(&secret, &offer.pub_key)?;
        drop(secret); // zeroized; only the derived keys are needed from here
        let transcript: [u8; TRANSCRIPT_LEN] =
            pair::transcript(&offer.pub_key, &joiner_pub, &offer.id, offer.exp, &offer.c);
        let keys = Keys::derive(&shared, &offer.s, &transcript);
        let mut body = [0u8; JOIN_BODY_LEN];
        body[..32].copy_from_slice(&joiner_pub);
        body[32..].copy_from_slice(&pair::joiner_tag(&keys));
        let mut offer = offer;
        offer.s = [0u8; 16]; // the secret did its work in K; the joiner keeps url, id, exp and c only
        Ok(Joiner { offer, joiner_pub, keys, transcript, body })
    }

    /// The offer this joiner was made for (`s` zeroed: it is spent once `K` exists).
    pub fn offer(&self) -> &Offer {
        &self.offer
    }

    /// The joiner's public key (the one the offerer binds).
    pub fn joiner_pub(&self) -> [u8; 32] {
        self.joiner_pub
    }

    /// POST the joiner key and tag, open the offerer's reply (length, commitment, tag), call `on_sas` with
    /// the six digits (only then), wait for the release, open the payload and check the key file against
    /// the master. `cancel` ends the wait. Nothing is written anywhere. Calling it again re-sends the same
    /// body.
    pub fn join(&self, on_sas: &mut dyn FnMut(&str), cancel: &AtomicBool) -> Result<Joined, PairError> {
        join_with(&self.offer, &self.keys, &self.transcript, &self.body, on_sas, cancel)
    }
}

/// One-shot: a fresh [`Joiner`] for `offer_text`, joined once (the CLI).
pub fn join(
    offer_text: &str,
    on_sas: &mut dyn FnMut(&str),
    cancel: &AtomicBool,
) -> Result<Joined, PairError> {
    Joiner::new(offer_text)?.join(on_sas, cancel)
}

fn join_with(
    offer: &Offer,
    keys: &Keys,
    transcript: &[u8; TRANSCRIPT_LEN],
    body: &[u8; JOIN_BODY_LEN],
    on_sas: &mut dyn FnMut(&str),
    cancel: &AtomicBool,
) -> Result<Joined, PairError> {
    if wall_clock() > offer.exp {
        return Err(PairError::Expired);
    }
    let agent = agent();
    let route = format!("{}{PAIR}/{}", offer.url, hex::encode(offer.id));
    // the same 64 bytes again after a network error: the offerer answers the same key with the same 202
    let mut attempt = 1;
    let (status, reply) = loop {
        let sent = agent
            .post(&route)
            .header("Content-Type", "application/octet-stream")
            .send(&body[..])
            .map_err(|_| PairError::Network)
            // read well past 64 so a long forged 202 is BadTag (shows no code), not a network error
            .and_then(|r| finish(r, 4096));
        match sent {
            Err(PairError::Network) if attempt < POST_ATTEMPTS => {
                attempt += 1;
                if pause(POST_RETRY_EVERY, cancel) {
                    return Err(PairError::Cancelled);
                }
            }
            other => break other?,
        }
    };
    match status {
        202 => {}
        410 => return Err(PairError::OfferEnded),
        other => return Err(PairError::Refused(other)),
    }
    // a forged, short or empty 202 shows no code: length, commitment, tag, in that order
    let n_o = pair::open_offerer_reply(keys, &offer.c, &reply)?;
    on_sas(&sas_text(sas(keys, &n_o)));

    let payload_url = format!("{route}/payload");
    let mut failures = 0u32;
    let sealed = loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(PairError::Cancelled);
        }
        if wall_clock() > offer.exp {
            return Err(PairError::Expired);
        }
        match agent.get(&payload_url).call().map_err(|_| PairError::Network).and_then(|r| finish(r, MAX_PAYLOAD)) {
            Ok((200, bytes)) => break bytes,
            Ok((202, _)) => failures = 0,
            Ok((410, _)) => return Err(PairError::OfferEnded),
            Ok((other, _)) => return Err(PairError::Refused(other)),
            Err(e) => {
                failures += 1;
                if failures >= POLL_FAILURES {
                    return Err(e);
                }
            }
        }
        if pause(POLL_EVERY, cancel) {
            return Err(PairError::Cancelled);
        }
    };
    let (master, key_file_bytes) = pair::open_payload(keys, transcript, &sealed)?;
    let parsed = keys::parse_key_file(&key_file_bytes)
        .map_err(|_| PairError::KeyFile("not a usable key file"))?;
    if keys::key_id_for(&master) != parsed.key_id {
        return Err(PairError::KeyFile("its key id is not the master's"));
    }
    Ok(Joined {
        master,
        key_file_bytes,
        url: offer.url.clone(),
    })
}

/// `relay.json` content for a LAN relay, in the shape `--remember` writes.
fn relay_file_text(url: &str) -> String {
    let value = canon::Value::Object(vec![(
        "lan".to_string(),
        canon::Value::Str(url.to_string()),
    )]);
    format!("{}\n", canon::dumps_spaced(&value))
}

/// Refuse, before any request, when joining would clobber something: the store exists, its key file
/// (`DISCONECT_KEYS` honoured) or `<keys>.next` exists, `DISCONECT_KEYS` is set at all (one key file
/// path would serve every store), or `relay_file` exists naming something other than `url`.
pub fn check_landing_site(db: &Path, relay_file: &Path, url: &str) -> Result<(), PairError> {
    if std::env::var_os(keys::KEYS_ENV).is_some_and(|v| !v.is_empty()) {
        return Err(PairError::Precondition("DISCONECT_KEYS is set; unset it so the key file lands beside the store"));
    }
    if db.exists() {
        return Err(PairError::Precondition("the store already exists"));
    }
    let key_path = keys::key_path_for(db);
    if key_path.exists() {
        return Err(PairError::Precondition("a key file already exists for this store"));
    }
    if keys::next_path_for(&key_path).exists() {
        return Err(PairError::Precondition("a key rotation is in progress for this store"));
    }
    if relay_file.exists() && relay_cfg::read(relay_file) != Some(RelayConfig::Lan(url.to_string())) {
        return Err(PairError::Precondition("the relay file already exists with other content"));
    }
    Ok(())
}

/// The steps of [`land`], in order; a hook sees each one after it completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandStep {
    RelayFile,
    KeyFile,
    Store,
    Pull,
}

/// [`land`] with a hook called after each step; an `Err` from it stops there (tests inject failures).
pub fn land_with(
    joined: &Joined,
    db: &Path,
    relay_file: &Path,
    hook: &mut dyn FnMut(LandStep) -> Result<(), PairError>,
) -> Result<PullResult, PairError> {
    check_landing_site(db, relay_file, &joined.url)?;
    let key_path = keys::key_path_for(db);
    let io = |what: &'static str| move |_: std::io::Error| PairError::Landing(format!("cannot write the {what}"));

    // (1) the relay file
    write_atomic(relay_file, relay_file_text(&joined.url).as_bytes()).map_err(io("relay file"))?;
    hook(LandStep::RelayFile)?;

    // (2) the key file, verbatim and atomic: the commit point
    write_atomic(&key_path, &joined.key_file_bytes).map_err(io("key file"))?;
    hook(LandStep::KeyFile)?;

    // from here on a failure leaves a key file: a `sync pull` with the passphrase finishes the job
    let left = |what: &str| {
        PairError::Landing(format!(
            "{what}; the key file is in place: finish with `sync pull --relay <the http://host:port in relay.json>` using the passphrase"
        ))
    };
    // (3) the encrypted store, created with the in-memory master
    let opened = store::open_for_write_with(db, "pair", 10.0, Some(&joined.master))
        .map_err(|_| left("cannot create the store"))?;
    hook(LandStep::Store)?;

    // (4) the first pull, in process, with the explicit relay
    let relay = LanRelay::new(&joined.url, &*joined.master).map_err(|_| left("the relay address is unusable"))?;
    let result = sync::pull(opened.conn(), &*joined.master, &relay).map_err(|_| left("the first pull failed"))?;
    hook(LandStep::Pull)?;
    Ok(result)
}

/// Land a join: relay file, key file (the commit point), encrypted store, first pull. See
/// [`check_landing_site`] for what is refused first. No keychain write (macOS binds an item to the
/// program that made it; the caller caches the master through its own path).
pub fn land(joined: &Joined, db: &Path, relay_file: &Path) -> Result<PullResult, PairError> {
    land_with(joined, db, relay_file, &mut |_| Ok(()))
}

/// Temp file beside `path` (0600), fsync, rename, fsync the directory; the parent is created if missing
/// and set to 0700 either way (a failed write leaves no temp file and no half `path`).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    std::fs::create_dir_all(&parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let temp = parent.join(format!(".{name}.tmp{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = (|| {
        let mut file = options.open(&temp)?;
        // iOS only: class A before the first byte, so the class survives the rename (12-F A7, attack S1)
        #[cfg(target_os = "ios")]
        set_class_a(&file);
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
        return written;
    }
    // best effort: some platforms cannot open a directory for sync
    if let Ok(dir) = std::fs::File::open(&parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// `fcntl` commands of `<sys/fcntl.h>` (Darwin) and the class value of `PROTECTION_CLASS_A`
/// (`NSFileProtectionComplete`: unreadable while the phone is locked).
#[cfg(target_os = "ios")]
const F_GETPROTECTIONCLASS: libc::c_int = 63;
#[cfg(target_os = "ios")]
const F_SETPROTECTIONCLASS: libc::c_int = 64;
#[cfg(target_os = "ios")]
const PROTECTION_CLASS_A: libc::c_int = 1;

/// Best effort: set class A on an open file. The result is not an error of the write (the simulator reports no
/// classes); the landing's read-back hook looks at the key file on the device and re-applies.
#[cfg(target_os = "ios")]
fn set_class_a(file: &std::fs::File) {
    use std::os::fd::AsRawFd;
    // SAFETY: `fcntl` on a descriptor this function borrows for the call; the command takes an int argument.
    let _ = unsafe { libc::fcntl(file.as_raw_fd(), F_SETPROTECTIONCLASS, PROTECTION_CLASS_A) };
}

/// The protection class of the file at `path` (`F_GETPROTECTIONCLASS`), `None` when it cannot be read or the
/// platform reports none (the simulator).
#[cfg(target_os = "ios")]
pub fn protection_class(path: &Path) -> Option<i32> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path).ok()?;
    // SAFETY: as in `set_class_a`.
    let class = unsafe { libc::fcntl(file.as_raw_fd(), F_GETPROTECTIONCLASS) };
    (class >= 0).then_some(class)
}

/// Read the class of the file at `path` back; when it is not class A, try once more to set it. Never an error.
/// Returns `true` when the platform reported class A. The simulator reports nothing, so this is `false` there.
#[cfg(target_os = "ios")]
pub fn verify_class_a(path: &Path) -> bool {
    if protection_class(path) == Some(PROTECTION_CLASS_A) {
        return true;
    }
    if let Ok(file) = std::fs::OpenOptions::new().read(true).open(path) {
        set_class_a(&file);
    }
    protection_class(path) == Some(PROTECTION_CLASS_A)
}

#[cfg(test)]
mod write_atomic_tests {
    use super::write_atomic;

    /// The desktop write path is the old one: the same bytes, mode 0600, the parent 0700, no temp file left.
    #[cfg(unix)]
    #[test]
    fn non_ios_write_atomic_keeps_bytes_and_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("inner").join("key.json");
        write_atomic(&target, b"{\"k\":1}\n").expect("write");
        assert_eq!(std::fs::read(&target).expect("read"), b"{\"k\":1}\n");
        let mode = |p: &std::path::Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&target), 0o600);
        assert_eq!(mode(target.parent().expect("parent")), 0o700);
        let names: Vec<_> = std::fs::read_dir(target.parent().expect("parent"))
            .expect("dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names.len(), 1, "no temp file is left behind");
        // overwrite keeps the mode
        write_atomic(&target, b"two").expect("rewrite");
        assert_eq!(std::fs::read(&target).expect("read"), b"two");
        assert_eq!(mode(&target), 0o600);
    }
}
