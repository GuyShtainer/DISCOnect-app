// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 12-E slice 2: the joiner. [`join`] runs the client side of the pairing dance against an offerer
//! (ADR 0011); [`land`] puts what it returned on disk in a crash-safe order; [`check_landing_site`] is
//! the refusal that runs before any request. The offerer is `relay::pair_routes`.
//!
//! The joiner shows the short code only after the offerer's tag verified (the offerer proved it bound
//! *this* joiner's key). Nothing here prints; the caller shows the code through a callback.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::canon;
use crate::keys::{self, Secret32};
use crate::pair::{
    self, JOIN_BODY_LEN, Keys, OFFERER_TAG_LEN, Offer, PairError, TRANSCRIPT_LEN, sas, sas_text,
};
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

/// Join `offer_text`: POST the joiner key and tag, verify the offerer's tag, call `on_sas` with the six
/// digits (only then), wait for the release, open the payload and check the key file against the master.
/// `cancel` ends the wait. Nothing is written anywhere.
pub fn join(
    offer_text: &str,
    on_sas: &mut dyn FnMut(&str),
    cancel: &AtomicBool,
) -> Result<Joined, PairError> {
    let offer = Offer::parse(offer_text.trim())?;
    if wall_clock() > offer.exp {
        return Err(PairError::Expired);
    }
    let (secret, joiner_pub) = pair::ephemeral()?;
    let shared = pair::dh(&secret, &offer.pub_key)?;
    let transcript: [u8; TRANSCRIPT_LEN] =
        pair::transcript(&offer.pub_key, &joiner_pub, &offer.id, offer.exp);
    let keys = Keys::derive(&shared, &offer.s, &transcript);
    let mut body = [0u8; JOIN_BODY_LEN];
    body[..32].copy_from_slice(&joiner_pub);
    body[32..].copy_from_slice(&pair::joiner_tag(&keys));

    let agent = agent();
    let route = format!("{}{PAIR}/{}", offer.url, hex::encode(offer.id));
    let response = agent
        .post(&route)
        .header("Content-Type", "application/octet-stream")
        .send(&body[..])
        .map_err(|_| PairError::Network)?;
    let (status, tag) = finish(response, OFFERER_TAG_LEN as u64 + 1)?;
    match status {
        202 => {}
        410 => return Err(PairError::OfferEnded),
        other => return Err(PairError::Refused(other)),
    }
    // a forged or empty 202 shows no code
    if tag.len() != OFFERER_TAG_LEN {
        return Err(PairError::BadTag);
    }
    pair::verify_offerer_tag(&keys, &tag)?;
    on_sas(&sas_text(sas(&keys)));

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
    let (master, key_file_bytes) = pair::open_payload(&keys, &transcript, &sealed)?;
    let parsed = keys::parse_key_file(&key_file_bytes)
        .map_err(|_| PairError::KeyFile("not a usable key file"))?;
    if keys::key_id_for(&master) != parsed.key_id {
        return Err(PairError::KeyFile("its key id is not the master's"));
    }
    Ok(Joined {
        master,
        key_file_bytes,
        url: offer.url,
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
    if let Some(parent) = relay_file.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(io("relay file"))?;
    }
    std::fs::write(relay_file, relay_file_text(&joined.url)).map_err(io("relay file"))?;
    hook(LandStep::RelayFile)?;

    // (2) the key file, verbatim and atomic: the commit point
    write_atomic(&key_path, &joined.key_file_bytes).map_err(io("key file"))?;
    hook(LandStep::KeyFile)?;

    // from here on a failure leaves a key file: a `sync pull` with the passphrase finishes the job
    let left = |what: &str| {
        PairError::Landing(format!(
            "{what}; the key file is in place: finish with 'sync pull' using the passphrase"
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

/// Temp file beside `path` (0600), fsync, rename, fsync the directory; a missing parent is created 0700.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    if !parent.exists() {
        std::fs::create_dir_all(&parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))?;
        }
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
