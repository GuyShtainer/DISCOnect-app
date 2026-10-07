// SPDX-License-Identifier: AGPL-3.0-or-later
//! The phone's half of the relay list (Bet 19d, I5 row 4). On the phone the shell owns the list: a folder the person
//! picked in the Files app is a security-scoped bookmark that only this container can resolve, and it must be resolved
//! (and its scope held) around each call. So the list lives here, not in `relay.json`; the core takes it per call
//! (`sync.run {"relays": [...]}`, the contract of `docs/pitches/19d-relay-list.md`) on since slice 2).
//!
//! * The list is `relays.json` in the app's data folder (mode 0600, flagged out of backups like the key file; Forget
//!   deletes it). Entries are `{id, kind, label, bookmark (base64) | url, added_at, site, last_push_at, last_pull_at}`.
//! * The page never names a path and never sees a bookmark: it gets the list in words (`relays_list`) and the core
//!   refuses a `relays` param from the page (`lib.rs::core_call`, the attack's A6). The param is built here, natively,
//!   on the way to the core ([`injected`]), behind one switch (`lib.rs::RELAYS_INJECT`).
//! * Ids are eight hex digits made here and kept; labels never reach the core. A folder whose bookmark fails to resolve
//!   goes as `unavailable`, not dropped. Nothing is ever listed at the store's own folder. Duplicate detection is the
//!   core's (it compares (dev, inode)); the shell only shows the word the core answers.
//! * The paired Mac (`relay.json {"lan": url}`, which pairing wrote) is adopted as an entry labelled "Your Mac", because
//!   a per-call list replaces the configured one and must therefore carry it.
//!
//! The pure part (the file, the ids, the param, the per-site state) builds and is tested everywhere; the part that
//! talks to UIKit and Foundation is `native`, iOS only.

pub mod native;

use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::Manager;

use crate::sidecar::CoreError;

/// The file beside the store.
pub const FILE: &str = "relays.json";
/// The label the paired Mac gets.
pub const MAC_LABEL: &str = "Your Mac";
/// A label is short text, never a path; longer is cut.
const LABEL_MAX: usize = 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub id: String,
    /// `"folder"` or `"lan"`.
    pub kind: String,
    pub label: String,
    /// A folder's security-scoped bookmark, base64. Never leaves this module.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bookmark: Option<String>,
    /// A LAN relay's `http://host:port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub added_at: u64,
    /// Debug seed only: the bookmark is of a plain folder (no security scope), which a debug build may use.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub debug_unscoped: bool,
    /// The last `sites[]` row the core answered for this entry (a copy of the core's object plus `at`, seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_push_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pull_at: Option<u64>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct Store {
    #[serde(default)]
    pub relays: Vec<Entry>,
    /// The Mac address the person removed on purpose; it is not adopted again from `relay.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_dismissed: Option<String>,
    /// The saved list could not be read and a copy was kept aside; shown on the card until the next change is saved.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unreadable: bool,
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What the page is told when something here fails: a code word the page maps to a sentence.
#[derive(Debug, PartialEq)]
pub struct Refusal(pub &'static str);

// ---- base64 (standard alphabet, padded): two dozen lines instead of a crate ----
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let t = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(t.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in t.bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

// ---- the file ----

/// The list, or an empty one when there is none. A file that exists but cannot be read is never overwritten silently:
/// it is kept aside as `relays.json.bad-<unix ts>` (mode 0600), an empty list takes its place and `unreadable` says so
/// until the next change is saved.
pub fn load(dir: &Path) -> Store {
    let path = dir.join(FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|_| keep_aside(dir)),
        Err(_) if path.exists() => keep_aside(dir),
        Err(_) => Store::default(),
    }
}

fn keep_aside(dir: &Path) -> Store {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(FILE);
    let aside = dir.join(format!("{FILE}.bad-{}", now_secs()));
    if std::fs::rename(&path, &aside).is_ok() {
        let _ = std::fs::set_permissions(&aside, std::fs::Permissions::from_mode(0o600));
        #[cfg(target_os = "ios")]
        let _ = crate::ios::exclude_from_backup(&aside);
    }
    let store = Store { unreadable: true, ..Store::default() };
    let _ = save(dir, &store);
    store
}

/// Save a change the person made: the "could not be read" line goes with it.
pub fn commit(dir: &Path, store: &mut Store) -> Result<(), Refusal> {
    store.unreadable = false;
    save(dir, store)
}

/// Write the list: a temp file at mode 0600, renamed over the old one, then flagged out of backups.
pub fn save(dir: &Path, store: &Store) -> Result<(), Refusal> {
    use std::os::unix::fs::OpenOptionsExt;
    let text = serde_json::to_string_pretty(store).map_err(|_| Refusal("write_failed"))?;
    let tmp = dir.join(format!(".{FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|_| Refusal("write_failed"))?;
    file.write_all(text.as_bytes()).and_then(|_| file.sync_all()).map_err(|_| Refusal("write_failed"))?;
    drop(file);
    let target = dir.join(FILE);
    std::fs::rename(&tmp, &target).map_err(|_| Refusal("write_failed"))?;
    #[cfg(target_os = "ios")]
    let _ = crate::ios::exclude_from_backup(&target);
    Ok(())
}

/// Eight hex digits from the OS, not already in the list.
pub fn new_id(store: &Store) -> Result<String, Refusal> {
    use std::io::Read;
    let mut urandom = std::fs::File::open("/dev/urandom").map_err(|_| Refusal("write_failed"))?;
    for _ in 0..16 {
        let mut b = [0u8; 4];
        urandom.read_exact(&mut b).map_err(|_| Refusal("write_failed"))?;
        let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
        if !store.relays.iter().any(|e| e.id == id) {
            return Ok(id);
        }
    }
    Err(Refusal("write_failed"))
}

/// A label as stored: trimmed, no control characters, at most [`LABEL_MAX`] characters; never empty.
pub fn clean_label(text: &str, fallback: &str) -> String {
    let t: String = text.chars().filter(|c| !c.is_control()).collect();
    let t = t.trim();
    let t: String = t.chars().take(LABEL_MAX).collect();
    if t.is_empty() { fallback.to_string() } else { t }
}

/// A LAN address in the one shape the core takes (`http://ip:port`) and in the address class the pairing joiner takes
/// (`serve/join.rs`: `offer_ip`, `never_a_pairing_address`, `reachable_class`), reimplemented here because that code is
/// the core's and private. An IP literal (v4 or v6), an explicit port, no user, path, query or fragment; unspecified,
/// multicast, reserved and link-local addresses never; loopback only in a simulator build; otherwise a private range
/// (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7). The core's "on-link public address" leg is left out: stricter
/// here, and the core re-checks every address at sync time.
///
/// The `Err` word is what the page maps: `bad_address` (not that shape), `address_name` (a name, not an IP address),
/// `not_local` (an address on no private or local network).
pub fn lan_check(text: &str) -> Result<String, &'static str> {
    lan_check_with(text, cfg!(target_abi = "sim"))
}

fn lan_check_with(text: &str, loopback_ok: bool) -> Result<String, &'static str> {
    let t = text.trim();
    if t.len() > 200 || t.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("bad_address");
    }
    let u = url::Url::parse(t).map_err(|_| "bad_address")?;
    let plain_path = matches!(u.path(), "" | "/");
    if u.scheme() != "http" || !u.username().is_empty() || u.password().is_some() || !plain_path || u.query().is_some() || u.fragment().is_some() {
        return Err("bad_address");
    }
    // (no address types are named here: the egress guard keeps the network types in the coach module)
    // the class of an address: (never a pairing address, loopback, private range), on its IPv4 form when it is mapped
    let v4_class = |o: [u8; 4]| (o[0] == 0 || o[0] >= 224 || (o[0] == 169 && o[1] == 254), o[0] == 127, o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168) || (o[0] == 100 && (64..=127).contains(&o[1])));
    let (never, loopback, private, host) = match u.host() {
        Some(url::Host::Ipv4(v4)) => {
            let (n, l, p) = v4_class(v4.octets());
            (n, l, p, v4.to_string())
        }
        Some(url::Host::Ipv6(v6)) => {
            let (n, l, p) = match v6.to_ipv4_mapped() {
                Some(m) => v4_class(m.octets()),
                None => (v6.is_unspecified() || v6.octets()[0] == 0xff || (v6.segments()[0] & 0xffc0) == 0xfe80, v6.is_loopback(), (v6.segments()[0] & 0xfe00) == 0xfc00),
            };
            (n, l, p, format!("[{v6}]"))
        }
        Some(url::Host::Domain(_)) => return Err("address_name"),
        None => return Err("bad_address"),
    };
    // an explicit port: the text after the host has to carry one (the url crate hides a spelled-out :80)
    let authority = t.split_once("://").map_or("", |(_, rest)| rest.split('/').next().unwrap_or(""));
    let has_port = if authority.starts_with('[') { authority.contains("]:") } else { authority.contains(':') };
    let port = u.port_or_known_default().filter(|_| has_port).ok_or("bad_address")?;
    if never || !(private || (loopback && loopback_ok)) {
        return Err("not_local");
    }
    Ok(format!("http://{host}:{port}"))
}

/// [`lan_check`] without the word.
pub fn clean_lan_url(text: &str) -> Option<String> {
    lan_check(text).ok()
}

/// The LAN address `relay.json` names (the paired Mac), in either of the file's forms: the legacy `{"lan": url}` and the
/// list form `{"relays": [{"kind": "lan", "url": ...}]}`.
pub fn mac_url_in(dir: &Path) -> Option<String> {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("relay.json")).ok()?).ok()?;
    let found = value
        .get("lan")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            value.get("relays")?.as_array()?.iter().find_map(|r| {
                (r.get("kind")?.as_str()? == "lan").then(|| r.get("url")?.as_str().map(str::to_string)).flatten()
            })
        })?;
    clean_lan_url(&found)
}

/// Add the paired Mac as "Your Mac" when `relay.json` names one that no entry holds and the person has not removed.
/// Returns whether the list changed.
pub fn adopt_mac(dir: &Path, store: &mut Store) -> bool {
    let Some(url) = mac_url_in(dir) else { return false };
    if store.mac_dismissed.as_deref() == Some(url.as_str()) || store.relays.iter().any(|e| e.url.as_deref() == Some(url.as_str())) {
        return false;
    }
    let Ok(id) = new_id(store) else { return false };
    store.relays.push(Entry { id, kind: "lan".into(), label: MAC_LABEL.into(), bookmark: None, url: Some(url), added_at: now_secs(), debug_unscoped: false, site: None, last_push_at: None, last_pull_at: None });
    true
}

/// Remove an entry. The paired Mac (the LAN entry `relay.json` names, `paired`) cannot be removed: the Mac is the
/// pairing, and "Forget this phone" is the way out of it. Any other removed LAN entry is remembered so `relay.json`
/// does not bring it back.
pub fn remove(store: &mut Store, id: &str, paired: Option<&str>) -> Result<(), Refusal> {
    let Some(at) = store.relays.iter().position(|e| e.id == id) else { return Err(Refusal("not_found")) };
    let e = &store.relays[at];
    if e.kind == "lan" && paired.is_some() && e.url.as_deref() == paired {
        return Err(Refusal("paired_mac"));
    }
    let gone = store.relays.remove(at);
    if gone.kind == "lan" {
        store.mac_dismissed = gone.url;
    }
    Ok(())
}

pub fn rename(store: &mut Store, id: &str, label: &str) -> bool {
    let Some(e) = store.relays.iter_mut().find(|e| e.id == id) else { return false };
    e.label = clean_label(label, &e.label.clone());
    true
}

/// A lan entry added by hand clears the "removed on purpose" mark for that address.
pub fn add_lan(store: &mut Store, url: &str, label: &str) -> Result<String, Refusal> {
    let url = lan_check(url).map_err(Refusal)?;
    if store.relays.iter().any(|e| e.url.as_deref() == Some(url.as_str())) {
        return Err(Refusal("already_listed"));
    }
    let id = new_id(store)?;
    if store.mac_dismissed.as_deref() == Some(url.as_str()) {
        store.mac_dismissed = None;
    }
    store.relays.push(Entry { id: id.clone(), kind: "lan".into(), label: clean_label(label, MAC_LABEL), bookmark: None, url: Some(url), added_at: now_secs(), debug_unscoped: false, site: None, last_push_at: None, last_pull_at: None });
    Ok(id)
}

pub fn add_folder(store: &mut Store, bookmark: &[u8], label: &str) -> Result<String, Refusal> {
    let b64 = b64_encode(bookmark);
    if store.relays.iter().any(|e| e.bookmark.as_deref() == Some(b64.as_str())) {
        return Err(Refusal("already_listed"));
    }
    let id = new_id(store)?;
    store.relays.push(Entry { id: id.clone(), kind: "folder".into(), label: clean_label(label, "Folder"), bookmark: Some(b64), url: None, added_at: now_secs(), debug_unscoped: false, site: None, last_push_at: None, last_pull_at: None });
    Ok(id)
}

/// Is `path` the store's own folder (compared as the file system sees it, so `/private/var` and symlinks agree)?
pub fn is_store_folder(path: &str, store_dir: &Path) -> bool {
    let a = std::fs::canonicalize(path).unwrap_or_else(|_| path.into());
    let b = std::fs::canonicalize(store_dir).unwrap_or_else(|_| store_dir.into());
    a == b
}

// ---- the per-call param ----

/// The `relays` list for one call. `resolve` turns a folder entry into its path (and, on the phone, starts its scope and
/// keeps the guard); `None` is a bookmark that does not resolve. The result is passed whole, in list order.
pub fn build_param(store: &Store, store_dir: &Path, resolve: &mut dyn FnMut(&Entry) -> Option<String>) -> Vec<Value> {
    let mut out = Vec::new();
    for e in &store.relays {
        match e.kind.as_str() {
            "folder" => match resolve(e) {
                Some(path) if is_store_folder(&path, store_dir) => {} // never an entry at the store's own folder
                Some(path) => out.push(json!({"id": e.id, "kind": "folder", "path": path})),
                None => out.push(json!({"id": e.id, "kind": "folder", "unavailable": true})),
            },
            "lan" => {
                if let Some(url) = &e.url {
                    out.push(json!({"id": e.id, "kind": "lan", "url": url}));
                }
            }
            _ => {}
        }
    }
    out
}

/// `params` for the core: for `sync.run` (never `sync.status`, which only echoes the last run) with `inject` on and a
/// list that has an entry, `relays` is added, whole; otherwise the params are returned untouched (an empty `relays`
/// would be the core's `not_found`, and "no list" means the relay setting that pairing wrote). `inject` is `lib.rs::RELAYS_INJECT`, passed in so the test can flip it.
pub fn injected(method: &str, mut params: Value, inject: bool, relays: Vec<Value>) -> Value {
    if inject && method == "sync.run" && !relays.is_empty() {
        if let Some(map) = params.as_object_mut() {
            map.insert("relays".into(), Value::Array(relays));
        }
    }
    params
}

/// Keep the core's per-site answer beside the list: each `sites[]` row goes onto the entry with that id, with the time
/// of the run; a push or a pull that did something stamps its own time. Returns whether anything changed.
pub fn record_sites(store: &mut Store, answer: &Value, now: u64, mac_url: Option<&str>) -> bool {
    let Some(sites) = answer.get("sites").and_then(Value::as_array) else { return false };
    let mut changed = false;
    // The core's own configured relay (the paired Mac, `relay.json`) answers as id "default": it is the Mac entry's row,
    // used when that entry has no row of its own or its own row only says "same as another relay". With no Mac entry the
    // row is dropped.
    let own = |id: &str| sites.iter().find(|r| r.get("id").and_then(Value::as_str) == Some(id));
    let mac_id = mac_url.and_then(|u| store.relays.iter().find(|e| e.kind == "lan" && e.url.as_deref() == Some(u)).map(|e| e.id.clone()));
    let default_row = own("default");
    let mut rows: Vec<(String, &Value)> = Vec::new();
    for row in sites {
        let Some(id) = row.get("id").and_then(Value::as_str) else { continue };
        if id != "default" {
            rows.push((id.to_string(), row));
        }
    }
    if let (Some(mac), Some(default)) = (mac_id, default_row) {
        let weak = own(&mac).is_none_or(|r| r.get("error").and_then(Value::as_str) == Some("same_relay"));
        if weak {
            rows.retain(|(id, _)| *id != mac);
            rows.push((mac, default));
        }
    }
    for (id, row) in rows {
        let Some(entry) = store.relays.iter_mut().find(|e| e.id == id) else { continue };
        let count = |k: &str| row.get(k).and_then(Value::as_u64).unwrap_or(0);
        let mut site = row.clone();
        if let Some(map) = site.as_object_mut() {
            map.insert("at".into(), json!(now));
        }
        entry.site = Some(site);
        if count("pushed") + count("healed") > 0 {
            entry.last_push_at = Some(now);
        }
        if count("pulled") > 0 {
            entry.last_pull_at = Some(now);
        }
        changed = true;
    }
    changed
}

/// What the page is given for one entry: no bookmark, no path, only words and numbers.
pub fn view_of(e: &Entry, display: Option<String>, available: bool) -> Value {
    json!({
        "id": e.id, "kind": e.kind, "label": e.label, "available": available,
        "display": display, "url": e.url, "added_at": e.added_at,
        "site": e.site, "last_push_at": e.last_push_at, "last_pull_at": e.last_pull_at,
    })
}

// ---- the commands the page may invoke (iOS list only; the page never sees a path or a bookmark) ----

/// One writer at a time: a command, a sync's record of sites and the debug seed all read, change and write the file.
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn refusal(r: Refusal) -> CoreError {
    CoreError::new(r.0, "the relay list could not do that")
}

fn data_dir(app: &tauri::AppHandle) -> Result<std::path::PathBuf, CoreError> {
    app.path().app_data_dir().map_err(|_| CoreError::new("write_failed", "no app data folder"))
}

/// Resolve every folder entry once (starting and stopping its scope) to learn its display line and whether it can be
/// read; a stale bookmark is replaced by the fresh one the OS gave. Returns whether the list changed.
fn survey(store: &mut Store) -> (Vec<(Option<String>, bool)>, bool) {
    let mut changed = false;
    let mut rows = Vec::new();
    for e in store.relays.iter_mut() {
        if e.kind != "folder" {
            rows.push((None, true));
            continue;
        }
        let Some(resolved) = e.bookmark.as_deref().and_then(b64_decode).and_then(|b| native::resolve(&b, e.debug_unscoped)) else {
            rows.push((None, false));
            continue;
        };
        if let Some(fresh) = &resolved.refreshed {
            e.bookmark = Some(b64_encode(fresh));
            changed = true;
        }
        rows.push((Some(native::display_of(&resolved.path)), std::fs::read_dir(&resolved.path).is_ok()));
    }
    (rows, changed)
}

/// The list in words: label, kind, a display line, whether it can be read now, and the last site state. Also the paired
/// Mac's address from `relay.json` (`mac_url`), which the Add-Mac form offers.
#[cfg(target_os = "ios")]
#[tauri::command]
pub async fn relays_list(app: tauri::AppHandle) -> Result<Value, CoreError> {
    let dir = data_dir(&app)?;
    let _guard = LOCK.lock().map_err(|_| CoreError::new("busy", "busy"))?;
    let mut store = load(&dir);
    let mut changed = adopt_mac(&dir, &mut store);
    let (rows, refreshed) = survey(&mut store);
    changed |= refreshed;
    if changed {
        save(&dir, &store).map_err(refusal)?;
    }
    let views: Vec<Value> = store.relays.iter().zip(rows).map(|(e, (display, available))| view_of(e, display, available)).collect();
    Ok(json!({"relays": views, "mac_url": mac_url_in(&dir), "unreadable": store.unreadable}))
}

/// Show the Files picker for one folder and keep its bookmark. `{"cancelled": true}` when the person backs out.
#[cfg(target_os = "ios")]
#[tauri::command]
pub async fn relays_add_folder(app: tauri::AppHandle) -> Result<Value, CoreError> {
    let dir = data_dir(&app)?;
    let (tx, rx) = std::sync::mpsc::channel();
    let (shown_tx, shown_rx) = std::sync::mpsc::channel();
    app.run_on_main_thread(move || {
        let shown = match objc2::MainThreadMarker::new() {
            Some(mtm) => native::present(mtm, tx),
            None => Err("unavailable"),
        };
        let _ = shown_tx.send(shown);
    })
    .map_err(|_| CoreError::new("unavailable", "could not reach the main thread"))?;
    let shown = tauri::async_runtime::spawn_blocking(move || shown_rx.recv()).await.map_err(|_| CoreError::new("unavailable", "no picker"))?;
    match shown {
        Ok(Ok(())) => {}
        Ok(Err(word)) => return Err(CoreError::new(word, "the folder picker could not open")),
        Err(_) => return Err(CoreError::new("unavailable", "the folder picker could not open")),
    }
    // the person takes as long as they take; ten minutes is the cut-off so the slot is never held for good
    let picked = tauri::async_runtime::spawn_blocking(move || rx.recv_timeout(std::time::Duration::from_secs(600))).await;
    let picked = match picked {
        Ok(Ok(p)) => p,
        _ => {
            native::abandon();
            None
        }
    };
    let Some((bookmark, name)) = picked else { return Ok(json!({"cancelled": true})) };
    let _guard = LOCK.lock().map_err(|_| CoreError::new("busy", "busy"))?;
    let mut store = load(&dir);
    if native::resolve(&bookmark, false).is_some_and(|r| is_store_folder(&r.path, &dir)) {
        return Err(CoreError::new("own_folder", "that is this app's own folder"));
    }
    let id = add_folder(&mut store, &bookmark, &name).map_err(refusal)?;
    commit(&dir, &mut store).map_err(refusal)?;
    Ok(json!({"cancelled": false, "id": id}))
}

/// Add a LAN relay from the Settings form: the page carries the address the person typed, and it has to pass the
/// joiner's address class here (`lan_check`) whatever the page says. There is no "no address" form: the paired Mac is
/// adopted by the shell on its own (`adopt_mac`).
#[cfg(target_os = "ios")]
#[tauri::command]
pub async fn relays_add_lan(app: tauri::AppHandle, url: String, label: Option<String>) -> Result<Value, CoreError> {
    let dir = data_dir(&app)?;
    let _guard = LOCK.lock().map_err(|_| CoreError::new("busy", "busy"))?;
    let mut store = load(&dir);
    let id = add_lan(&mut store, &url, label.as_deref().unwrap_or(MAC_LABEL)).map_err(refusal)?;
    commit(&dir, &mut store).map_err(refusal)?;
    Ok(json!({"id": id}))
}

#[cfg(target_os = "ios")]
#[tauri::command]
pub async fn relays_remove(app: tauri::AppHandle, id: String) -> Result<Value, CoreError> {
    let dir = data_dir(&app)?;
    let _guard = LOCK.lock().map_err(|_| CoreError::new("busy", "busy"))?;
    let mut store = load(&dir);
    remove(&mut store, &id, mac_url_in(&dir).as_deref()).map_err(refusal)?;
    commit(&dir, &mut store).map_err(refusal)?;
    Ok(json!({"removed": true}))
}

#[cfg(target_os = "ios")]
#[tauri::command]
pub async fn relays_rename(app: tauri::AppHandle, id: String, label: String) -> Result<Value, CoreError> {
    let dir = data_dir(&app)?;
    let _guard = LOCK.lock().map_err(|_| CoreError::new("busy", "busy"))?;
    let mut store = load(&dir);
    if !rename(&mut store, &id, &label) {
        return Err(refusal(Refusal("not_found")));
    }
    commit(&dir, &mut store).map_err(refusal)?;
    Ok(json!({"renamed": true}))
}

// ---- the way to the core ----

/// The core's params for one call. With `inject` on, a `sync.run` gets the whole list as `relays`: each
/// folder's bookmark resolved and its scope started, the guards returned so the caller holds them until the answer is
/// back; the paired Mac is adopted first so the list carries it. With `inject` off nothing is read and nothing is held.
pub fn params_for_call(app: &tauri::AppHandle, method: &str, params: Value, inject: bool) -> (Value, Vec<native::Scope>) {
    if !inject || method != "sync.run" {
        return (params, Vec::new());
    }
    let Ok(dir) = data_dir(app) else { return (params, Vec::new()) };
    let Ok(_guard) = LOCK.lock() else { return (params, Vec::new()) };
    let mut store = load(&dir);
    if adopt_mac(&dir, &mut store) {
        let _ = save(&dir, &store);
    }
    let mut scopes = Vec::new();
    let list = build_param(&store, &dir, &mut |e| {
        let resolved = e.bookmark.as_deref().and_then(b64_decode).and_then(|b| native::resolve(&b, e.debug_unscoped))?;
        let path = resolved.path.clone();
        scopes.push(resolved.scope);
        Some(path)
    });
    (injected(method, params, inject, list), scopes)
}

/// Keep what the core said about each site beside the list (a `sync.run` answer that carries `sites`).
pub fn note_answer(app: &tauri::AppHandle, method: &str, answer: &Value) {
    if method != "sync.run" || answer.get("sites").is_none() {
        return;
    }
    let (Ok(dir), Ok(_guard)) = (data_dir(app), LOCK.lock()) else { return };
    let mut store = load(&dir);
    if record_sites(&mut store, answer, now_secs(), mac_url_in(&dir).as_deref()) {
        let _ = save(&dir, &store);
    }
}

/// Forget this phone takes the list with it (it names the Mac and the person's folders).
pub fn forget(app: &tauri::AppHandle) {
    if let Ok(dir) = data_dir(app) {
        remove_files(&dir);
    }
}

/// The list, its temp file and any copy kept aside from a corrupt one (they hold the same bookmarks). Also the start-up
/// hook's part of a Forget that did not end (`ios::finish_forget`).
pub fn remove_files(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(FILE));
    let _ = std::fs::remove_file(dir.join(format!(".{FILE}.tmp")));
    if let Ok(read) = std::fs::read_dir(dir) {
        for item in read.flatten() {
            if item.file_name().to_string_lossy().starts_with(&format!("{FILE}.bad-")) {
                let _ = std::fs::remove_file(item.path());
            }
        }
    }
}

/// Debug iOS builds. `--debug-relays-seed`: two plain folders become the first two entries (the Files picker cannot be
/// driven on the simulator); they sit under `DEBUG_RELAYS_BASE` when that is set (the simulator's host path), else under
/// this app's Documents. The paired Mac joins by itself when `relay.json` names one. Only when the list is empty.
/// `--debug-relays-remove-b`: drop the second folder entry (the Remove button's effect, for the evidence run).
/// Synthetic values only.
#[cfg(debug_assertions)]
pub fn debug_seed(app: &tauri::AppHandle) {
    let args: Vec<String> = std::env::args().collect();
    let (seed, drop_b) = (args.iter().any(|a| a == "--debug-relays-seed"), args.iter().any(|a| a == "--debug-relays-remove-b"));
    if !seed && !drop_b {
        return;
    }
    let (Ok(dir), Ok(_guard)) = (data_dir(app), LOCK.lock()) else { return };
    let mut store = load(&dir);
    if drop_b {
        if let Some(b) = store.relays.iter().filter(|e| e.kind == "folder").nth(1).map(|e| e.id.clone()) {
            let _ = remove(&mut store, &b, None);
            let _ = commit(&dir, &mut store);
        }
        return;
    }
    if !store.relays.is_empty() {
        return;
    }
    let base = std::env::var_os("DEBUG_RELAYS_BASE").map(std::path::PathBuf::from).or_else(|| app.path().document_dir().ok()).unwrap_or_else(|| dir.clone());
    for (name, label) in [("FolderA", "Folder A"), ("FolderB", "Folder B")] {
        let folder = base.join(name);
        let _ = std::fs::create_dir_all(&folder);
        if let Some(bytes) = native::bookmark_for_path(&folder) {
            if let Ok(id) = add_folder(&mut store, &bytes, label) {
                if let Some(e) = store.relays.iter_mut().find(|e| e.id == id) {
                    e.debug_unscoped = true;
                }
            }
        }
    }
    let _ = save(&dir, &store);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("disconect-relays-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn two() -> Store {
        let mut s = Store::default();
        add_folder(&mut s, b"bookmark-one", "Cloud A").unwrap();
        add_folder(&mut s, b"bookmark-two", "Cloud B").unwrap();
        add_lan(&mut s, "http://192.168.1.20:24816", "Your Mac").unwrap();
        s
    }

    #[test]
    fn base64_round_trips_every_length() {
        for n in 0..40usize {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let text = b64_encode(&bytes);
            assert_eq!(b64_decode(&text).unwrap(), bytes, "{n}");
        }
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_encode(b"Ma"), "TWE=");
        assert_eq!(b64_decode("not base64!"), None);
    }

    #[test]
    fn ids_are_eight_hex_and_unique_and_the_list_round_trips_through_a_0600_file() {
        let dir = scratch("file");
        let store = two();
        let ids: Vec<&String> = store.relays.iter().map(|e| &e.id).collect();
        assert!(ids.iter().all(|id| id.len() == 8 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))), "{ids:?}");
        assert_eq!(ids.iter().collect::<std::collections::HashSet<_>>().len(), 3);
        save(&dir, &store).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join(FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!dir.join(format!(".{FILE}.tmp")).exists());
        assert_eq!(load(&dir), store);
        assert_eq!(load(&scratch("empty")), Store::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_param_is_whole_in_list_order_with_unavailable_kept_and_no_label_or_bookmark() {
        let dir = scratch("param");
        let store = two();
        let mut resolve = |e: &Entry| (e.label == "Cloud A").then(|| "/Volumes/A".to_string());
        let list = build_param(&store, &dir, &mut resolve);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0], json!({"id": store.relays[0].id, "kind": "folder", "path": "/Volumes/A"}));
        assert_eq!(list[1], json!({"id": store.relays[1].id, "kind": "folder", "unavailable": true}));
        assert_eq!(list[2], json!({"id": store.relays[2].id, "kind": "lan", "url": "http://192.168.1.20:24816"}));
        let text = serde_json::to_string(&list).unwrap();
        assert!(!text.contains("Cloud") && !text.contains("bookmark") && !text.contains("Your Mac"), "{text}");
    }

    #[test]
    fn an_entry_at_the_stores_own_folder_is_left_out() {
        let dir = scratch("own");
        let store = two();
        let own = dir.to_str().unwrap().to_string();
        let mut resolve = |e: &Entry| Some(if e.label == "Cloud A" { own.clone() } else { "/Volumes/B".into() });
        let list = build_param(&store, &dir, &mut resolve);
        assert_eq!(list.len(), 2, "{list:?}");
        assert!(list.iter().all(|r| r["id"] != json!(store.relays[0].id)));
    }

    #[test]
    fn injection_is_absent_when_off_and_present_and_well_formed_on_sync_run_only() {
        let dir = scratch("inject");
        let store = two();
        let list = build_param(&store, &dir, &mut |_| Some("/Volumes/X".into()));
        let base = json!({"keep": 1});
        for m in ["sync.run", "sync.status"] {
            assert_eq!(injected(m, base.clone(), false, list.clone()), base, "off: {m}");
        }
        assert_eq!(injected("sync.status", base.clone(), true, list.clone()), base, "sync.status only echoes the last run: never injected");
        assert_eq!(injected("sync.run", base.clone(), true, Vec::new()), base, "an empty list is not sent (the core would answer not_found)");
        let p = injected("sync.run", base.clone(), true, list.clone());
        assert_eq!(p["keep"], json!(1));
        let relays = p["relays"].as_array().unwrap();
        assert_eq!(relays.len(), 3);
        for r in relays {
            let id = r["id"].as_str().unwrap();
            assert!(id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit()));
            match r["kind"].as_str().unwrap() {
                "folder" => assert!(r["path"].is_string() || r["unavailable"] == json!(true)),
                "lan" => assert!(r["url"].as_str().unwrap().starts_with("http://")),
                other => panic!("{other}"),
            }
        }
        assert_eq!(injected("data.today", base.clone(), true, list), base, "other methods never get it");
    }

    #[test]
    fn the_paired_mac_is_adopted_once_and_a_removal_sticks_until_it_is_added_by_hand() {
        let dir = scratch("mac");
        let mut store = Store::default();
        assert!(!adopt_mac(&dir, &mut store), "no relay.json, nothing to adopt");
        std::fs::write(dir.join("relay.json"), r#"{"lan": "http://192.168.1.20:24816"}"#).unwrap();
        assert!(adopt_mac(&dir, &mut store));
        assert_eq!((store.relays[0].label.as_str(), store.relays[0].kind.as_str()), (MAC_LABEL, "lan"));
        assert!(!adopt_mac(&dir, &mut store), "adopted once");
        let id = store.relays[0].id.clone();
        assert_eq!(remove(&mut store, &id, Some("http://192.168.1.20:24816")).err().map(|r| r.0), Some("paired_mac"), "the paired Mac stays");
        assert_eq!(store.relays.len(), 1);
        assert_eq!(remove(&mut store, "0000000a", Some("http://192.168.1.20:24816")).err().map(|r| r.0), Some("not_found"));
        assert!(remove(&mut store, &id, None).is_ok(), "no longer the paired address: removable");
        assert!(!adopt_mac(&dir, &mut store), "removed on purpose: not brought back");
        add_lan(&mut store, "http://192.168.1.20:24816", "Your Mac").unwrap();
        assert_eq!(store.mac_dismissed, None);
        // the list form of the file reads too
        std::fs::write(dir.join("relay.json"), r#"{"relays": [{"id": "x", "kind": "folder", "path": "/f"}, {"id": "y", "kind": "lan", "url": "http://10.0.0.2:9"}]}"#).unwrap();
        assert_eq!(mac_url_in(&dir).as_deref(), Some("http://10.0.0.2:9"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn addresses_keep_one_shape_and_labels_stay_short_text() {
        assert_eq!(clean_lan_url(" http://192.168.1.20:24816/ ").as_deref(), Some("http://192.168.1.20:24816"));
        assert_eq!(clean_lan_url("http://[fd00::1]:24816").as_deref(), Some("http://[fd00::1]:24816"));
        assert_eq!(clean_lan_url("http://192.168.1.20:80").as_deref(), Some("http://192.168.1.20:80"), "a spelled-out port 80 is explicit");
        for bad in ["https://192.168.1.2:1", "http://u:p@192.168.1.2:1", "http://192.168.1.2:1/path", "http://192.168.1.2:1?q=1", "ftp://192.168.1.2:1", "x:1", "http://a b:1", ""] {
            assert_eq!(clean_lan_url(bad), None, "{bad}");
        }
        assert_eq!(clean_label("  Dropbox\n ", "Folder"), "Dropbox");
        assert_eq!(clean_label("   ", "Folder"), "Folder");
        assert_eq!(clean_label(&"x".repeat(200), "Folder").len(), LABEL_MAX);
        let mut s = Store::default();
        assert_eq!(add_lan(&mut s, "nope", "x"), Err(Refusal("bad_address")));
        add_lan(&mut s, "http://10.1.2.3:5", "x").unwrap();
        assert_eq!(add_lan(&mut s, "http://10.1.2.3:5/", "y"), Err(Refusal("already_listed")));
        add_folder(&mut s, b"b", "f").unwrap();
        assert_eq!(add_folder(&mut s, b"b", "g"), Err(Refusal("already_listed")));
    }

    /// 19d review #3: the joiner's address class (an IP literal, an explicit port, private or on-link; loopback only in a
    /// simulator build) on the Mac's address.
    #[test]
    fn the_mac_address_must_pass_the_joiners_address_class() {
        // a private v4 with a port, and a ULA v6 with a port: accepted
        for ok in ["http://192.168.1.20:24816", "http://10.0.0.5:9", "http://172.16.0.1:24816", "http://100.64.1.1:24816", "http://[fd12::5]:24816"] {
            assert!(lan_check_with(ok, false).is_ok(), "{ok}");
        }
        // a name, a public address, no port, loopback (outside a simulator build), link-local, multicast, unspecified
        assert_eq!(lan_check_with("http://mac.local:24816", false), Err("address_name"));
        assert_eq!(lan_check_with("http://example.com:24816", false), Err("address_name"));
        assert_eq!(lan_check_with("http://8.8.8.8:24816", false), Err("not_local"));
        assert_eq!(lan_check_with("http://[2001:4860::1]:24816", false), Err("not_local"));
        assert_eq!(lan_check_with("http://192.168.1.20", false), Err("bad_address"));
        assert_eq!(lan_check_with("http://[fd12::5]", false), Err("bad_address"));
        assert_eq!(lan_check_with("http://127.0.0.1:24816", false), Err("not_local"));
        assert_eq!(lan_check_with("http://[::1]:24816", false), Err("not_local"));
        assert_eq!(lan_check_with("http://127.0.0.1:24816", true).as_deref(), Ok("http://127.0.0.1:24816"));
        for never in ["http://169.254.1.1:1", "http://[fe80::1]:1", "http://224.0.0.1:1", "http://0.0.0.0:1", "http://255.255.255.255:1"] {
            assert_eq!(lan_check_with(never, true), Err("not_local"), "{never}");
        }
        // the adopted Mac and a hand-typed one go through the same rule
        let mut s = Store::default();
        assert_eq!(add_lan(&mut s, "http://example.com:24816", "x"), Err(Refusal("address_name")));
        assert_eq!(add_lan(&mut s, "http://8.8.8.8:24816", "x"), Err(Refusal("not_local")));
        assert_eq!(add_lan(&mut s, "http://192.168.1.20", "x"), Err(Refusal("bad_address")));
        assert!(s.relays.is_empty());
        let dir = scratch("macclass");
        std::fs::write(dir.join("relay.json"), r#"{"lan": "http://mac.local:24816"}"#).unwrap();
        assert!(!adopt_mac(&dir, &mut s), "a name is never adopted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 19d review #17b: a list that cannot be read is kept aside, never overwritten, and says so until a change is saved.
    #[test]
    fn a_corrupt_list_is_kept_aside_at_0600_and_the_notice_stays_until_a_change_is_saved() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("corrupt");
        std::fs::write(dir.join(FILE), b"{ this is not json").unwrap();
        let store = load(&dir);
        assert!(store.unreadable && store.relays.is_empty());
        let asides: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.starts_with("relays.json.bad-")).collect();
        assert_eq!(asides.len(), 1, "{asides:?}");
        assert_eq!(std::fs::read(dir.join(&asides[0])).unwrap(), b"{ this is not json");
        assert_eq!(std::fs::metadata(dir.join(&asides[0])).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(load(&dir).unreadable, "the next read still says so");
        let mut store = load(&dir);
        add_folder(&mut store, b"b", "f").unwrap();
        commit(&dir, &mut store).unwrap();
        assert!(!load(&dir).unreadable, "a saved change clears it");
        remove_files(&dir);
        assert!(!dir.join(FILE).exists() && !dir.join(&asides[0]).exists(), "Forget takes the copy too");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cores_default_row_is_the_mac_entrys_row_and_dropped_without_one() {
        let mut store = Store::default();
        let mac = add_lan(&mut store, "http://192.168.1.20:24816", "Your Mac").unwrap();
        let answer = json!({"sites": [{"id": "default", "kind": "lan", "pushed": 2, "healed": 0, "behind": 0, "pulled": 1, "rejected": 0, "error": null}]});
        assert!(record_sites(&mut store, &answer, 5, Some("http://192.168.1.20:24816")));
        assert_eq!(store.relays[0].site.as_ref().unwrap()["pushed"], json!(2), "the default row lands on {mac}");
        // its own row wins unless that only says same_relay
        let both = json!({"sites": [
            {"id": mac, "kind": "lan", "pushed": 0, "healed": 0, "behind": 0, "pulled": 0, "rejected": 0, "error": "same_relay"},
            {"id": "default", "kind": "lan", "pushed": 7, "healed": 0, "behind": 0, "pulled": 0, "rejected": 0, "error": null}]});
        assert!(record_sites(&mut store, &both, 6, Some("http://192.168.1.20:24816")));
        assert_eq!(store.relays[0].site.as_ref().unwrap()["pushed"], json!(7));
        // no Mac entry: nothing to put it on
        let mut folders = Store::default();
        add_folder(&mut folders, b"b", "f").unwrap();
        assert!(!record_sites(&mut folders, &answer, 7, Some("http://192.168.1.20:24816")));
        assert_eq!(folders.relays[0].site, None);
    }

    #[test]
    fn the_cores_site_rows_are_kept_beside_the_list_and_stamp_their_own_times() {
        let mut store = two();
        let (a, b) = (store.relays[0].id.clone(), store.relays[1].id.clone());
        let answer = json!({"sites": [
            {"id": a, "kind": "folder", "pushed": 2, "healed": 0, "behind": 0, "pulled": 1, "rejected": 0, "error": null},
            {"id": b, "kind": "folder", "pushed": 0, "healed": 0, "behind": 3, "pulled": 0, "rejected": 0, "error": null},
            {"id": "ffffffff", "kind": "folder", "pushed": 9}
        ]});
        assert!(record_sites(&mut store, &answer, 1000, None));
        assert_eq!((store.relays[0].last_push_at, store.relays[0].last_pull_at), (Some(1000), Some(1000)));
        assert_eq!((store.relays[1].last_push_at, store.relays[1].last_pull_at), (None, None));
        assert_eq!(store.relays[1].site.as_ref().unwrap()["behind"], json!(3));
        assert_eq!(store.relays[1].site.as_ref().unwrap()["at"], json!(1000));
        assert_eq!(store.relays[2].site, None);
        assert!(!record_sites(&mut store, &json!({"pull": {}}), 2000, None), "no sites, no change");
        let view = view_of(&store.relays[0], Some("Cloud".into()), true);
        let text = view.to_string();
        assert!(!text.contains("bookmark"), "{text}");
    }
}
