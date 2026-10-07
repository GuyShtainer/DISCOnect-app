// SPDX-License-Identifier: AGPL-3.0-or-later
//! The phone's half of the relay list (Bet 19d, I5 row 4). On the phone the shell owns the list: a folder the person
//! picked in the Files app is a security-scoped bookmark that only this container can resolve, and it must be resolved
//! (and its scope held) around each call. So the list lives here, not in `relay.json`; the core takes it per call
//! (`sync.run {"relays": [...]}`, the contract of `docs/pitches/19d-relay-list.md`) once it can.
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

/// The list, or an empty one when the file is missing or unreadable (the list is a convenience, never a gate).
pub fn load(dir: &Path) -> Store {
    std::fs::read_to_string(dir.join(FILE)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
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

/// A LAN address in the one shape the core takes: `http://host:port`, no user, path, query or fragment. `None` when it
/// is not that. (Whether the host is a good address is the core's to say at sync time; the shell only keeps the shape.)
pub fn clean_lan_url(text: &str) -> Option<String> {
    let t = text.trim();
    if t.len() > 200 || t.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let u = url::Url::parse(t).ok()?;
    let plain_path = matches!(u.path(), "" | "/");
    if u.scheme() != "http" || !u.username().is_empty() || u.password().is_some() || !plain_path || u.query().is_some() || u.fragment().is_some() {
        return None;
    }
    let host = u.host_str()?;
    let port = u.port_or_known_default()?;
    let host = if host.contains(':') { format!("[{}]", host.trim_matches(|c| c == '[' || c == ']')) } else { host.to_string() };
    Some(format!("http://{host}:{port}"))
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
    store.relays.push(Entry { id, kind: "lan".into(), label: MAC_LABEL.into(), bookmark: None, url: Some(url), added_at: now_secs(), site: None, last_push_at: None, last_pull_at: None });
    true
}

/// Remove an entry; a removed Mac is remembered so `relay.json` does not bring it back.
pub fn remove(store: &mut Store, id: &str) -> bool {
    let Some(at) = store.relays.iter().position(|e| e.id == id) else { return false };
    let gone = store.relays.remove(at);
    if gone.kind == "lan" {
        store.mac_dismissed = gone.url;
    }
    true
}

pub fn rename(store: &mut Store, id: &str, label: &str) -> bool {
    let Some(e) = store.relays.iter_mut().find(|e| e.id == id) else { return false };
    e.label = clean_label(label, &e.label.clone());
    true
}

/// A lan entry added by hand clears the "removed on purpose" mark for that address.
pub fn add_lan(store: &mut Store, url: &str, label: &str) -> Result<String, Refusal> {
    let url = clean_lan_url(url).ok_or(Refusal("bad_address"))?;
    if store.relays.iter().any(|e| e.url.as_deref() == Some(url.as_str())) {
        return Err(Refusal("already_listed"));
    }
    let id = new_id(store)?;
    if store.mac_dismissed.as_deref() == Some(url.as_str()) {
        store.mac_dismissed = None;
    }
    store.relays.push(Entry { id: id.clone(), kind: "lan".into(), label: clean_label(label, MAC_LABEL), bookmark: None, url: Some(url), added_at: now_secs(), site: None, last_push_at: None, last_pull_at: None });
    Ok(id)
}

pub fn add_folder(store: &mut Store, bookmark: &[u8], label: &str) -> Result<String, Refusal> {
    let b64 = b64_encode(bookmark);
    if store.relays.iter().any(|e| e.bookmark.as_deref() == Some(b64.as_str())) {
        return Err(Refusal("already_listed"));
    }
    let id = new_id(store)?;
    store.relays.push(Entry { id: id.clone(), kind: "folder".into(), label: clean_label(label, "Folder"), bookmark: Some(b64), url: None, added_at: now_secs(), site: None, last_push_at: None, last_pull_at: None });
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

/// `params` for the core: for `sync.run` and `sync.status` with `inject` on, `relays` is added, whole; otherwise the
/// params are returned untouched. `inject` is `lib.rs::RELAYS_INJECT`, passed in so the test can flip it.
pub fn injected(method: &str, mut params: Value, inject: bool, relays: Vec<Value>) -> Value {
    if inject && matches!(method, "sync.run" | "sync.status") {
        if let Some(map) = params.as_object_mut() {
            map.insert("relays".into(), Value::Array(relays));
        }
    }
    params
}

/// Keep the core's per-site answer beside the list: each `sites[]` row goes onto the entry with that id, with the time
/// of the run; a push or a pull that did something stamps its own time. Returns whether anything changed.
pub fn record_sites(store: &mut Store, answer: &Value, now: u64) -> bool {
    let Some(sites) = answer.get("sites").and_then(Value::as_array) else { return false };
    let mut changed = false;
    for row in sites {
        let Some(id) = row.get("id").and_then(Value::as_str) else { continue };
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
        let Some(resolved) = e.bookmark.as_deref().and_then(b64_decode).and_then(|b| native::resolve(&b)) else {
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
    Ok(json!({"relays": views, "mac_url": mac_url_in(&dir)}))
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
    if native::resolve(&bookmark).is_some_and(|r| is_store_folder(&r.path, &dir)) {
        return Err(CoreError::new("own_folder", "that is this app's own folder"));
    }
    let id = add_folder(&mut store, &bookmark, &name).map_err(refusal)?;
    save(&dir, &store).map_err(refusal)?;
    Ok(json!({"cancelled": false, "id": id}))
}

/// Add a LAN relay. With no `url`, the paired Mac's address from `relay.json`.
#[cfg(target_os = "ios")]
#[tauri::command]
pub async fn relays_add_lan(app: tauri::AppHandle, url: Option<String>, label: Option<String>) -> Result<Value, CoreError> {
    let dir = data_dir(&app)?;
    let _guard = LOCK.lock().map_err(|_| CoreError::new("busy", "busy"))?;
    let mut store = load(&dir);
    let url = url.or_else(|| mac_url_in(&dir)).ok_or_else(|| refusal(Refusal("bad_address")))?;
    let id = add_lan(&mut store, &url, label.as_deref().unwrap_or(MAC_LABEL)).map_err(refusal)?;
    save(&dir, &store).map_err(refusal)?;
    Ok(json!({"id": id}))
}

#[cfg(target_os = "ios")]
#[tauri::command]
pub async fn relays_remove(app: tauri::AppHandle, id: String) -> Result<Value, CoreError> {
    let dir = data_dir(&app)?;
    let _guard = LOCK.lock().map_err(|_| CoreError::new("busy", "busy"))?;
    let mut store = load(&dir);
    if !remove(&mut store, &id) {
        return Err(refusal(Refusal("not_found")));
    }
    save(&dir, &store).map_err(refusal)?;
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
    save(&dir, &store).map_err(refusal)?;
    Ok(json!({"renamed": true}))
}

// ---- the way to the core ----

/// The core's params for one call. With `inject` on, a `sync.run` or `sync.status` gets the whole list as `relays`: each
/// folder's bookmark resolved and its scope started, the guards returned so the caller holds them until the answer is
/// back; the paired Mac is adopted first so the list carries it. With `inject` off nothing is read and nothing is held.
pub fn params_for_call(app: &tauri::AppHandle, method: &str, params: Value, inject: bool) -> (Value, Vec<native::Scope>) {
    if !inject || !matches!(method, "sync.run" | "sync.status") {
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
        let resolved = e.bookmark.as_deref().and_then(b64_decode).and_then(|b| native::resolve(&b))?;
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
    if record_sites(&mut store, answer, now_secs()) {
        let _ = save(&dir, &store);
    }
}

/// Forget this phone takes the list with it (it names the Mac and the person's folders).
pub fn forget(app: &tauri::AppHandle) {
    if let Ok(dir) = data_dir(app) {
        let _ = std::fs::remove_file(dir.join(FILE));
        let _ = std::fs::remove_file(dir.join(format!(".{FILE}.tmp")));
    }
}

/// Debug iOS builds, `--debug-relays-seed`: two folders this app owns become the first two entries (the Files picker
/// cannot be driven on the simulator), the first with a made-up last result so the Settings words can be seen. Only
/// when the list is empty. Synthetic values only.
#[cfg(debug_assertions)]
pub fn debug_seed(app: &tauri::AppHandle) {
    if !std::env::args().any(|a| a == "--debug-relays-seed") {
        return;
    }
    let (Ok(dir), Ok(_guard)) = (data_dir(app), LOCK.lock()) else { return };
    let mut store = load(&dir);
    if !store.relays.is_empty() {
        return;
    }
    let base = app.path().document_dir().unwrap_or_else(|_| dir.clone());
    for (name, label) in [("FolderA", "Folder A"), ("FolderB", "Folder B")] {
        let folder = base.join(name);
        let _ = std::fs::create_dir_all(&folder);
        if let Some(bytes) = native::bookmark_for_path(&folder) {
            let _ = add_folder(&mut store, &bytes, label);
        }
    }
    let now = now_secs();
    if let Some(first) = store.relays.first_mut() {
        first.site = Some(json!({"id": first.id, "kind": "folder", "pushed": 3, "healed": 0, "behind": 0, "pulled": 2, "rejected": 0, "error": null, "at": now - 60}));
        first.last_push_at = Some(now - 120);
        first.last_pull_at = Some(now - 60);
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
        add_lan(&mut s, "http://192.168.1.20:8443", "Your Mac").unwrap();
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
        assert_eq!(list[2], json!({"id": store.relays[2].id, "kind": "lan", "url": "http://192.168.1.20:8443"}));
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
    fn injection_is_absent_when_off_and_present_and_well_formed_when_on() {
        let dir = scratch("inject");
        let store = two();
        let list = build_param(&store, &dir, &mut |_| Some("/Volumes/X".into()));
        let base = json!({"keep": 1});
        // off: the params are untouched, for either method
        for m in ["sync.run", "sync.status"] {
            assert_eq!(injected(m, base.clone(), false, list.clone()), base, "{m}");
        }
        // on: `relays` is the whole list, for the two methods only
        for m in ["sync.run", "sync.status"] {
            let p = injected(m, base.clone(), true, list.clone());
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
        }
        assert_eq!(injected("data.today", base.clone(), true, list), base, "other methods never get it");
    }

    #[test]
    fn the_paired_mac_is_adopted_once_and_a_removal_sticks_until_it_is_added_by_hand() {
        let dir = scratch("mac");
        let mut store = Store::default();
        assert!(!adopt_mac(&dir, &mut store), "no relay.json, nothing to adopt");
        std::fs::write(dir.join("relay.json"), r#"{"lan": "http://192.168.1.20:8443"}"#).unwrap();
        assert!(adopt_mac(&dir, &mut store));
        assert_eq!((store.relays[0].label.as_str(), store.relays[0].kind.as_str()), (MAC_LABEL, "lan"));
        assert!(!adopt_mac(&dir, &mut store), "adopted once");
        let id = store.relays[0].id.clone();
        assert!(remove(&mut store, &id));
        assert!(!adopt_mac(&dir, &mut store), "removed on purpose: not brought back");
        add_lan(&mut store, "http://192.168.1.20:8443", "Your Mac").unwrap();
        assert_eq!(store.mac_dismissed, None);
        // the list form of the file reads too
        std::fs::write(dir.join("relay.json"), r#"{"relays": [{"id": "x", "kind": "folder", "path": "/f"}, {"id": "y", "kind": "lan", "url": "http://10.0.0.2:9"}]}"#).unwrap();
        assert_eq!(mac_url_in(&dir).as_deref(), Some("http://10.0.0.2:9"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn addresses_keep_one_shape_and_labels_stay_short_text() {
        assert_eq!(clean_lan_url(" http://192.168.1.20:8443/ ").as_deref(), Some("http://192.168.1.20:8443"));
        assert_eq!(clean_lan_url("http://[fe80::1]:80").as_deref(), Some("http://[fe80::1]:80"));
        for bad in ["https://x:1", "http://u:p@x:1", "http://x:1/path", "http://x:1?q=1", "ftp://x:1", "x:1", "http://a b:1", ""] {
            assert_eq!(clean_lan_url(bad), None, "{bad}");
        }
        assert_eq!(clean_label("  Dropbox\n ", "Folder"), "Dropbox");
        assert_eq!(clean_label("   ", "Folder"), "Folder");
        assert_eq!(clean_label(&"x".repeat(200), "Folder").len(), LABEL_MAX);
        let mut s = Store::default();
        assert_eq!(add_lan(&mut s, "nope", "x"), Err(Refusal("bad_address")));
        add_lan(&mut s, "http://1.2.3.4:5", "x").unwrap();
        assert_eq!(add_lan(&mut s, "http://1.2.3.4:5/", "y"), Err(Refusal("already_listed")));
        add_folder(&mut s, b"b", "f").unwrap();
        assert_eq!(add_folder(&mut s, b"b", "g"), Err(Refusal("already_listed")));
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
        assert!(record_sites(&mut store, &answer, 1000));
        assert_eq!((store.relays[0].last_push_at, store.relays[0].last_pull_at), (Some(1000), Some(1000)));
        assert_eq!((store.relays[1].last_push_at, store.relays[1].last_pull_at), (None, None));
        assert_eq!(store.relays[1].site.as_ref().unwrap()["behind"], json!(3));
        assert_eq!(store.relays[1].site.as_ref().unwrap()["at"], json!(1000));
        assert_eq!(store.relays[2].site, None);
        assert!(!record_sites(&mut store, &json!({"pull": {}}), 2000), "no sites, no change");
        let view = view_of(&store.relays[0], Some("Cloud".into()), true);
        let text = view.to_string();
        assert!(!text.contains("bookmark"), "{text}");
    }
}
