// SPDX-License-Identifier: AGPL-3.0-or-later
//! Push and pull: what crosses the relay and how it is applied. The twin of
//! `disconect/relay/sync.py` (read its module docstring and `docs/relay-protocol.md`).
//!
//! Push = every raw record and export range not yet marked in `relay_seen` /
//! `relay_seen_ranges` (pushed or received) -> bundles split on the *compressed* payload length
//! -> `relay.put`. Pull = `relay.list(account)` minus the applied bundles -> `unpack` -> verify
//! every record's bytes -> the normal `Writer` as one import run with transport `relay`: FIT
//! first, then JSON records through the export decoders, then the readiness batch, then the
//! derived dailies. A bundle that fails authentication or validation is recorded `rejected` and
//! retried on the next pull.
//!
//! Conflict rule (JSON streams): same `(stream, source_key)`, different `payload_hash` -> the
//! record whose decoded facts carry the later observed time wins, ties by the larger
//! `payload_hash`; the batch streams (readiness) have no time of their own, so the hash alone
//! decides. The loser's bytes go to `raw_superseded`, the decision to `sync_conflicts`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::bundle::{
    self, BundleError, Header, RangeRow, RawRow, account_for, new_name, pack, unpack,
};
use super::config::{RelayConfig, RelayEntry};
use super::folder::{FolderRelay, Relay, RelayError};
use super::lan::{LanRelay, parse_base_url};
use crate::canon::{self, Value};
use crate::clock::ClockOffsets;
use crate::export::{self, DecodeError};
use crate::keys;
use crate::fit;
use crate::model::{Decoded, Instant};
use crate::sources::{self, SourceError};
use crate::time::{parse_iso_utc, utc_now_iso};
use crate::writer::{KeptRow, WriteOutcome, Writer, WriterError};

pub const TRANSPORT_RELAY: &str = "relay";
/// A bundle is cut once its compressed payloads would pass this many bytes.
pub const PUSH_BYTES_LIMIT: usize = 8 * 1024 * 1024;
/// The `core` header field of the bundles this build writes.
const CORE: &str = concat!("disconect-core/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Writer(#[from] WriterError),
    #[error("{0}")]
    Source(#[from] SourceError),
    #[error("{0}")]
    Bundle(#[from] BundleError),
    #[error("{0}")]
    Relay(#[from] RelayError),
    /// An exception the oracle lets escape (`AttributeError` on a record that is not an object,
    /// `OverflowError` on a huge epoch): the pull stops, its run is booked failed.
    #[error("{0}")]
    Abort(String),
    /// A pulled record could not be stored (a storage error, not a decode failure). Whatever the
    /// write covered was rolled back -- for a conflict winner that includes the retirement of the
    /// losing record, which is still in place. The bundle stays `applying`; the next pull reapplies it.
    #[error("{0}")]
    WriteFailed(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PushResult {
    pub bundles: Vec<String>,
    pub records: usize,
    pub ranges: usize,
    /// True when no site could take a bundle: the push stopped there and the rest stays unsent.
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub chain: String,
    pub device_seq: i64,
    pub missing: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullResult {
    pub applied: Vec<String>,
    /// (bundle name, reason), in the order they were met.
    pub rejected: Vec<(String, String)>,
    pub records_new: i64,
    pub records_duplicate: i64,
    pub records_invalid: i64,
    pub conflicts: i64,
    pub ranges_new: i64,
    /// Stored copies whose bytes no longer matched their hash, refetched from the relay.
    pub records_repaired: i64,
    /// Bytes of a stream this build has no decoder for, retained for a later reparse.
    pub records_kept: i64,
    pub gaps: Vec<Gap>,
    pub status: &'static str,
}

impl Default for PullResult {
    fn default() -> Self {
        PullResult {
            applied: Vec::new(),
            rejected: Vec::new(),
            records_new: 0,
            records_duplicate: 0,
            records_invalid: 0,
            conflicts: 0,
            ranges_new: 0,
            records_repaired: 0,
            records_kept: 0,
            gaps: Vec::new(),
            status: "ok",
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn device(conn: &Connection) -> Result<(String, i64, Option<String>), SyncError> {
    let row: Option<(String, i64, Option<String>)> = conn
        .query_row(
            "SELECT device_id, next_seq, last_bundle FROM relay_device WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some(row) = row {
        return Ok(row);
    }
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|e| BundleError::Random(e.to_string()))?;
    let device_id = hex::encode(random);
    conn.execute(
        "INSERT INTO relay_device(id, device_id, next_seq, last_bundle) VALUES(1, ?, 1, NULL)",
        params![device_id],
    )?;
    Ok((device_id, 1, None))
}

// ---------------------------------------------------------------- push

/// Never more than this many bundles are re-put on one site in one run (the rest is `behind`).
pub const HEAL_BUNDLES_PER_SITE: usize = 16;
/// Nor more than this many packed bytes (a first bundle over it still goes).
pub const HEAL_BYTES_PER_SITE: usize = 64 * 1024 * 1024;

/// One open relay of a run.
pub struct Site {
    pub id: String,
    /// `"folder"` or `"lan"`.
    pub kind: &'static str,
    pub relay: Box<dyn Relay + Send>,
    /// Index of this site's [`SiteReport`] in the run's reports (an entry that did not open has a report, no site).
    pub report: usize,
}

/// What one site did in one run: `sync.run`'s `sites` rows. `error` is a stable site word (see
/// [`RelayError::site_word`], plus the words `open_sites` adds), never a path or an OS text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteReport {
    pub id: String,
    pub kind: &'static str,
    /// The entry's label (`""` when it has none): user text, never a path.
    pub label: String,
    pub pushed: usize,
    pub healed: usize,
    pub behind: usize,
    pub pulled: usize,
    pub rejected: usize,
    pub error: Option<&'static str>,
}

impl SiteReport {
    pub fn new(id: &str, kind: &'static str) -> SiteReport {
        SiteReport {
            id: id.to_string(),
            kind,
            label: String::new(),
            pushed: 0,
            healed: 0,
            behind: 0,
            pulled: 0,
            rejected: 0,
            error: None,
        }
    }

    pub fn value(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "pushed": self.pushed,
            "healed": self.healed,
            "behind": self.behind,
            "pulled": self.pulled,
            "rejected": self.rejected,
            "error": self.error,
        })
    }

    fn fail(&mut self, error: &RelayError) {
        self.error.get_or_insert(error.site_word());
    }
}

/// A relay to open: from a `RelayEntry` or from a per-call `relays` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteSpec {
    pub id: String,
    pub config: RelayConfig,
    /// The entry's label (`""` for none); echoed in the site's report.
    pub label: String,
    /// The shell could not reach the folder (an unmounted volume, a revoked bookmark): reported, never opened.
    pub unavailable: bool,
    /// A folder whose root may be missing is opened anyway and the first put creates it (the legacy single
    /// folder and the entry this device serves); otherwise a missing root is `unavailable`.
    pub create_root: bool,
    /// A `lan` address also has to be an address class the phone may sync with (an IP literal, private or
    /// on-link; see `serve::join::lan_address_class_ok`): set for the entries a shell injects per call.
    pub check_address: bool,
}

impl SiteSpec {
    pub fn from_entry(entry: &RelayEntry) -> SiteSpec {
        SiteSpec {
            id: entry.id.clone(),
            config: entry.config.clone(),
            label: entry.label.clone(),
            unavailable: false,
            create_root: entry.serve,
            check_address: false,
        }
    }
}

/// Who a folder is: the root's (device, inode), so two paths to one folder (a symlink, `/private/var`, case or
/// normalisation differences) are one relay.
#[cfg(unix)]
fn folder_identity(root: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(root).ok().filter(|m| m.is_dir())?;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn folder_identity(root: &Path) -> Option<(u64, u64)> {
    use std::hash::{Hash, Hasher};
    std::fs::metadata(root).ok().filter(|m| m.is_dir())?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::fs::canonicalize(root).ok()?.hash(&mut hasher);
    Some((0, hasher.finish()))
}

/// Open every relay of a run. There is one report per spec, in the specs' order; a spec that cannot be used
/// carries its reason word (`unavailable`, `same_relay`, `bad_url`) and has no site. Never an error, and nothing is
/// created: a missing root is `unavailable` (the first put creates `<root>/<account>` only).
pub fn open_sites(specs: &[SiteSpec], master: &[u8]) -> (Vec<Site>, Vec<SiteReport>) {
    let mut sites: Vec<Site> = Vec::new();
    let mut reports: Vec<SiteReport> = Vec::new();
    let mut folders: Vec<(u64, u64)> = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    for spec in specs {
        let kind = match spec.config {
            RelayConfig::Folder(_) => "folder",
            RelayConfig::Lan(_) => "lan",
        };
        let mut report = SiteReport::new(&spec.id, kind);
        report.label = spec.label.clone();
        let opened: Result<Box<dyn Relay + Send>, &'static str> = if spec.unavailable {
            Err("unavailable")
        } else {
            match &spec.config {
                RelayConfig::Folder(folder) => {
                    let root = keys::expand_user(Path::new(folder));
                    match folder_identity(&root) {
                        None if spec.create_root && !root.exists() => Ok(Box::new(FolderRelay::creating_root(root))),
                        None => Err("unavailable"),
                        Some(identity) if folders.contains(&identity) => Err("same_relay"),
                        Some(identity) => {
                            folders.push(identity);
                            Ok(Box::new(if spec.create_root {
                                FolderRelay::creating_root(root)
                            } else {
                                FolderRelay::new(root)
                            }))
                        }
                    }
                }
                RelayConfig::Lan(url) => match parse_base_url(url) {
                    Err(_) => Err("bad_url"),
                    Ok(base) if spec.check_address && !crate::serve::join::lan_address_class_ok(&base) => Err("bad_url"),
                    Ok(base) if urls.contains(&base) => Err("same_relay"),
                    Ok(base) => match LanRelay::new(&base, master) {
                        Ok(relay) => {
                            urls.push(base);
                            Ok(Box::new(relay))
                        }
                        Err(_) => Err("bad_url"),
                    },
                },
            }
        };
        match opened {
            Ok(relay) => sites.push(Site {
                id: spec.id.clone(),
                kind,
                relay,
                report: reports.len(),
            }),
            Err(word) => report.error = Some(word),
        }
        reports.push(report);
    }
    (sites, reports)
}

/// A relay of one call and the index of its report.
type Target<'a> = (&'a dyn Relay, usize);

fn targets(sites: &[Site]) -> Vec<Target<'_>> {
    sites.iter().map(|s| (&*s.relay as &dyn Relay, s.report)).collect()
}

/// Bundle every unseen local-origin record and range and put them on the relay (one site, errors raised).
pub fn push(conn: &Connection, master: &[u8], relay: &dyn Relay) -> Result<PushResult, SyncError> {
    let mut reports = vec![SiteReport::new("default", "folder")];
    let mut faults = vec![None];
    let result = push_core(conn, master, &[(relay, 0)], &mut reports, &mut faults)?;
    match faults.pop().flatten() {
        Some(error) => Err(error.into()),
        None => Ok(result),
    }
}

/// [`push`] over every site: a new bundle is packed once and put on each, booked when one took it; then each site
/// that is still sound is healed (the names this device pushed that its listing lacks are re-packed and put again,
/// within the per-site budget). A site's failure is its report's `error`, never the run's.
pub fn push_all(
    conn: &Connection,
    master: &[u8],
    sites: &[Site],
    reports: &mut [SiteReport],
) -> Result<PushResult, SyncError> {
    let mut faults: Vec<Option<RelayError>> = (0..sites.len()).map(|_| None).collect();
    push_core(conn, master, &targets(sites), reports, &mut faults)
}

/// [`push_all`] for a list of one: the site's first failure is raised as the error (what [`push`] does), its report
/// is filled all the same.
pub fn push_strict(
    conn: &Connection,
    master: &[u8],
    sites: &[Site],
    reports: &mut [SiteReport],
) -> Result<PushResult, SyncError> {
    let mut faults: Vec<Option<RelayError>> = (0..sites.len()).map(|_| None).collect();
    let result = push_core(conn, master, &targets(sites), reports, &mut faults)?;
    match faults.into_iter().flatten().next() {
        Some(error) => Err(error.into()),
        None => Ok(result),
    }
}

fn push_core(
    conn: &Connection,
    master: &[u8],
    relays: &[Target<'_>],
    reports: &mut [SiteReport],
    faults: &mut [Option<RelayError>],
) -> Result<PushResult, SyncError> {
    let mut result = PushResult::default();
    push_new(conn, master, relays, reports, faults, &mut result)?;
    heal(conn, master, relays, reports, faults)?;
    Ok(result)
}

fn push_new(
    conn: &Connection,
    master: &[u8],
    relays: &[Target<'_>],
    reports: &mut [SiteReport],
    faults: &mut [Option<RelayError>],
    result: &mut PushResult,
) -> Result<(), SyncError> {
    let account = account_for(master);
    let rows: Vec<(i64, RawRow)> = {
        let mut stmt = conn.prepare(
            "SELECT r.id, r.stream, r.source_key, r.source_scope, r.transport, r.device_id, r.start_utc, r.end_utc, \
             r.payload_kind, r.payload, r.payload_hash, r.payload_bytes, r.imported_at FROM raw_records r \
             LEFT JOIN relay_seen s ON s.raw_record_id = r.id WHERE s.raw_record_id IS NULL ORDER BY r.id",
        )?;
        let mapped = stmt.query_map([], raw_row)?;
        mapped.collect::<Result<_, _>>()?
    };
    let ranges: Vec<(i64, RangeRow)> = {
        let mut stmt = conn.prepare(
            "SELECT x.id, x.stream, x.from_day, x.to_day FROM export_ranges x \
             LEFT JOIN relay_seen_ranges s ON s.export_range_id = x.id WHERE s.export_range_id IS NULL ORDER BY x.id",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                RangeRow {
                    stream: r.get(1)?,
                    from_day: r.get(2)?,
                    to_day: r.get(3)?,
                },
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    if rows.is_empty() && ranges.is_empty() {
        return Ok(());
    }
    if faults.iter().all(Option::is_some) {
        // no site can take a bundle (this also holds for no site at all): nothing is packed, nothing is booked
        result.partial = true;
        return Ok(());
    }
    // split on the *compressed* payload length (what travels); ranges ride in the last bundle only
    let mut batches: Vec<Vec<(i64, RawRow)>> = vec![Vec::new()];
    let mut size = 0usize;
    for row in rows {
        let payload_len = row.1.payload.len();
        if batches.last().is_some_and(|b| !b.is_empty()) && size + payload_len > PUSH_BYTES_LIMIT {
            batches.push(Vec::new());
            size = 0;
        }
        if let Some(last) = batches.last_mut() {
            last.push(row);
        }
        size += payload_len;
    }
    let last_index = batches.len() - 1;
    for (index, batch) in batches.iter().enumerate() {
        let records: Vec<RawRow> = batch.iter().map(|(_, row)| row.clone()).collect();
        let (bundle_ranges, range_ids): (Vec<RangeRow>, Vec<i64>) = if index == last_index {
            ranges
                .iter()
                .map(|(id, range)| (range.clone(), *id))
                .unzip()
        } else {
            (Vec::new(), Vec::new())
        };
        // created lazily and outside the bundle's transaction, as the oracle does
        let (device_id, seq, prev) = device(conn)?;
        let name = new_name(&account)?;
        let header = Header {
            device_id: device_id.clone(),
            device_seq: seq,
            prev: prev.clone(),
            created_utc: utc_now_iso(),
        };
        let data = pack(master, &name, CORE, &header, &records, &bundle_ranges)?;
        // the ONLY puts in the crate (with the heal's): the argument is AEAD output
        let mut took = 0usize;
        for (index, (relay, report)) in relays.iter().enumerate() {
            if faults[index].is_some() {
                continue;
            }
            match relay.put(&name, &data) {
                Ok(()) => {
                    took += 1;
                    reports[*report].pushed += 1;
                }
                Err(error) => {
                    reports[*report].fail(&error);
                    faults[index] = Some(error);
                }
            }
        }
        if took == 0 {
            // nothing after an unbooked bundle may be booked: prev and seq stay a chain
            result.partial = true;
            return Ok(());
        }
        conn.execute_batch("BEGIN")?;
        let booked = (|| -> rusqlite::Result<()> {
            conn.execute(
                "INSERT INTO relay_bundles(name, direction, status, device_id, device_seq, prev, created_utc, noted_at, \
                 bytes, records) VALUES(?,?,?,?,?,?,?,?,?,?)",
                params![
                    name,
                    "pushed",
                    "applied",
                    device_id,
                    seq,
                    prev,
                    header.created_utc,
                    utc_now_iso(),
                    data.len() as i64,
                    records.len() as i64
                ],
            )?;
            for (raw_id, _) in batch {
                conn.execute(
                    "INSERT OR IGNORE INTO relay_seen(raw_record_id, bundle, direction) VALUES(?,?,'pushed')",
                    params![raw_id, name],
                )?;
            }
            for range_id in &range_ids {
                conn.execute(
                    "INSERT OR IGNORE INTO relay_seen_ranges(export_range_id, bundle, direction) VALUES(?,?,'pushed')",
                    params![range_id, name],
                )?;
            }
            conn.execute(
                "UPDATE relay_device SET next_seq = ?, last_bundle = ? WHERE id=1",
                params![seq + 1, name],
            )?;
            Ok(())
        })();
        match booked {
            Ok(()) => conn.execute_batch("COMMIT")?,
            Err(error) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(error.into());
            }
        }
        result.records += records.len();
        result.ranges += bundle_ranges.len();
        result.bundles.push(name);
    }
    Ok(())
}

/// What a site is missing: the names this device pushed (in sequence order) that its listing does not show, are
/// packed again from the stored header and the rows still linked to the name (a record a later conflict retired
/// is simply absent) and put under the same name. At most [`HEAL_BUNDLES_PER_SITE`] bundles and
/// [`HEAL_BYTES_PER_SITE`] packed bytes per site per run; the rest is the report's `behind`. The re-pack is not
/// byte-identical to the first copy (fresh nonce, possibly fewer rows); every reader keys by name, sequence and
/// record identity, so the two are interchangeable.
fn heal(
    conn: &Connection,
    master: &[u8],
    relays: &[Target<'_>],
    reports: &mut [SiteReport],
    faults: &mut [Option<RelayError>],
) -> Result<(), SyncError> {
    if faults.iter().all(Option::is_some) {
        return Ok(());
    }
    let account = account_for(master);
    let pushed: Vec<(String, Header)> = {
        let mut stmt = conn.prepare(
            "SELECT name, device_id, device_seq, prev, created_utc FROM relay_bundles \
             WHERE direction='pushed' AND status='applied' AND name LIKE ? ORDER BY device_seq",
        )?;
        // only this account's names: after a key rotation whose forget failed, the old account's rows stay
        let mapped = stmt.query_map(params![format!("{account}/%")], |r| {
            Ok((
                r.get::<_, String>(0)?,
                Header {
                    device_id: r.get(1)?,
                    device_seq: r.get(2)?,
                    prev: r.get(3)?,
                    created_utc: r.get(4)?,
                },
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    if pushed.is_empty() {
        return Ok(());
    }
    for (index, (relay, report)) in relays.iter().enumerate() {
        if faults[index].is_some() {
            continue;
        }
        let listing: HashSet<String> = match relay.list_present(&account) {
            Ok(names) => names.into_iter().collect(),
            Err(error) => {
                reports[*report].fail(&error);
                faults[index] = Some(error);
                continue;
            }
        };
        let missing: Vec<&(String, Header)> =
            pushed.iter().filter(|(name, _)| !listing.contains(name)).collect();
        let mut bytes = 0usize;
        for (position, (name, header)) in missing.iter().enumerate() {
            let rest = missing.len() - position;
            if reports[*report].healed >= HEAL_BUNDLES_PER_SITE {
                reports[*report].behind = rest;
                break;
            }
            let (records, ranges) = linked_rows(conn, name)?;
            let Ok(data) = pack(master, name, CORE, header, &records, &ranges) else {
                // one name that cannot be packed is this site's `io_error`, never the run's
                let error = RelayError::Io(std::io::Error::other("pack"));
                reports[*report].fail(&error);
                faults[index] = Some(error);
                break;
            };
            if reports[*report].healed > 0 && bytes + data.len() > HEAL_BYTES_PER_SITE {
                reports[*report].behind = rest;
                break;
            }
            match relay.put(name, &data) {
                Ok(()) => {
                    bytes += data.len();
                    reports[*report].healed += 1;
                }
                Err(error) => {
                    reports[*report].fail(&error);
                    faults[index] = Some(error);
                    break;
                }
            }
        }
    }
    Ok(())
}

/// The records and ranges still linked to the pushed bundle `name` (`relay_seen`, `relay_seen_ranges`), in the
/// order a push packs them.
fn linked_rows(conn: &Connection, name: &str) -> Result<(Vec<RawRow>, Vec<RangeRow>), SyncError> {
    let records: Vec<RawRow> = {
        let mut stmt = conn.prepare(
            "SELECT r.id, r.stream, r.source_key, r.source_scope, r.transport, r.device_id, r.start_utc, r.end_utc, \
             r.payload_kind, r.payload, r.payload_hash, r.payload_bytes, r.imported_at FROM raw_records r \
             JOIN relay_seen s ON s.raw_record_id = r.id WHERE s.bundle = ? ORDER BY r.id",
        )?;
        let mapped = stmt.query_map(params![name], |r| Ok(raw_row(r)?.1))?;
        mapped.collect::<Result<_, _>>()?
    };
    let ranges: Vec<RangeRow> = {
        let mut stmt = conn.prepare(
            "SELECT x.stream, x.from_day, x.to_day FROM export_ranges x \
             JOIN relay_seen_ranges s ON s.export_range_id = x.id WHERE s.bundle = ? ORDER BY x.id",
        )?;
        let mapped = stmt.query_map(params![name], |r| {
            Ok(RangeRow {
                stream: r.get(0)?,
                from_day: r.get(1)?,
                to_day: r.get(2)?,
            })
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    Ok((records, ranges))
}

/// A `raw_records` row selected as `id, stream, ..., imported_at`.
fn raw_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, RawRow)> {
    Ok((
        r.get(0)?,
        RawRow {
            stream: r.get(1)?,
            source_key: r.get(2)?,
            source_scope: r.get(3)?,
            transport: r.get(4)?,
            device_id: r.get(5)?,
            start_utc: r.get(6)?,
            end_utc: r.get(7)?,
            payload_kind: r.get(8)?,
            payload: r.get(9)?,
            payload_hash: r.get(10)?,
            payload_bytes: r.get(11)?,
            imported_at: r.get(12)?,
        },
    ))
}

// ---------------------------------------------------------------- pull

/// The decompressed bytes if they match the record's hashes, else `None` (`_verify`).
fn verify(record: &RawRow) -> Option<Vec<u8>> {
    let data = sources::inflate(&record.payload)?;
    let digest = sha256_hex(&data);
    if digest != record.payload_hash || data.len() as i64 != record.payload_bytes {
        return None;
    }
    if record.payload_kind == "fit" && digest != record.source_key {
        return None;
    }
    if record.payload_kind != "fit" && record.payload_kind != "json" {
        return None;
    }
    Some(data)
}

/// The latest moment the decoded facts speak for (`_observed`); `None` where the oracle has `''`.
fn observed(decoded: &Decoded) -> Option<Instant> {
    decoded
        .end_utc
        .into_iter()
        .chain(decoded.daily.iter().filter_map(|f| f.ts_utc))
        .max()
}

/// `_has_decoder`: this build can decode records of `stream` (a batch stream or a registered
/// per-record decoder).
fn has_decoder(stream: &str) -> bool {
    export::is_batch_stream(stream) || export::has_record_decoder(stream)
}

/// `_decode_json`: the record and its decoded facts, `None` where the oracle's `ValueError` /
/// `TypeError` / no-decoder / no-facts paths lead to an invalid record. An exception the oracle
/// lets escape (a record that is not an object) is `Err(Abort)`.
fn decode_json(
    stream: &str,
    data: &[u8],
    row: Option<&RawRow>,
) -> Result<Option<(Value, Decoded)>, SyncError> {
    let Ok(record) = canon::parse(data) else {
        return Ok(None); // json.loads -> ValueError, caught by the caller
    };
    if export::is_batch_stream(stream) {
        // decoded as a batch later; the raw row keeps the sender's span and device
        let scope = row
            .map(|r| r.source_scope.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("vendor_cloud");
        let mut decoded = Decoded::new(stream, scope);
        decoded.device_id = row.and_then(|r| r.device_id.clone());
        for (field, slot) in [
            (
                row.and_then(|r| r.start_utc.as_deref()),
                &mut decoded.start_utc,
            ),
            (row.and_then(|r| r.end_utc.as_deref()), &mut decoded.end_utc),
        ] {
            if let Some(text) = field.filter(|t| !t.is_empty()) {
                match parse_iso_utc(text) {
                    Some(moment) => *slot = Some(moment),
                    None => return Ok(None), // strptime -> ValueError
                }
            }
        }
        return Ok(Some((record, decoded)));
    }
    if !export::has_record_decoder(stream) {
        return Ok(None);
    }
    match export::decode_stored_record(stream, &record) {
        Ok(Some((_key, decoded))) => Ok(Some((record, decoded))),
        Ok(None) | Err(DecodeError::Refused(_)) => Ok(None),
        Err(DecodeError::Abort(message)) => {
            if message.starts_with("ValueError") || message.starts_with("TypeError") {
                Ok(None)
            } else {
                Err(SyncError::Abort(message))
            }
        }
    }
}

struct Existing {
    id: i64,
    payload: Vec<u8>,
    payload_hash: String,
    payload_kind: String,
    transport: String,
    imported_at: String,
}

fn insert_conflict(
    conn: &Connection,
    record: &RawRow,
    winner: &str,
    loser: &str,
    rule: &str,
    bundle_name: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO sync_conflicts(stream, source_key, winner_hash, loser_hash, rule, bundle, decided_at) \
         VALUES(?,?,?,?,?,?,?)",
        params![record.stream, record.source_key, winner, loser, rule, bundle_name, utc_now_iso()],
    )?;
    Ok(())
}

/// The bytes of the record that lost, as `raw_superseded` keeps them.
struct Loser<'a> {
    kind: &'a str,
    payload: &'a [u8],
    hash: &'a str,
    transport: &'a str,
    imported_at: &'a str,
}

fn insert_superseded(
    conn: &Connection,
    record: &RawRow,
    loser: &Loser<'_>,
    bundle_name: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO raw_superseded(stream, source_key, payload_kind, payload, payload_hash, transport, imported_at, \
         superseded_at, bundle) VALUES(?,?,?,?,?,?,?,?,?)",
        params![
            record.stream,
            record.source_key,
            loser.kind,
            loser.payload,
            loser.hash,
            loser.transport,
            loser.imported_at,
            utc_now_iso(),
            bundle_name
        ],
    )?;
    Ok(())
}

/// The decision on a same-key, different-bytes pair (`_decide_conflict`): pure, writes nothing.
pub struct Conflict {
    pub incoming_wins: bool,
    rule: &'static str,
    winner: String,
    loser: String,
    existing: Existing,
}

/// Same key, different bytes: who wins. `None` when no stored row differs from the incoming bytes
/// (no row at all, or the very same bytes): nothing to decide. `incoming = None` is a record of a
/// stream this build cannot decode: neither side has a time, so the rule is the hash alone (as for
/// a batch stream) -- the one rule a device without the decoder can apply.
pub fn decide_conflict(
    conn: &Connection,
    record: &RawRow,
    incoming: Option<&Decoded>,
) -> Result<Option<Conflict>, SyncError> {
    let existing: Option<Existing> = conn
        .query_row(
            "SELECT id, payload, payload_hash, payload_kind, transport, imported_at FROM raw_records \
             WHERE stream=? AND source_key=?",
            params![record.stream, record.source_key],
            |r| {
                Ok(Existing {
                    id: r.get(0)?,
                    payload: r.get(1)?,
                    payload_hash: r.get(2)?,
                    payload_kind: r.get(3)?,
                    transport: r.get(4)?,
                    imported_at: r.get(5)?,
                })
            },
        )
        .optional()?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.payload_hash == record.payload_hash {
        return Ok(None);
    }
    let (existing_observed, incoming_observed) = if incoming.is_none() || export::is_batch_stream(&record.stream) {
        // a batch stream's record carries no time of its own: the protocol's rule is the hash alone;
        // a stream with no decoder here has no time either
        (None, None)
    } else {
        // an undecodable existing record loses by definition
        let decoded = sources::inflate(&existing.payload)
            .and_then(|data| decode_json(&record.stream, &data, None).ok().flatten())
            .map(|(_record, decoded)| decoded);
        (decoded.as_ref().and_then(observed), incoming.and_then(observed))
    };
    let (incoming_wins, rule) = if incoming_observed != existing_observed {
        (incoming_observed > existing_observed, "observed_utc")
    } else {
        (record.payload_hash > existing.payload_hash, "payload_hash")
    };
    let (winner, loser) = if incoming_wins {
        (record.payload_hash.clone(), existing.payload_hash.clone())
    } else {
        (existing.payload_hash.clone(), record.payload_hash.clone())
    };
    Ok(Some(Conflict {
        incoming_wins,
        rule,
        winner,
        loser,
        existing,
    }))
}

/// The incoming record lost: keep its bytes in `raw_superseded` with the decision, one transaction.
fn record_incoming_loser(
    conn: &Connection,
    record: &RawRow,
    conflict: &Conflict,
    bundle_name: &str,
) -> Result<(), SyncError> {
    conn.execute_batch("BEGIN")?;
    let decided = (|| -> rusqlite::Result<()> {
        insert_conflict(
            conn,
            record,
            &conflict.winner,
            &conflict.loser,
            conflict.rule,
            bundle_name,
        )?;
        let loser = Loser {
            kind: &record.payload_kind,
            payload: &record.payload,
            hash: &record.payload_hash,
            transport: &record.transport,
            imported_at: &record.imported_at,
        };
        insert_superseded(conn, record, &loser, bundle_name)
    })();
    match decided {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(error.into());
        }
    }
    Ok(())
}

/// The pre-write hook of an incoming winner: every write that retires the stored loser. It runs
/// inside `write_json_record_with`'s own transaction, before the winner's raw row and canonical
/// rows, so a storage error anywhere rolls the decision back together with the winner's write.
fn retire_loser(
    conn: &Connection,
    writer: &Writer<'_>,
    record: &RawRow,
    conflict: &Conflict,
    bundle_name: &str,
) -> rusqlite::Result<()> {
    let existing = &conflict.existing;
    insert_conflict(
        conn,
        record,
        &conflict.winner,
        &conflict.loser,
        conflict.rule,
        bundle_name,
    )?;
    let loser = Loser {
        kind: &existing.payload_kind,
        payload: &existing.payload,
        hash: &existing.payload_hash,
        transport: &existing.transport,
        imported_at: &existing.imported_at,
    };
    insert_superseded(conn, record, &loser, bundle_name)?;
    writer.delete_canonical_for_raw(existing.id)?;
    // rows that point at the losing record (a past decode failure, relay bookkeeping) go first
    conn.execute(
        "DELETE FROM import_failures WHERE raw_record_id=?",
        params![existing.id],
    )?;
    conn.execute(
        "DELETE FROM relay_seen WHERE raw_record_id=?",
        params![existing.id],
    )?;
    conn.execute("DELETE FROM raw_records WHERE id=?", params![existing.id])?;
    Ok(())
}

fn conflict_recorded(
    conn: &Connection,
    bundle_name: &str,
    record: &RawRow,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM sync_conflicts WHERE bundle=? AND source_key=? AND stream=?",
        params![bundle_name, record.source_key, record.stream],
        |_| Ok(()),
    )
    .optional()
    .map(|found| found.is_some())
}

/// Fetch and apply every bundle on the relay this store has not applied yet.
/// `_repair_damaged`: every stored record the relay has carried (`relay_seen`) is checked against its
/// hash; a copy whose bytes no longer inflate to it is refetched from the bundle that carried it and the
/// streams it feeds are re-derived. Without this a damaged copy stays damaged forever: a peer never pushes
/// a pulled record back, and the conflict rule, meeting bytes that do not decode, would hand the key to
/// whatever arrives next. A bundle the relay no longer has leaves the record as it is (nothing fails).
fn repair_damaged(
    conn: &Connection,
    master: &[u8],
    relays: &[Target<'_>],
    result: &mut PullResult,
) -> Result<(), SyncError> {
    let mut damaged: BTreeMap<String, Vec<(i64, String, String)>> = BTreeMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT r.id, r.payload, r.payload_hash, r.stream, s.bundle FROM raw_records r \
             JOIN relay_seen s ON s.raw_record_id = r.id ORDER BY r.id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (id, payload, digest, stream, bundle) = row?;
            let intact = sources::inflate(&payload).is_some_and(|data| sha256_hex(&data) == digest);
            if !intact {
                damaged.entry(bundle).or_default().push((id, digest, stream));
            }
        }
    }
    let mut streams: BTreeSet<String> = BTreeSet::new();
    for (bundle_name, wanted) in damaged {
        // the first site that holds a copy which unpacks
        let Some(bundle) = relays.iter().find_map(|(relay, _)| {
            let blob = relay.get(&bundle_name).ok()?;
            unpack(master, &bundle_name, &blob).ok()
        }) else {
            continue;
        };
        let by_hash: HashMap<&str, &RawRow> = bundle
            .records
            .iter()
            .filter(|r| verify(r).is_some())
            .map(|r| (r.payload_hash.as_str(), r))
            .collect();
        for (id, digest, stream) in wanted {
            let Some(record) = by_hash.get(digest.as_str()) else { continue };
            conn.execute(
                "UPDATE raw_records SET payload=? WHERE id=?",
                params![record.payload, id],
            )?;
            conn.execute("DELETE FROM import_failures WHERE raw_record_id=?", params![id])?;
            result.records_repaired += 1;
            streams.insert(stream);
        }
    }
    if !streams.is_empty() {
        let streams: Vec<String> = streams.into_iter().collect();
        sources::reparse_all(conn, Some(&streams), true)?;
    }
    Ok(())
}

/// [`pull_all`] over one site, its failure raised as an error (the CLI's `--relay`, pairing, tests).
pub fn pull(conn: &Connection, master: &[u8], relay: &dyn Relay) -> Result<PullResult, SyncError> {
    let mut reports = vec![SiteReport::new("default", "folder")];
    let mut faults = vec![None];
    let result = pull_core(conn, master, &[(relay, 0)], &mut reports, &mut faults)?;
    match faults.pop().flatten() {
        Some(error) => Err(error.into()),
        None => Ok(result),
    }
}

/// Fetch and apply every bundle any site lists that this store has not applied: the union of the listings, each
/// name tried on every site that lists it, in site order, until one unpacks (`rejected` only when all fail). A
/// site that cannot be listed contributes nothing; a transient failure skips that site for the rest of the run and
/// leaves its names pending (the run is `partial`). Failures are the reports' `error`, never the run's.
pub fn pull_all(
    conn: &Connection,
    master: &[u8],
    sites: &[Site],
    reports: &mut [SiteReport],
) -> Result<PullResult, SyncError> {
    let mut faults: Vec<Option<RelayError>> = (0..sites.len()).map(|_| None).collect();
    pull_core(conn, master, &targets(sites), reports, &mut faults)
}

/// [`pull_all`] for a list of one: the site's first failure is raised as the error (what [`pull`] does), its report
/// is filled all the same.
pub fn pull_strict(
    conn: &Connection,
    master: &[u8],
    sites: &[Site],
    reports: &mut [SiteReport],
) -> Result<PullResult, SyncError> {
    let mut faults: Vec<Option<RelayError>> = (0..sites.len()).map(|_| None).collect();
    let result = pull_core(conn, master, &targets(sites), reports, &mut faults)?;
    match faults.into_iter().flatten().next() {
        Some(error) => Err(error.into()),
        None => Ok(result),
    }
}

fn pull_core(
    conn: &Connection,
    master: &[u8],
    relays: &[Target<'_>],
    reports: &mut [SiteReport],
    faults: &mut [Option<RelayError>],
) -> Result<PullResult, SyncError> {
    let account = account_for(master);
    let mut result = PullResult::default();
    repair_damaged(conn, master, relays, &mut result)?;
    let names = |status: &str| -> rusqlite::Result<HashSet<String>> {
        let mut stmt = conn.prepare("SELECT name FROM relay_bundles WHERE status=?")?;
        let mapped = stmt.query_map(params![status], |r| r.get::<_, String>(0))?;
        mapped.collect()
    };
    let known = names("applied")?;
    let half_applied = names("applying")?;
    // the union of the listings in first-seen order (site order, then listing order), each name with its sites
    let mut pending: Vec<(String, Vec<usize>)> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    for (index, (relay, report)) in relays.iter().enumerate() {
        let listing = match relay.list(&account) {
            Ok(listing) => listing,
            Err(error) => {
                reports[*report].fail(&error);
                faults[index] = Some(error);
                continue;
            }
        };
        for name in listing.into_iter().filter(|name| !known.contains(name)) {
            match at.get(&name) {
                Some(&slot) => pending[slot].1.push(index),
                None => {
                    at.insert(name.clone(), pending.len());
                    pending.push((name, vec![index]));
                }
            }
        }
    }
    if faults.iter().any(Option::is_some) {
        result.status = "partial";
    }
    if pending.is_empty() {
        report_gaps(conn, &mut result)?;
        return Ok(result);
    }
    let mut writer = Writer::new(conn, ClockOffsets::load(conn)?, TRANSPORT_RELAY);
    writer.begin_run()?;
    if let Err(error) = apply_pending(
        conn,
        master,
        relays,
        reports,
        faults,
        &mut writer,
        &pending,
        &half_applied,
        &mut result,
    ) {
        writer.finish_run(Some(&error.to_string()))?;
        return Err(error);
    }
    writer.stats.dates_assumed_utc = writer.offsets.assumed_utc();
    writer.finish_run(None)?;
    if !result.rejected.is_empty() {
        result.status = "partial";
    }
    report_gaps(conn, &mut result)?;
    Ok(result)
}

struct Applied {
    name: String,
    header: Header,
    size: usize,
    count: usize,
}

#[allow(clippy::too_many_arguments)]
fn apply_pending(
    conn: &Connection,
    master: &[u8],
    relays: &[Target<'_>],
    reports: &mut [SiteReport],
    faults: &mut [Option<RelayError>],
    writer: &mut Writer<'_>,
    pending: &[(String, Vec<usize>)],
    half_applied: &HashSet<String>,
    result: &mut PullResult,
) -> Result<(), SyncError> {
    let mut applied: Vec<Applied> = Vec::new();
    let mut reparse_streams: BTreeSet<String> = BTreeSet::new();
    // sites a transient failure took out of this run
    let mut skipped = vec![false; relays.len()];
    for (name, holders) in pending {
        let mut fetched: Option<(Vec<u8>, bundle::Bundle)> = None;
        let mut failed = 0usize;
        let mut first_reason: Option<String> = None;
        for &index in holders {
            if skipped[index] {
                continue;
            }
            let (relay, report) = relays[index];
            let blob = match relay.get(name) {
                Ok(blob) => blob,
                // the relay, not the object, is the problem: this site is out for the run, the name stays
                // pending if no other site has it
                Err(error) if error.is_transient() => {
                    skipped[index] = true;
                    reports[report].fail(&error);
                    faults[index].get_or_insert(error);
                    continue;
                }
                Err(error) => {
                    reports[report].rejected += 1;
                    failed += 1;
                    first_reason.get_or_insert_with(|| error.reason().to_string());
                    continue;
                }
            };
            match unpack(master, name, &blob) {
                Ok(bundle) => {
                    reports[report].pulled += 1;
                    fetched = Some((blob, bundle));
                    break;
                }
                Err(rejected) => {
                    reports[report].rejected += 1;
                    failed += 1;
                    first_reason.get_or_insert(rejected.reason);
                }
            }
        }
        let Some((blob, bundle)) = fetched else {
            if failed == holders.len() {
                let reason = first_reason.unwrap_or_default();
                writer.stats.files_failed += 1;
                conn.execute(
                    "INSERT OR REPLACE INTO relay_bundles(name, direction, status, noted_at, reason) \
                     VALUES(?, 'pulled', 'rejected', ?, ?)",
                    params![name, utc_now_iso(), reason],
                )?;
                result.rejected.push((name.clone(), reason));
            } else {
                // a site that may hold a good copy was out of reach: nothing is booked, the next pull retries
                result.status = "partial";
            }
            continue;
        };
        let bundle::Bundle {
            header,
            records,
            ranges,
        } = bundle;
        if half_applied.contains(name) {
            // a crash cut the previous pull before its derive step: its records are in, the derived
            // rows may not be -- re-derive those streams in full
            reparse_streams.extend(records.iter().map(|r| r.stream.clone()));
        }
        conn.execute(
            "INSERT OR REPLACE INTO relay_bundles(name, direction, status, noted_at, bytes, records) \
             VALUES(?, 'pulled', 'applying', ?, ?, ?)",
            params![name, utc_now_iso(), blob.len() as i64, records.len() as i64],
        )?;
        let mut fits: Vec<(&RawRow, Vec<u8>)> = Vec::new();
        let mut jsons: Vec<(&RawRow, Vec<u8>)> = Vec::new();
        for record in &records {
            let Some(data) = verify(record) else { continue };
            match record.payload_kind.as_str() {
                "fit" => fits.push((record, data)),
                "json" => jsons.push((record, data)),
                _ => {}
            }
        }
        result.records_invalid += (records.len() - fits.len() - jsons.len()) as i64;
        let label = format!("relay:{}", &name[name.len().saturating_sub(8)..]);
        for (_record, data) in &fits {
            writer.offsets.extend(fit::scan_clock_offsets(data));
        }
        for (record, data) in &fits {
            let before = writer.last_raw_id()?;
            let outcome =
                writer.write_fit(data, &label, Some((&record.transport, &record.imported_at)))?;
            if outcome == WriteOutcome::Failed && writer.last_failure_is_storage() {
                return Err(SyncError::WriteFailed(format!(
                    "{} file not stored ({outcome:?}); nothing it wrote is kept",
                    record.stream
                )));
            }
            mark(conn, before, name, outcome, result)?;
            if outcome == WriteOutcome::Duplicate {
                mark_existing(conn, record, name)?;
            }
        }
        for (record, data) in &jsons {
            let known = has_decoder(&record.stream);
            // a stream a newer build published: the bytes are kept (no canonical rows) for the day
            // a decoder arrives -- dropping them would lose them for good
            let decoded = if known {
                let Some(pair) = decode_json(&record.stream, data, Some(record))? else {
                    result.records_invalid += 1;
                    continue;
                };
                Some(pair)
            } else {
                None
            };
            let facts = decoded.as_ref().map(|(_value, facts)| facts);
            let conflict = decide_conflict(conn, record, facts)?;
            if let Some(conflict) = conflict.as_ref().filter(|c| !c.incoming_wins) {
                // a reapplied bundle decided this record already
                if !conflict_recorded(conn, name, record)? {
                    record_incoming_loser(conn, record, conflict, name)?;
                }
                result.conflicts += 1;
                continue;
            }
            if conflict.is_none() {
                let stored = conn
                    .prepare_cached("SELECT 1 FROM raw_records WHERE stream=? AND source_key=?")?
                    .exists(params![record.stream, record.source_key])?;
                if stored {
                    // the same bytes are already here (a local import or an earlier bundle)
                    if conflict_recorded(conn, name, record)? {
                        // a reapplied bundle: the winner is stored, its relay_seen row may not be
                        result.conflicts += 1;
                        mark_existing(conn, record, name)?;
                    } else {
                        result.records_duplicate += 1;
                        mark_existing(conn, record, name)?;
                    }
                    continue;
                }
            }
            let before = writer.last_raw_id()?;
            let hook;
            let before_write: Option<crate::writer::BeforeWrite<'_>> = match conflict.as_ref() {
                Some(conflict) => {
                    hook = |w: &Writer<'_>| retire_loser(conn, w, record, conflict, name);
                    Some(&hook)
                }
                None => None,
            };
            let origin = Some((record.transport.as_str(), record.imported_at.as_str()));
            let outcome = match &decoded {
                Some((record_value, facts)) => writer.write_json_record_with(
                    &record.stream,
                    &record.source_key,
                    record_value,
                    facts,
                    &label,
                    origin,
                    before_write,
                )?,
                None => writer.keep_undecodable_record(
                    &record.stream,
                    &record.source_key,
                    &KeptRow {
                        source_scope: &record.source_scope,
                        device_id: record.device_id.as_deref(),
                        start_utc: record.start_utc.as_deref(),
                        end_utc: record.end_utc.as_deref(),
                    },
                    data,
                    &label,
                    origin,
                    before_write,
                )?,
            };
            let storage_failure =
                outcome == WriteOutcome::Failed && writer.last_failure_is_storage();
            if storage_failure || (conflict.is_some() && !matches!(outcome, WriteOutcome::Imported | WriteOutcome::Kept)) {
                return Err(SyncError::WriteFailed(format!(
                    "{} record not stored ({outcome:?}); nothing it wrote is kept",
                    record.stream
                )));
            }
            if conflict.is_some() {
                result.conflicts += 1;
            }
            mark(conn, before, name, outcome, result)?;
            if conflict.is_some() {
                // the winner may have reused the retired loser's rowid (`id > before` misses it)
                mark_existing(conn, record, name)?;
            }
        }
        for item in &ranges {
            let changes_before = conn.total_changes();
            writer.record_export_range(&item.stream, &item.from_day, &item.to_day)?;
            let id: Option<i64> = conn
                .query_row(
                    "SELECT id FROM export_ranges WHERE stream=? AND from_day=? AND to_day=?",
                    params![item.stream, item.from_day, item.to_day],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(id) = id {
                if conn.total_changes() > changes_before {
                    result.ranges_new += 1;
                }
                conn.execute(
                    "INSERT OR IGNORE INTO relay_seen_ranges(export_range_id, bundle, direction) VALUES(?,?,'pulled')",
                    params![id, name],
                )?;
            }
        }
        applied.push(Applied {
            name: name.clone(),
            header,
            size: blob.len(),
            count: records.len(),
        });
    }
    // daily rows are a pure function of the raw set: every JSON stream a record was written to
    // (new, or a conflict winner that replaced the loser) is rebuilt in content order
    let touched: Vec<String> = writer.stats.streams.keys().cloned().collect();
    sources::rederive_json(conn, writer, &touched)?;
    writer.derive_daily_steps()?;
    writer.derive_daily_from_samples()?;
    writer.derive_live_samples()?;
    if !reparse_streams.is_empty() {
        let streams: Vec<String> = reparse_streams.into_iter().collect();
        sources::reparse_all(conn, Some(&streams), false)?;
    }
    for item in applied {
        conn.execute(
            "INSERT OR REPLACE INTO relay_bundles(name, direction, status, device_id, device_seq, prev, created_utc, \
             noted_at, bytes, records) VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                item.name,
                "pulled",
                "applied",
                item.header.device_id,
                item.header.device_seq,
                item.header.prev,
                item.header.created_utc,
                utc_now_iso(),
                item.size as i64,
                item.count as i64
            ],
        )?;
        result.applied.push(item.name);
    }
    Ok(())
}

/// `_mark`: an imported record's rows are marked received -- every raw id above `before`.
fn mark(
    conn: &Connection,
    before: i64,
    name: &str,
    outcome: WriteOutcome,
    result: &mut PullResult,
) -> Result<(), SyncError> {
    match outcome {
        WriteOutcome::Imported | WriteOutcome::Kept => {
            if outcome == WriteOutcome::Imported {
                result.records_new += 1;
            } else {
                result.records_kept += 1;
            }
            let ids: Vec<i64> = {
                let mut stmt = conn.prepare("SELECT id FROM raw_records WHERE id > ?")?;
                let mapped = stmt.query_map(params![before], |r| r.get(0))?;
                mapped.collect::<Result<_, _>>()?
            };
            for raw_id in ids {
                conn.execute(
                    "INSERT OR IGNORE INTO relay_seen(raw_record_id, bundle, direction) VALUES(?,?,'pulled')",
                    params![raw_id, name],
                )?;
            }
        }
        WriteOutcome::Duplicate => result.records_duplicate += 1,
        WriteOutcome::Failed | WriteOutcome::Reparsed => result.records_invalid += 1,
    }
    Ok(())
}

/// `_mark_existing`: the same bytes were already here (a local import or an earlier bundle):
/// never push them back. A FIT record falls back to its key (the bytes' hash) alone.
fn mark_existing(conn: &Connection, record: &RawRow, name: &str) -> Result<(), SyncError> {
    let mut id: Option<i64> = conn
        .query_row(
            "SELECT id FROM raw_records WHERE stream=? AND source_key=? AND payload_hash=?",
            params![record.stream, record.source_key, record.payload_hash],
            |r| r.get(0),
        )
        .optional()?;
    if id.is_none() && record.payload_kind == "fit" {
        id = conn
            .query_row(
                "SELECT id FROM raw_records WHERE payload_kind='fit' AND source_key=?",
                params![record.source_key],
                |r| r.get(0),
            )
            .optional()?;
    }
    if let Some(id) = id {
        conn.execute(
            "INSERT OR IGNORE INTO relay_seen(raw_record_id, bundle, direction) VALUES(?,?,'pulled')",
            params![id, name],
        )?;
    }
    Ok(())
}

/// A device's chain (`device_seq`, `prev`) with a missing link means the relay dropped a middle bundle.
fn report_gaps(conn: &Connection, result: &mut PullResult) -> Result<(), SyncError> {
    result.gaps = gaps(conn)?;
    Ok(())
}

pub fn gaps(conn: &Connection) -> Result<Vec<Gap>, SyncError> {
    type Link = (i64, Option<String>, String);
    let rows: Vec<(String, Link)> = {
        let mut stmt = conn.prepare(
            "SELECT device_id, device_seq, prev, name FROM relay_bundles WHERE status='applied' \
             AND device_id IS NOT NULL ORDER BY device_id, device_seq",
        )?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?, r.get(3)?))))?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut by_device: Vec<(String, Vec<Link>)> = Vec::new();
    for (device_id, link) in rows {
        match by_device.last_mut() {
            Some((id, chain)) if *id == device_id => chain.push(link),
            _ => by_device.push((device_id, vec![link])),
        }
    }
    let mut found = Vec::new();
    for (device_id, chain) in by_device {
        let names: HashSet<&str> = chain.iter().map(|(_, _, name)| name.as_str()).collect();
        for (seq, prev, _name) in &chain {
            if let Some(prev) = prev
                && !names.contains(prev.as_str())
            {
                found.push(Gap {
                    chain: device_id.clone(),
                    device_seq: *seq,
                    missing: prev.clone(),
                });
            }
        }
    }
    Ok(found)
}

/// Counts only: bundles pushed/pulled/rejected, records seen, conflicts, chain gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    /// `"<direction>_<status>"` -> bundle count.
    pub bundles: BTreeMap<String, i64>,
    pub records_unsent: i64,
    pub records_seen: i64,
    pub conflicts: i64,
    pub superseded: i64,
    pub gaps: Vec<Gap>,
    /// `noted_at` of the newest applied pushed bundle: a push that moved nothing books no bundle,
    /// so this is "last data sent", not "last attempt". `None` until the first.
    pub last_pushed_at: Option<String>,
    /// The same for pulled bundles: "last data received".
    pub last_pulled_at: Option<String>,
}

pub fn status(conn: &Connection) -> Result<StatusReport, SyncError> {
    let mut bundles = BTreeMap::new();
    {
        let mut stmt =
            conn.prepare("SELECT direction, status, count(*) FROM relay_bundles GROUP BY 1, 2")?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in mapped {
            let (direction, state, count) = row?;
            bundles.insert(format!("{direction}_{state}"), count);
        }
    }
    let count = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0));
    Ok(StatusReport {
        bundles,
        records_unsent: count(
            "SELECT count(*) FROM raw_records r LEFT JOIN relay_seen s ON s.raw_record_id=r.id WHERE s.raw_record_id IS NULL",
        )?,
        records_seen: count("SELECT count(*) FROM relay_seen")?,
        // by content (the versions that lost), so converged devices report the same numbers: the tables
        // themselves are per-bundle journals whose row counts depend on arrival order
        conflicts: count(
            "SELECT count(*) FROM (SELECT DISTINCT stream, source_key, loser_hash FROM sync_conflicts)",
        )?,
        superseded: count(
            "SELECT count(*) FROM (SELECT DISTINCT stream, source_key, payload_hash FROM raw_superseded)",
        )?,
        gaps: gaps(conn)?,
        last_pushed_at: last_applied(conn, "pushed")?,
        last_pulled_at: last_applied(conn, "pulled")?,
    })
}

/// `max(noted_at)` of the applied bundles in one direction, `None` when there is none.
fn last_applied(conn: &Connection, direction: &str) -> Result<Option<String>, SyncError> {
    Ok(conn.query_row(
        "SELECT max(noted_at) FROM relay_bundles WHERE status='applied' AND direction=?",
        [direction],
        |r| r.get::<_, Option<String>>(0),
    )?)
}

/// `status` for a store that may predate the relay tables (schema 1 or 2, never synced): the same
/// counts a fresh schema-3 store would show, so a read-only `sync.status` never needs a migration.
pub fn status_or_fresh(conn: &Connection) -> Result<StatusReport, SyncError> {
    let has_relay: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='relay_bundles')",
        [],
        |r| r.get(0),
    )?;
    if has_relay {
        return status(conn);
    }
    Ok(StatusReport {
        bundles: BTreeMap::new(),
        records_unsent: conn.query_row("SELECT count(*) FROM raw_records", [], |r| r.get(0))?,
        records_seen: 0,
        conflicts: 0,
        superseded: 0,
        gaps: Vec::new(),
        last_pushed_at: None,
        last_pulled_at: None,
    })
}

/// The JSON `sync status --json` prints and the `sync.status` method answers.
pub fn status_value(report: &StatusReport) -> serde_json::Value {
    let bundles: serde_json::Map<String, serde_json::Value> = report
        .bundles
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::json!(v)))
        .collect();
    let gaps: Vec<serde_json::Value> = report
        .gaps
        .iter()
        .map(|g| serde_json::json!({"chain": g.chain, "device_seq": g.device_seq, "missing": g.missing}))
        .collect();
    serde_json::json!({
        "bundles": bundles,
        "records_unsent": report.records_unsent,
        "records_seen": report.records_seen,
        "conflicts": report.conflicts,
        "superseded": report.superseded,
        "gaps": gaps,
        "last_pushed_at": report.last_pushed_at,
        "last_pulled_at": report.last_pulled_at,
    })
}

/// After a master rotation or a re-pair: a new account and key, so every record is pushed again
/// under them. Conflict and superseded history is kept (it is local history, not relay state).
pub fn forget_relay_state(conn: &Connection) -> Result<(), SyncError> {
    for table in [
        "relay_bundles",
        "relay_seen",
        "relay_seen_ranges",
        "relay_device",
    ] {
        conn.execute(&format!("DELETE FROM {table}"), [])?;
    }
    Ok(())
}
