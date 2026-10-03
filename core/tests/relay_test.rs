// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay client against the Python oracle's behaviour (`tests/test_relay.py`): bundle crypto
//! through real stores, push and pull, the conflict rule, crash recovery, rejections. Synthetic
//! data only, scratch encrypted stores built from the empty fixture.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use common::{PASSPHRASE, encrypted_copy, fixtures};
use disconect_core::canon;
use disconect_core::keys::{self, PassphraseSource};
use disconect_core::relay::bundle::{
    self, Header, RawRow, account_for, new_name, seal_lines, unpack,
};
use disconect_core::relay::folder::{FolderRelay, MAX_OBJECT, Relay};
use disconect_core::relay::sync::{self, PullResult, SyncError};
use disconect_core::sources::{self, SourceError, import_path};
use disconect_core::store::{self, Store};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

fn master() -> &'static [u8] {
    static MASTER: OnceLock<Vec<u8>> = OnceLock::new();
    MASTER.get_or_init(|| {
        let key = keys::unlock(
            &fixtures().join("test.keys.json"),
            PassphraseSource::Explicit(PASSPHRASE),
        )
        .expect("unlock the fixture key");
        key.to_vec()
    })
}

fn other_master() -> Vec<u8> {
    (1u8..33).collect()
}

struct Device {
    _dir: tempfile::TempDir,
    store: Store,
}

impl Device {
    fn conn(&self) -> &Connection {
        self.store.conn()
    }
}

fn device() -> Device {
    let (dir, db) = encrypted_copy();
    let secret = keys::unlock(
        &keys::key_path_for(&db),
        PassphraseSource::Explicit(PASSPHRASE),
    )
    .expect("unlock");
    let store = store::open_for_write_with(&db, "test", 5.0, Some(&secret)).expect("open store");
    Device { _dir: dir, store }
}

fn relay_in(dir: &Path) -> FolderRelay {
    FolderRelay::new(dir.join("relay"))
}

fn write(dir: &Path, relative: &str, text: &str) {
    let path = dir.join(relative);
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, text).expect("write");
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).expect("count")
}

/// A folder of synthetic FIT files copied from the fixtures.
fn fit_drop(dir: &Path, name: &str, fixtures_used: &[&str]) -> PathBuf {
    let target = dir.join(name);
    fs::create_dir_all(&target).expect("mkdir");
    for stem in fixtures_used {
        fs::copy(
            fixtures().join("synthetic").join(format!("{stem}.fit.bin")),
            target.join(format!("{stem}.fit")),
        )
        .expect("copy fixture");
    }
    target
}

const MONITORING: [&str; 2] = ["monitoring_timestamp16", "monitoring_cycles_resolution"];

fn uds(day: &str, steps: i64, end: &str) -> String {
    format!(
        r#"{{"calendarDate":"{day}","totalSteps":{steps},"wellnessEndTimeGmt":"{end}","wellnessStartTimeGmt":"{day}T00:00:00.0"}}"#
    )
}

fn readiness(day: &str, stamp: &str, context: &str, score: i64) -> String {
    format!(
        r#"{{"calendarDate":"{day}","timestamp":"{stamp}","inputContext":"{context}","score":{score},"level":"HIGH"}}"#
    )
}

fn export_with_uds(dir: &Path, name: &str, record: &str) -> PathBuf {
    let root = dir.join(name);
    write(
        &root,
        "DI_CONNECT/DI-Connect-Aggregator/UDSFile_2025-06-15_2025-06-15.json",
        &format!("[{record}]"),
    );
    fs::create_dir_all(root.join("DI_CONNECT/DI-Connect-Uploaded-Files")).expect("mkdir");
    root
}

fn export_with_readiness(dir: &Path, name: &str, record: &str) -> PathBuf {
    let root = dir.join(name);
    write(
        &root,
        "DI_CONNECT/DI-Connect-Metrics/TrainingReadinessDTO_111_111_111.json",
        &format!("[{record}]"),
    );
    fs::create_dir_all(root.join("DI_CONNECT/DI-Connect-Uploaded-Files")).expect("mkdir");
    root
}

fn import(device: &Device, path: &Path) {
    import_path(device.conn(), path, None, None).expect("import");
}

fn push(device: &Device, relay: &dyn Relay) -> sync::PushResult {
    sync::push(device.conn(), master(), relay).expect("push")
}

fn pull(device: &Device, relay: &dyn Relay) -> PullResult {
    sync::pull(device.conn(), master(), relay).expect("pull")
}

fn keys_of(device: &Device) -> BTreeSet<(String, String, String)> {
    let mut stmt = device
        .conn()
        .prepare("SELECT stream, source_key, payload_hash FROM raw_records")
        .expect("prepare");
    let mapped = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("query");
    mapped.map(|r| r.expect("row")).collect()
}

type Fingerprint = (
    BTreeSet<(String, String, String, String, String)>,
    BTreeSet<String>,
    Vec<i64>,
);

/// What a second device must reproduce: raw keys and bytes, ranges, daily and sample counts.
fn fingerprint(device: &Device) -> Fingerprint {
    let conn = device.conn();
    let mut stmt = conn
        .prepare("SELECT stream, source_key, payload_hash, transport, imported_at FROM raw_records")
        .expect("prepare");
    let raw = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    let mut stmt = conn
        .prepare("SELECT stream || '|' || from_day || '|' || to_day FROM export_ranges")
        .expect("prepare");
    let ranges = stmt
        .query_map([], |r| r.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    let counts = [
        "SELECT count(*) FROM daily_metrics",
        "SELECT count(*) FROM daily_labels",
        "SELECT count(*) FROM metric_samples",
        "SELECT count(*) FROM monitoring_intervals",
        "SELECT count(*) FROM sleep_sessions",
        "SELECT count(*) FROM clock_offsets",
    ]
    .map(|sql| count(conn, sql))
    .to_vec();
    (raw, ranges, counts)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn canonical_hash(record_json: &str) -> String {
    sha256_hex(&canon::canonical(record_json.as_bytes()).expect("canonical"))
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(data).expect("write");
    encoder.finish().expect("finish")
}

fn header_for(seq: i64) -> Header {
    Header {
        device_id: "ffffffffffffffff".into(),
        device_seq: seq,
        prev: None,
        created_utc: "2025-07-01T00:00:00Z".into(),
    }
}

fn json_row(stream: &str, key: &str, data: &[u8]) -> RawRow {
    RawRow {
        stream: stream.into(),
        source_key: key.into(),
        source_scope: "vendor_cloud".into(),
        transport: "connect_export".into(),
        device_id: None,
        start_utc: None,
        end_utc: None,
        payload_kind: "json".into(),
        payload: zlib(data),
        payload_hash: sha256_hex(data),
        payload_bytes: data.len() as i64,
        imported_at: "2025-07-01T00:00:00Z".into(),
    }
}

fn put_bundle(relay: &FolderRelay, records: &[RawRow]) -> String {
    let name = new_name(&account_for(master())).expect("name");
    let blob = bundle::pack(master(), &name, "test", &header_for(1), records, &[]).expect("pack");
    relay.put(&name, &blob).expect("put");
    name
}

// ---------------------------------------------------------------- push / pull

#[test]
fn two_devices_with_split_data_converge_and_nothing_echoes() {
    let tmp = tempfile::tempdir().expect("tmp");
    let export = {
        let root = export_with_uds(
            tmp.path(),
            "export",
            &uds("2025-06-15", 4000, "2025-06-15T12:00:00.0"),
        );
        write(
            &root,
            "DI_CONNECT/DI-Connect-Metrics/TrainingReadinessDTO_111_111_111.json",
            &format!(
                "[{}]",
                readiness(
                    "2025-06-15",
                    "2025-06-15T04:00:00.0",
                    "AFTER_WAKEUP_RESET",
                    70
                )
            ),
        );
        root
    };
    let extra = fit_drop(tmp.path(), "extra", &MONITORING);
    let (a, b) = (device(), device());
    import(&a, &export);
    import(&b, &extra);
    let relay = relay_in(tmp.path());
    let pa = push(&a, &relay);
    let pb = push(&b, &relay);
    assert_eq!(
        (pa.bundles.len(), pa.records, pa.ranges),
        (1, 2, 1),
        "uds window only (the readiness name has none)"
    );
    assert_eq!((pb.bundles.len(), pb.ranges), (1, 0));
    assert!(pb.records >= 1);
    let (ra, rb) = (pull(&a, &relay), pull(&b, &relay));
    assert_eq!((ra.status, rb.status), ("ok", "ok"));
    assert_eq!(
        (ra.records_new as usize, ra.records_duplicate),
        (pb.records, 0),
        "A applies only B's records"
    );
    assert_eq!((rb.records_new as usize, rb.ranges_new), (pa.records, 1));
    assert_eq!(
        fingerprint(&a),
        fingerprint(&b),
        "identical raw keys, ranges, daily counts, samples"
    );
    // no echo: a second push from either side sends nothing
    assert!(push(&a, &relay).bundles.is_empty() && push(&b, &relay).bundles.is_empty());
    // idempotent: a re-pull changes nothing
    let before = fingerprint(&a);
    let again = pull(&a, &relay);
    assert!(again.applied.is_empty() && again.records_new == 0);
    assert_eq!(fingerprint(&a), before);
    // the incremental apply equals a full reparse on B
    let reference = fingerprint(&b);
    sources::reparse_all(b.conn(), None, false).expect("reparse");
    assert_eq!(fingerprint(&b), reference);
    // relay-origin records keep their origin transport; the pull is one `relay` import run
    let transports: BTreeSet<String> = {
        let mut stmt = b
            .conn()
            .prepare("SELECT DISTINCT transport FROM raw_records")
            .expect("prepare");
        stmt.query_map([], |r| r.get(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    };
    assert_eq!(
        transports,
        BTreeSet::from(["connect_export".to_string(), "drop".to_string()])
    );
    assert_eq!(
        count(
            b.conn(),
            "SELECT count(*) FROM import_runs WHERE transport='relay' AND status='ok'"
        ),
        1
    );
}

#[test]
fn late_bundles_are_applied_and_rejected_ones_retried() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    import(&a, &fit_drop(tmp.path(), "d1", &["monitoring_timestamp16"]));
    let relay = relay_in(tmp.path());
    let first = push(&a, &relay).bundles[0].clone();
    // a stranger's object (version byte right, so it fails authentication) arrives before B pulls
    let account = account_for(master());
    let garbage = new_name(&account).expect("name");
    let mut noise = vec![0x55u8; 70_000];
    noise[0] = 1;
    relay.put(&garbage, &noise).expect("put");
    let r = pull(&b, &relay);
    assert_eq!(r.applied, vec![first.clone()]);
    assert_eq!(
        r.rejected,
        vec![(garbage.clone(), "authentication_failed".to_string())]
    );
    assert_eq!(r.status, "partial");
    // a late bundle is applied on the next pull; the garbage is retried and rejected again
    import(
        &a,
        &fit_drop(tmp.path(), "d2", &["monitoring_cycles_resolution"]),
    );
    let second = push(&a, &relay).bundles[0].clone();
    let r2 = pull(&b, &relay);
    assert_eq!(r2.applied, vec![second]);
    assert_eq!(
        r2.rejected,
        vec![(garbage, "authentication_failed".to_string())]
    );
    assert_eq!(keys_of(&a), keys_of(&b));
    let report = sync::status(b.conn()).expect("status");
    assert_eq!(report.bundles.get("pulled_applied"), Some(&2));
    assert_eq!(report.bundles.get("pulled_rejected"), Some(&1));
    assert!(report.gaps.is_empty());
    // the relay import run of a pull that rejected something is partial (both pulls did)
    assert_eq!(
        count(
            b.conn(),
            "SELECT count(*) FROM import_runs WHERE transport='relay' AND status='partial'"
        ),
        2
    );
}

#[test]
fn a_wrong_master_a_renamed_copy_and_an_oversized_object_are_rejected_with_their_reasons() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    import(&a, &fit_drop(tmp.path(), "d", &["monitoring_timestamp16"]));
    let relay = relay_in(tmp.path());
    let good = push(&a, &relay).bundles[0].clone();
    let account = account_for(master());
    // the operator copies an object to a new name: the AAD no longer matches
    let renamed = new_name(&account).expect("name");
    relay
        .put(&renamed, &relay.get(&good).expect("get"))
        .expect("put");
    // an object past the size cap is refused before it is read
    let oversized = new_name(&account).expect("name");
    relay.put(&oversized, b"x").expect("put");
    fs::OpenOptions::new()
        .write(true)
        .open(tmp.path().join("relay").join(&oversized))
        .expect("open")
        .set_len(MAX_OBJECT + 1)
        .expect("sparse");
    let r = pull(&b, &relay);
    assert_eq!(r.applied, vec![good.clone()]);
    let mut rejected = r.rejected.clone();
    rejected.sort();
    let mut expected = vec![
        (renamed, "authentication_failed".to_string()),
        (oversized, "too_large".to_string()),
    ];
    expected.sort();
    assert_eq!(rejected, expected);
    assert_eq!(keys_of(&a), keys_of(&b));
    // a different master fails every object, whatever its name (copied under the other account)
    let c = device();
    let other = other_master();
    let other_relay = relay_in(&tmp.path().join("elsewhere"));
    let other_name = new_name(&account_for(&other)).expect("name");
    other_relay
        .put(&other_name, &relay.get(&good).expect("get"))
        .expect("put");
    let r = sync::pull(c.conn(), &other, &other_relay).expect("pull");
    assert_eq!(
        r.rejected,
        vec![(other_name, "authentication_failed".to_string())]
    );
    assert!(r.applied.is_empty());
    assert_eq!(count(c.conn(), "SELECT count(*) FROM raw_records"), 0);
}

#[test]
fn poison_bundles_are_rejected_without_blocking_the_rest() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    import(&a, &fit_drop(tmp.path(), "d", &["monitoring_timestamp16"]));
    let relay = relay_in(tmp.path());
    let account = account_for(master());
    let head =
        r#"{"t":"h","format":1,"device_id":"zz","device_seq":1,"prev":null,"created_utc":"x"}"#;
    let mut poisoned = Vec::new();
    for (items, reason) in [
        (
            vec![head, r#"{"t":"x","stream":"s","from_day":"a"}"#],
            "bad_bundle",
        ),
        (
            vec![r#"{"t":"h","format":1,"device_seq":"1"}"#],
            "bad_header",
        ),
        (vec![head, "[1,2]"], "bad_bundle"),
    ] {
        let name = new_name(&account).expect("name");
        let lines: Vec<Vec<u8>> = items.iter().map(|s| s.as_bytes().to_vec()).collect();
        relay
            .put(&name, &seal_lines(master(), &name, &lines).expect("seal"))
            .expect("put");
        poisoned.push((name, reason.to_string()));
    }
    let good = push(&a, &relay).bundles[0].clone();
    let r = pull(&b, &relay);
    assert_eq!(r.applied, vec![good]);
    let mut got = r.rejected.clone();
    got.sort();
    poisoned.sort();
    assert_eq!(got, poisoned);
    assert_eq!(r.status, "partial");
    assert_eq!(keys_of(&a), keys_of(&b));
}

#[test]
fn a_dropped_middle_bundle_shows_as_a_chain_gap() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    let relay = relay_in(tmp.path());
    import(&a, &fit_drop(tmp.path(), "d1", &["monitoring_timestamp16"]));
    let first = push(&a, &relay).bundles[0].clone();
    import(
        &a,
        &fit_drop(tmp.path(), "d2", &["monitoring_cycles_resolution"]),
    );
    let second = push(&a, &relay).bundles[0].clone();
    import(&a, &fit_drop(tmp.path(), "d3", &["skin_temp"]));
    let third = push(&a, &relay).bundles[0].clone();
    // the relay loses the middle bundle
    let middle = relay.get(&second).expect("get");
    fs::remove_file(tmp.path().join("relay").join(&second)).expect("drop it");
    let r = pull(&b, &relay);
    // bundles apply in name order (random), so compare as a set
    let mut applied = r.applied.clone();
    applied.sort();
    let mut expected = vec![first, third];
    expected.sort();
    assert_eq!(applied, expected);
    assert_eq!(r.gaps.len(), 1);
    assert_eq!(
        (r.gaps[0].missing.as_str(), r.gaps[0].device_seq),
        (second.as_str(), 3)
    );
    assert_eq!(sync::status(b.conn()).expect("status").gaps.len(), 1);
    // the late arrival closes the gap
    relay.put(&second, &middle).expect("put back");
    let late = pull(&b, &relay);
    assert_eq!(late.applied, vec![second]);
    assert!(late.gaps.is_empty());
    assert_eq!(keys_of(&a), keys_of(&b));
}

#[test]
fn forget_then_push_republishes_under_the_same_account() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    let relay = relay_in(tmp.path());
    import(&a, &fit_drop(tmp.path(), "d", &MONITORING));
    let first = push(&a, &relay);
    pull(&b, &relay);
    assert!(
        push(&b, &relay).bundles.is_empty(),
        "received records are never pushed back"
    );
    sync::forget_relay_state(b.conn()).expect("forget");
    assert_eq!(
        count(b.conn(), "SELECT count(*) FROM relay_seen")
            + count(b.conn(), "SELECT count(*) FROM relay_bundles"),
        0
    );
    let again = push(&b, &relay);
    assert_eq!(again.bundles.len(), 1);
    assert_eq!(again.records, first.records);
    assert_eq!(relay.list(&account_for(master())).expect("list").len(), 2);
}

#[test]
fn the_device_row_is_created_lazily_and_the_chain_links_bundles() {
    let tmp = tempfile::tempdir().expect("tmp");
    let a = device();
    let relay = relay_in(tmp.path());
    assert!(push(&a, &relay).bundles.is_empty());
    assert_eq!(
        count(a.conn(), "SELECT count(*) FROM relay_device"),
        0,
        "nothing to send, no device row"
    );
    import(&a, &fit_drop(tmp.path(), "d1", &["monitoring_timestamp16"]));
    let one = push(&a, &relay).bundles[0].clone();
    import(
        &a,
        &fit_drop(tmp.path(), "d2", &["monitoring_cycles_resolution"]),
    );
    let two = push(&a, &relay).bundles[0].clone();
    let (next, last): (i64, String) = a
        .conn()
        .query_row(
            "SELECT next_seq, last_bundle FROM relay_device WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("device");
    assert_eq!((next, last), (3, two.clone()));
    let blob = relay.get(&two).expect("get");
    let opened = unpack(master(), &two, &blob).expect("unpack");
    assert_eq!(
        (opened.header.device_seq, opened.header.prev),
        (2, Some(one))
    );
}

#[test]
fn a_push_splits_on_compressed_length_and_ranges_ride_in_the_last_bundle() {
    let tmp = tempfile::tempdir().expect("tmp");
    let a = device();
    let relay = relay_in(tmp.path());
    // four 3 MB payloads (zeros: cheap to seal; the split counts the stored column, not the ciphertext)
    for i in 0..4 {
        a.conn()
            .execute(
                "INSERT INTO raw_records(stream, source_key, source_scope, transport, payload_kind, payload, payload_hash, \
                 payload_bytes, imported_at) VALUES('fit:monitoring_b', ?, 'device', 'usb', 'fit', ?, ?, 1, '2025-07-01T00:00:00Z')",
                rusqlite::params![format!("{i:064x}"), vec![0u8; 3 * 1024 * 1024], format!("{i:064x}")],
            )
            .expect("insert");
    }
    a.conn()
        .execute(
            "INSERT INTO import_runs(started_at, transport, status) VALUES('x', 'drop', 'ok')",
            [],
        )
        .expect("run");
    for stream in ["json:uds", "json:sleep"] {
        a.conn()
            .execute("INSERT INTO export_ranges(run_id, stream, from_day, to_day) VALUES(1, ?, '2025-06-01', '2025-06-30')", [stream])
            .expect("range");
    }
    let r = push(&a, &relay);
    assert_eq!((r.bundles.len(), r.records, r.ranges), (2, 4, 2));
    let counts: Vec<(usize, usize)> = r
        .bundles
        .iter()
        .map(|name| {
            let opened = unpack(master(), name, &relay.get(name).expect("get")).expect("unpack");
            (opened.records.len(), opened.ranges.len())
        })
        .collect();
    assert_eq!(
        counts,
        vec![(2, 0), (2, 2)],
        "ranges only in the last bundle"
    );
    // a puller counts the junk payloads as invalid records but applies both bundles
    let b = device();
    let pulled = pull(&b, &relay);
    assert_eq!(
        (
            pulled.applied.len(),
            pulled.records_invalid,
            pulled.ranges_new
        ),
        (2, 4, 2)
    );
    assert!(pulled.gaps.is_empty());
    assert_eq!(count(b.conn(), "SELECT count(*) FROM raw_records"), 0);
}

#[test]
fn fit_bytes_under_another_stream_label_are_one_record() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    let drop = fit_drop(tmp.path(), "d", &["monitoring_timestamp16"]);
    import(&a, &drop);
    import(&b, &drop);
    a.conn()
        .execute("UPDATE raw_records SET stream='fit:legacy'", [])
        .expect("relabel");
    let relay = relay_in(tmp.path());
    push(&a, &relay);
    let r = pull(&b, &relay);
    assert_eq!((r.records_new, r.records_duplicate), (0, 1));
    assert_eq!(count(b.conn(), "SELECT count(*) FROM raw_records"), 1);
    assert_eq!(
        count(b.conn(), "SELECT count(*) FROM relay_seen"),
        1,
        "marked through the FIT key: B will never push it back"
    );
    assert!(push(&b, &relay).bundles.is_empty());
}

#[test]
fn a_pulled_record_is_marked_through_every_raw_id_above_the_mark() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    import(&a, &fit_drop(tmp.path(), "d", &MONITORING));
    let relay = relay_in(tmp.path());
    let pushed = push(&a, &relay);
    pull(&b, &relay);
    assert_eq!(
        count(b.conn(), "SELECT count(*) FROM raw_records") as usize,
        pushed.records
    );
    assert_eq!(
        count(
            b.conn(),
            "SELECT count(*) FROM relay_seen WHERE direction='pulled'"
        ) as usize,
        pushed.records
    );
    assert_eq!(count(b.conn(), "SELECT count(*) FROM relay_seen_ranges"), 0);
}

// ---------------------------------------------------------------- conflicts

fn steps_of(device: &Device) -> f64 {
    device
        .conn()
        .query_row(
            "SELECT value FROM daily_metrics WHERE metric='steps' AND source_scope='vendor_cloud'",
            [],
            |r| r.get(0),
        )
        .expect("steps")
}

#[test]
fn a_uds_pair_converges_on_the_later_observation_in_both_orders() {
    let early = uds("2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let late = uds("2025-06-15", 8000, "2025-06-15T21:00:00.0");
    for (order, (first, second)) in [(&early, &late), (&late, &early)].into_iter().enumerate() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (a, b) = (device(), device());
        import(&a, &export_with_uds(tmp.path(), "x", first));
        import(&b, &export_with_uds(tmp.path(), "y", second));
        let relay = relay_in(tmp.path());
        push(&a, &relay);
        push(&b, &relay);
        let (ra, rb) = (pull(&a, &relay), pull(&b, &relay));
        assert!(ra.conflicts + rb.conflicts >= 1, "order {order}");
        assert_eq!(
            (steps_of(&a), steps_of(&b)),
            (8000.0, 8000.0),
            "the later observation wins on both"
        );
        assert_eq!(
            count(a.conn(), "SELECT count(*) FROM raw_superseded")
                + count(b.conn(), "SELECT count(*) FROM raw_superseded"),
            2,
            "each store keeps the loser it saw"
        );
        for d in [&a, &b] {
            let rules: BTreeSet<String> = {
                let mut stmt = d
                    .conn()
                    .prepare("SELECT rule FROM sync_conflicts")
                    .expect("prepare");
                stmt.query_map([], |r| r.get(0))
                    .expect("query")
                    .map(|r| r.expect("row"))
                    .collect()
            };
            assert_eq!(rules, BTreeSet::from(["observed_utc".to_string()]));
        }
        assert_eq!(keys_of(&a), keys_of(&b));
        // a second round is quiet
        push(&a, &relay);
        push(&b, &relay);
        let (ra2, rb2) = (pull(&a, &relay), pull(&b, &relay));
        assert_eq!(
            (
                ra2.conflicts,
                rb2.conflicts,
                ra2.records_new,
                rb2.records_new
            ),
            (0, 0, 0, 0)
        );
    }
}

#[test]
fn a_readiness_pair_converges_by_hash_alone_and_stays_quiet() {
    let first = readiness(
        "2025-06-15",
        "2025-06-15T04:00:00.0",
        "AFTER_WAKEUP_RESET",
        70,
    );
    let second = readiness(
        "2025-06-15",
        "2025-06-15T04:00:00.0",
        "AFTER_WAKEUP_RESET",
        75,
    );
    let larger = [canonical_hash(&first), canonical_hash(&second)]
        .into_iter()
        .max()
        .expect("max");
    for (first, second) in [(&first, &second), (&second, &first)] {
        let tmp = tempfile::tempdir().expect("tmp");
        let (a, b) = (device(), device());
        import(&a, &export_with_readiness(tmp.path(), "x", first));
        import(&b, &export_with_readiness(tmp.path(), "y", second));
        let relay = relay_in(tmp.path());
        push(&a, &relay);
        push(&b, &relay);
        let (ra, rb) = (pull(&a, &relay), pull(&b, &relay));
        assert_eq!(
            (ra.conflicts, rb.conflicts),
            (1, 1),
            "both sides record the one decision"
        );
        let hashes: Vec<Vec<String>> = [&a, &b]
            .iter()
            .map(|d| {
                let mut stmt = d
                    .conn()
                    .prepare("SELECT payload_hash FROM raw_records WHERE stream='json:readiness'")
                    .expect("prepare");
                stmt.query_map([], |r| r.get(0))
                    .expect("query")
                    .map(|r| r.expect("row"))
                    .collect()
            })
            .collect();
        assert_eq!(hashes[0], hashes[1]);
        assert_eq!(
            hashes[0],
            vec![larger.clone()],
            "the larger hash wins on both sides"
        );
        let scores: Vec<f64> = [&a, &b]
            .iter()
            .map(|d| {
                d.conn()
                    .query_row(
                        "SELECT value FROM daily_metrics WHERE metric='training_readiness'",
                        [],
                        |r| r.get(0),
                    )
                    .expect("score")
            })
            .collect();
        assert_eq!(scores[0], scores[1]);
        for d in [&a, &b] {
            let rule: String = d
                .conn()
                .query_row("SELECT DISTINCT rule FROM sync_conflicts", [], |r| r.get(0))
                .expect("rule");
            assert_eq!(rule, "payload_hash");
        }
        // a second round must find nothing to swap: the winner is a fixed point
        push(&a, &relay);
        push(&b, &relay);
        let (ra2, rb2) = (pull(&a, &relay), pull(&b, &relay));
        assert_eq!(
            (
                ra2.conflicts,
                rb2.conflicts,
                ra2.records_new,
                rb2.records_new
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(keys_of(&a), keys_of(&b));
    }
}

#[test]
fn a_conflict_against_a_record_with_a_past_decode_failure_does_not_wedge() {
    let early = uds("2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let late = uds("2025-06-15", 8000, "2025-06-15T21:00:00.0");
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    import(&a, &export_with_uds(tmp.path(), "x", &early));
    import(&b, &export_with_uds(tmp.path(), "y", &late));
    // a past reparse failure points at the losing record
    a.conn()
        .execute(
            "INSERT INTO import_failures(run_id, stream, raw_record_id, kind, recorded_at) \
             VALUES(1, 'json:uds', (SELECT id FROM raw_records), 'x', 'now')",
            [],
        )
        .expect("failure row");
    let relay = relay_in(tmp.path());
    push(&a, &relay);
    push(&b, &relay);
    let r = pull(&a, &relay);
    assert_eq!((r.conflicts, r.status), (1, "ok"));
    assert_eq!(count(a.conn(), "SELECT count(*) FROM raw_records"), 1);
    assert_eq!(steps_of(&a), 8000.0);
    assert_eq!(count(a.conn(), "SELECT count(*) FROM sync_conflicts"), 1);
    assert_eq!(
        count(
            a.conn(),
            "SELECT count(*) FROM import_failures WHERE raw_record_id IS NOT NULL"
        ),
        0
    );
    let again = pull(&a, &relay);
    assert!(again.applied.is_empty() && again.conflicts == 0);
}

/// Daily rows plus labels, no ids: what a reparse must leave exactly as it found it.
fn daily_rows(device: &Device) -> BTreeSet<String> {
    let mut stmt = device
        .conn()
        .prepare(
            "SELECT 'm|' || date || '|' || metric || '|' || source_scope || '|' || value || '|' || COALESCE(observed_utc, '') \
             FROM daily_metrics UNION ALL \
             SELECT 'l|' || date || '|' || metric || '|' || source_scope || '|' || label || '|' || COALESCE(observed_utc, '') \
             FROM daily_labels",
        )
        .expect("prepare");
    stmt.query_map([], |r| r.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

fn pulled_statuses(device: &Device) -> Vec<String> {
    let mut stmt = device
        .conn()
        .prepare("SELECT status FROM relay_bundles WHERE direction='pulled'")
        .expect("prepare");
    stmt.query_map([], |r| r.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

#[test]
fn a_failed_winner_write_rolls_the_whole_conflict_back_and_the_next_pull_converges() {
    let early = uds("2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let late = uds("2025-06-15", 8000, "2025-06-15T21:00:00.0");
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    import(&a, &export_with_uds(tmp.path(), "x", &early));
    import(&b, &export_with_uds(tmp.path(), "y", &late));
    let relay = relay_in(tmp.path());
    push(&a, &relay);
    push(&b, &relay);
    let (incoming, loser) = (canonical_hash(&late), canonical_hash(&early));
    a.conn()
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER inject BEFORE INSERT ON raw_records WHEN NEW.payload_hash='{incoming}' \
             BEGIN SELECT RAISE(ABORT,'injected'); END"
        ))
        .expect("trigger");
    let error =
        sync::pull(a.conn(), master(), &relay).expect_err("the pull reports the storage error");
    assert!(
        matches!(error, SyncError::WriteFailed(_)),
        "{error:?}"
    );
    assert!(a.conn().is_autocommit(), "no transaction left open");
    let stored: Vec<String> = {
        let mut stmt = a
            .conn()
            .prepare("SELECT payload_hash FROM raw_records WHERE stream='json:uds'")
            .expect("prepare");
        stmt.query_map([], |r| r.get(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    };
    assert_eq!(stored, vec![loser], "the loser is still stored");
    assert_eq!(steps_of(&a), 4000.0, "and still feeds its daily row");
    assert_eq!(count(a.conn(), "SELECT count(*) FROM sync_conflicts"), 0);
    assert_eq!(count(a.conn(), "SELECT count(*) FROM raw_superseded"), 0);
    assert_eq!(
        count(
            a.conn(),
            &format!(
                "SELECT count(*) FROM relay_seen s JOIN raw_records r ON r.id=s.raw_record_id \
                 WHERE r.payload_hash='{incoming}'"
            )
        ),
        0
    );
    assert_eq!(pulled_statuses(&a), vec!["applying".to_string()]);
    a.conn().execute_batch("DROP TRIGGER inject").expect("drop");
    let retry = pull(&a, &relay);
    assert_eq!(
        (retry.status, retry.conflicts, retry.applied.len()),
        ("ok", 1, 1)
    );
    pull(&b, &relay);
    assert_eq!(fingerprint(&a), fingerprint(&b));
    assert_eq!(steps_of(&a), 8000.0);
    assert_eq!(pulled_statuses(&a), vec!["applied".to_string()]);
    let before = daily_rows(&a);
    sources::reparse_all(a.conn(), None, false).expect("reparse");
    assert_eq!(
        daily_rows(&a),
        before,
        "a reparse of the converged store changes no daily row"
    );
}

#[test]
fn a_failed_loser_record_leaves_no_transaction_open() {
    let early = uds("2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let late = uds("2025-06-15", 8000, "2025-06-15T21:00:00.0");
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    import(&a, &export_with_uds(tmp.path(), "x", &early));
    import(&b, &export_with_uds(tmp.path(), "y", &late));
    let relay = relay_in(tmp.path());
    push(&a, &relay);
    push(&b, &relay);
    // b holds the winner: a's bundle brings the loser
    b.conn()
        .execute_batch(
            "CREATE TEMP TRIGGER inject BEFORE INSERT ON raw_superseded BEGIN SELECT RAISE(ABORT,'injected'); END",
        )
        .expect("trigger");
    assert!(sync::pull(b.conn(), master(), &relay).is_err());
    assert!(
        b.conn().is_autocommit(),
        "the incoming-loses branch rolled back"
    );
    assert_eq!(count(b.conn(), "SELECT count(*) FROM sync_conflicts"), 0);
    assert_eq!(steps_of(&b), 8000.0);
    b.conn().execute_batch("DROP TRIGGER inject").expect("drop");
    b.conn()
        .execute(
            "INSERT INTO import_runs(started_at, transport, status) VALUES('now', 'probe', 'ok')",
            [],
        )
        .expect("a following write works");
    let again = pull(&b, &relay);
    assert_eq!((again.conflicts, again.status), (1, "ok"));
    assert_eq!(count(b.conn(), "SELECT count(*) FROM sync_conflicts"), 1);
    assert_eq!(count(b.conn(), "SELECT count(*) FROM raw_superseded"), 1);
}

#[test]
fn the_conflict_rule_is_one_pure_function_of_the_two_rows() {
    // direct: an existing uds record, an incoming one with the same observed time and the same key
    let tmp = tempfile::tempdir().expect("tmp");
    let a = device();
    import(
        &a,
        &export_with_uds(
            tmp.path(),
            "x",
            &uds("2025-06-15", 4000, "2025-06-15T12:00:00.0"),
        ),
    );
    let relay = relay_in(tmp.path());
    let same_time = uds("2025-06-15", 9000, "2025-06-15T12:00:00.0");
    let canon_same = canon::canonical(same_time.as_bytes()).expect("canonical");
    let name = put_bundle(&relay, &[json_row("json:uds", "2025-06-15", &canon_same)]);
    let existing_hash: String = a
        .conn()
        .query_row("SELECT payload_hash FROM raw_records", [], |r| r.get(0))
        .expect("hash");
    let incoming_hash = sha256_hex(&canon_same);
    let r = pull(&a, &relay);
    assert_eq!(r.applied, vec![name]);
    assert_eq!(r.conflicts, 1);
    let (winner, rule): (String, String) = a
        .conn()
        .query_row("SELECT winner_hash, rule FROM sync_conflicts", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .expect("decision");
    assert_eq!(
        rule, "payload_hash",
        "a tie in observed time falls to the hash"
    );
    assert_eq!(winner, existing_hash.clone().max(incoming_hash));
}

// ---------------------------------------------------------------- crash recovery and escapes

#[test]
fn a_half_applied_bundle_is_repaired_by_the_next_pull_through_reparse() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    let export = export_with_uds(
        tmp.path(),
        "x",
        &uds("2025-06-15", 4000, "2025-06-15T12:00:00.0"),
    );
    import(&a, &export);
    import(&a, &fit_drop(tmp.path(), "d", &MONITORING));
    let relay = relay_in(tmp.path());
    push(&a, &relay);
    pull(&b, &relay);
    let healthy = fingerprint(&b);
    assert!(healthy.2[0] > 0 && healthy.2[2] > 0);
    // simulate a crash after the record loop: records are in, derived rows are not, status 'applying'
    for table in [
        "daily_metrics",
        "daily_labels",
        "metric_samples",
        "monitoring_intervals",
        "sleep_stages",
        "sleep_sessions",
        "clock_offsets",
    ] {
        b.conn()
            .execute(&format!("DELETE FROM {table}"), [])
            .expect("wipe");
    }
    b.conn()
        .execute("UPDATE relay_bundles SET status='applying'", [])
        .expect("half-applied");
    assert_ne!(fingerprint(&b).2, healthy.2);
    let r = pull(&b, &relay);
    assert_eq!(
        r.applied.len(),
        1,
        "the half-applied bundle is applied again"
    );
    assert_eq!(
        fingerprint(&b),
        healthy,
        "the re-applied bundle re-derived its streams"
    );
    assert_eq!(
        count(
            b.conn(),
            "SELECT count(*) FROM relay_bundles WHERE status='applied'"
        ),
        1
    );
    assert!(
        count(
            b.conn(),
            "SELECT count(*) FROM import_runs WHERE transport='reparse'"
        ) >= 1
    );
}

#[test]
fn a_record_that_is_not_an_object_aborts_the_whole_pull() {
    let tmp = tempfile::tempdir().expect("tmp");
    let b = device();
    let relay = relay_in(tmp.path());
    let name = put_bundle(&relay, &[json_row("json:uds", "2025-06-15", b"[1,2]")]);
    let error =
        sync::pull(b.conn(), master(), &relay).expect_err("an AttributeError in the oracle");
    assert!(
        matches!(&error, SyncError::Abort(m) if m.starts_with("AttributeError")),
        "{error}"
    );
    let status: String = b
        .conn()
        .query_row(
            "SELECT status FROM relay_bundles WHERE name=?",
            [&name],
            |r| r.get(0),
        )
        .expect("bundle row");
    assert_eq!(status, "applying", "left half-applied for the next pull");
    let (run_status, run_error): (String, Option<String>) = b
        .conn()
        .query_row(
            "SELECT status, error FROM import_runs WHERE transport='relay'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("run row");
    assert_eq!(run_status, "failed");
    assert!(run_error.is_some());
    // a readiness record that is not an object only aborts at the store-wide batch
    let c = device();
    let relay2 = relay_in(&tmp.path().join("two"));
    put_bundle(
        &relay2,
        &[json_row("json:readiness", "2025-06-15|x", b"[1]")],
    );
    let error = sync::pull(c.conn(), master(), &relay2).expect_err("abort at the batch");
    assert!(
        matches!(error, SyncError::Source(SourceError::Abort(_))),
        "{error:?}"
    );
}

#[test]
fn bytes_that_fail_their_hashes_or_decode_to_nothing_are_counted_invalid() {
    let tmp = tempfile::tempdir().expect("tmp");
    let b = device();
    let relay = relay_in(tmp.path());
    let good = canon::canonical(uds("2025-06-15", 1, "2025-06-15T12:00:00.0").as_bytes())
        .expect("canonical");
    let mut wrong_hash = json_row("json:uds", "2025-06-16", &good);
    wrong_hash.payload_hash = "0".repeat(64);
    let mut wrong_size = json_row("json:uds", "2025-06-17", &good);
    wrong_size.payload_bytes += 1;
    let mut not_zlib = json_row("json:uds", "2025-06-18", &good);
    not_zlib.payload = b"not zlib".to_vec();
    let no_decoder = json_row("json:unknown", "k", &good);
    let not_json = json_row("json:uds", "2025-06-19", b"{broken");
    let no_date = json_row("json:uds", "2025-06-20", br#"{"totalSteps":3}"#);
    let kind = {
        let mut row = json_row("json:uds", "2025-06-21", &good);
        row.payload_kind = "xml".into();
        row
    };
    let ok = json_row("json:uds", "2025-06-15", &good);
    let name = put_bundle(
        &relay,
        &[
            wrong_hash, wrong_size, not_zlib, no_decoder, not_json, no_date, kind, ok,
        ],
    );
    let r = pull(&b, &relay);
    assert_eq!(r.applied, vec![name]);
    assert_eq!((r.records_new, r.records_invalid), (1, 7));
    assert_eq!(count(b.conn(), "SELECT count(*) FROM raw_records"), 1);
}

#[test]
fn status_counts_and_forget_clear_only_relay_state() {
    let tmp = tempfile::tempdir().expect("tmp");
    let a = device();
    import(&a, &fit_drop(tmp.path(), "d", &MONITORING));
    let relay = relay_in(tmp.path());
    let before = sync::status(a.conn()).expect("status");
    assert!(before.records_unsent > 0 && before.records_seen == 0 && before.bundles.is_empty());
    push(&a, &relay);
    let after = sync::status(a.conn()).expect("status");
    assert_eq!(
        (after.records_unsent, after.records_seen),
        (0, before.records_unsent)
    );
    assert_eq!(after.bundles.get("pushed_applied"), Some(&1));
    let raw = count(a.conn(), "SELECT count(*) FROM raw_records");
    sync::forget_relay_state(a.conn()).expect("forget");
    assert_eq!(
        count(a.conn(), "SELECT count(*) FROM raw_records"),
        raw,
        "records are local history, not relay state"
    );
    assert_eq!(sync::status(a.conn()).expect("status").records_unsent, raw);
}

#[test]
fn a_listed_object_that_vanishes_before_it_is_read_is_rejected_as_file_not_found() {
    struct Vanishing(FolderRelay, String);
    impl Relay for Vanishing {
        fn put(
            &self,
            name: &str,
            data: &[u8],
        ) -> Result<(), disconect_core::relay::folder::RelayError> {
            self.0.put(name, data)
        }
        fn get(&self, name: &str) -> Result<Vec<u8>, disconect_core::relay::folder::RelayError> {
            if name == self.1 {
                fs::remove_file(self.0.root().join(name))?;
            }
            self.0.get(name)
        }
        fn list(
            &self,
            account: &str,
        ) -> Result<Vec<String>, disconect_core::relay::folder::RelayError> {
            self.0.list(account)
        }
        fn delete(&self, name: &str) -> Result<(), disconect_core::relay::folder::RelayError> {
            self.0.delete(name)
        }
    }
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    import(&a, &fit_drop(tmp.path(), "d", &["monitoring_timestamp16"]));
    let inner = relay_in(tmp.path());
    let name = push(&a, &inner).bundles[0].clone();
    let relay = Vanishing(inner, name.clone());
    let r = sync::pull(b.conn(), master(), &relay).expect("pull");
    assert_eq!(r.rejected, vec![(name, "FileNotFoundError".to_string())]);
    assert_eq!(r.status, "partial");
}

// ---------------------------------------------------------------- 12a review (F1-F4)

/// One UDS record per day, each in its own file (the dated name keeps the days apart).
fn export_with_days(dir: &Path, name: &str, records: &[(&str, i64, &str)]) -> PathBuf {
    let root = dir.join(name);
    for (day, steps, end) in records {
        write(
            &root,
            &format!("DI_CONNECT/DI-Connect-Aggregator/UDSFile_{day}_{day}.json"),
            &format!("[{}]", uds(day, *steps, &format!("{day}T{end}:00:00.0"))),
        );
    }
    fs::create_dir_all(root.join("DI_CONNECT/DI-Connect-Uploaded-Files")).expect("mkdir");
    root
}

fn seen_count(device: &Device, payload_hash: &str) -> i64 {
    count(
        device.conn(),
        &format!(
            "SELECT count(*) FROM relay_seen s JOIN raw_records r ON r.id=s.raw_record_id \
             WHERE r.payload_hash='{payload_hash}'"
        ),
    )
}

fn unsent(device: &Device) -> i64 {
    count(
        device.conn(),
        "SELECT count(*) FROM raw_records r LEFT JOIN relay_seen s ON s.raw_record_id=r.id \
         WHERE s.raw_record_id IS NULL",
    )
}

#[test]
fn f1_the_winner_is_marked_seen_when_the_loser_held_the_max_rowid() {
    let early = uds("2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let late = uds("2025-06-15", 8000, "2025-06-15T21:00:00.0");
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    import(&a, &export_with_uds(tmp.path(), "x", &early));
    import(&b, &export_with_uds(tmp.path(), "y", &late));
    let relay = relay_in(tmp.path());
    push(&a, &relay);
    push(&b, &relay);
    let r = pull(&a, &relay);
    assert_eq!((r.conflicts, r.status), (1, "ok"));
    assert_eq!(seen_count(&a, &canonical_hash(&late)), 1, "the winner is relay_seen");
    assert_eq!(unsent(&a), 0, "a clean conflict pull leaves nothing to push back");
    assert_eq!(push(&a, &relay).records, 0, "the winner is not echoed");
}

#[test]
fn f2_a_retried_pull_marks_the_already_stored_winner_seen() {
    let early = uds("2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let late = uds("2025-06-15", 8000, "2025-06-15T21:00:00.0");
    let tmp = tempfile::tempdir().expect("tmp");
    let (a, b) = (device(), device());
    // the loser (06-15) is rowid 1, a second day takes rowid 2
    import(
        &a,
        &export_with_days(tmp.path(), "x", &[("2025-06-15", 4000, "12"), ("2025-06-16", 3000, "21")]),
    );
    import(&b, &export_with_uds(tmp.path(), "y", &late));
    let _ = early;
    let relay = relay_in(tmp.path());
    push(&a, &relay);
    push(&b, &relay);
    let incoming = canonical_hash(&late);
    a.conn()
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER inject BEFORE INSERT ON relay_seen WHEN \
             (SELECT payload_hash FROM raw_records WHERE id=NEW.raw_record_id)='{incoming}' \
             BEGIN SELECT RAISE(ABORT,'crash after commit'); END"
        ))
        .expect("trigger");
    assert!(sync::pull(a.conn(), master(), &relay).is_err());
    assert_eq!(pulled_statuses(&a), vec!["applying".to_string()]);
    a.conn().execute_batch("DROP TRIGGER inject").expect("drop");
    let retry = pull(&a, &relay);
    assert_eq!((retry.status, retry.applied.len()), ("ok", 1));
    assert_eq!(seen_count(&a, &incoming), 1, "the retry marked the winner seen");
    assert_eq!(count(a.conn(), "SELECT count(*) FROM sync_conflicts"), 1);
    assert_eq!(count(a.conn(), "SELECT count(*) FROM raw_superseded"), 1);
    assert_eq!(unsent(&a), 0);
}

#[test]
fn f3_a_plain_record_storage_failure_keeps_the_bundle_applying() {
    let late = uds("2025-06-15", 8000, "2025-06-15T21:00:00.0");
    for abort in ["ABORT", "ROLLBACK"] {
        let tmp = tempfile::tempdir().expect("tmp");
        let (feeder, puller) = (device(), device());
        import(&feeder, &export_with_uds(tmp.path(), "y", &late));
        let relay = relay_in(tmp.path());
        push(&feeder, &relay);
        let incoming = canonical_hash(&late);
        puller
            .conn()
            .execute_batch(&format!(
                "CREATE TEMP TRIGGER inject BEFORE INSERT ON raw_records WHEN NEW.payload_hash='{incoming}' \
                 BEGIN SELECT RAISE({abort},'injected'); END"
            ))
            .expect("trigger");
        let error = sync::pull(puller.conn(), master(), &relay).expect_err("a storage failure fails the pull");
        assert!(matches!(error, SyncError::WriteFailed(_)), "{abort}: {error:?}");
        assert!(puller.conn().is_autocommit(), "no transaction left open");
        assert_eq!(pulled_statuses(&puller), vec!["applying".to_string()]);
        assert_eq!(count(puller.conn(), "SELECT count(*) FROM raw_records"), 0);
        puller.conn().execute_batch("DROP TRIGGER inject").expect("drop");
        let retry = pull(&puller, &relay);
        assert_eq!((retry.status, retry.records_new, retry.applied.len()), ("ok", 1, 1));
        assert_eq!(daily_rows(&puller), daily_rows(&feeder), "{abort}: the daily rows converged");
        assert_eq!(pulled_statuses(&puller), vec!["applied".to_string()]);
    }
}

fn history(device: &Device) -> (i64, i64) {
    (
        count(device.conn(), "SELECT count(*) FROM sync_conflicts"),
        count(device.conn(), "SELECT count(*) FROM raw_superseded"),
    )
}

#[test]
fn f4_a_reapplied_bundle_does_not_duplicate_its_incoming_loser_rows() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (feeder, puller, third) = (device(), device(), device());
    // the feeder's 06-14 record loses at the puller, its 06-15 record wins there
    import(
        &feeder,
        &export_with_days(tmp.path(), "f", &[("2025-06-14", 1000, "12"), ("2025-06-15", 8000, "21")]),
    );
    import(
        &puller,
        &export_with_days(tmp.path(), "p", &[("2025-06-14", 2000, "21"), ("2025-06-15", 4000, "12")]),
    );
    import(&third, &export_with_days(tmp.path(), "t", &[("2025-06-16", 3000, "21")]));
    let relay = relay_in(tmp.path());
    for d in [&feeder, &puller, &third] {
        push(d, &relay);
    }
    let winner = canonical_hash(&uds("2025-06-15", 8000, "2025-06-15T21:00:00.0"));
    puller
        .conn()
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER inject BEFORE INSERT ON raw_records WHEN NEW.payload_hash='{winner}' \
             BEGIN SELECT RAISE(ABORT,'x'); END"
        ))
        .expect("trigger");
    assert!(sync::pull(puller.conn(), master(), &relay).is_err());
    puller.conn().execute_batch("DROP TRIGGER inject").expect("drop");
    pull(&puller, &relay);
    pull(&third, &relay);
    for _ in 0..3 {
        for d in [&feeder, &puller, &third] {
            push(d, &relay);
        }
        for d in [&feeder, &puller, &third] {
            pull(d, &relay);
        }
    }
    let (p, f, t) = (history(&puller), history(&feeder), history(&third));
    assert_eq!(p.0, p.1, "one superseded row per conflict row");
    assert!(p == f && f == t, "puller {p:?} feeder {f:?} third {t:?}");
    assert_eq!(daily_rows(&feeder), daily_rows(&puller));
    assert_eq!(daily_rows(&feeder), daily_rows(&third));
}

// ---------------------------------------------------------------- reparse (the crash-recovery path)

#[test]
fn reparse_touches_nothing_when_a_record_fails_to_decode_unless_forced() {
    let tmp = tempfile::tempdir().expect("tmp");
    let a = device();
    import(&a, &fit_drop(tmp.path(), "d", &MONITORING));
    import(
        &a,
        &export_with_uds(
            tmp.path(),
            "x",
            &uds("2025-06-15", 4000, "2025-06-15T12:00:00.0"),
        ),
    );
    let healthy = fingerprint(&a);
    let intervals = count(a.conn(), "SELECT count(*) FROM monitoring_intervals");
    // one retained FIT record turns into bytes today's decoder rejects
    let junk = zlib(b"this is not a FIT file");
    let broken: i64 = a
        .conn()
        .query_row(
            "SELECT id FROM raw_records WHERE payload_kind='fit' ORDER BY id LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("a fit record");
    a.conn()
        .execute(
            "UPDATE raw_records SET payload=? WHERE id=?",
            rusqlite::params![junk, broken],
        )
        .expect("corrupt");

    let refused = sources::reparse_all(a.conn(), None, false).expect("dry run");
    assert_eq!((refused.files_failed, refused.failures.len()), (1, 1));
    assert_eq!(refused.transport, "reparse");
    assert_eq!(
        count(a.conn(), "SELECT count(*) FROM monitoring_intervals"),
        intervals,
        "nothing was cleared"
    );
    assert_eq!(fingerprint(&a).2, healthy.2);
    let (status, error): (String, Option<String>) = a
        .conn()
        .query_row(
            "SELECT status, error FROM import_runs WHERE transport='reparse'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("run row");
    assert_eq!(status, "failed");
    assert!(error.expect("error text").contains("nothing was changed"));

    let forced = sources::reparse_all(a.conn(), None, true).expect("forced");
    assert_eq!(
        forced.files_failed, 1,
        "the record that no longer decodes is booked as a failure"
    );
    assert_eq!(
        count(
            a.conn(),
            &format!("SELECT count(*) FROM import_failures WHERE raw_record_id={broken}")
        ),
        1,
        "its failure row follows the retained record"
    );
    assert!(
        count(a.conn(), "SELECT count(*) FROM monitoring_intervals") < intervals,
        "its rows are lost, the rest rebuilt"
    );
    assert_eq!(
        count(
            a.conn(),
            "SELECT count(*) FROM daily_metrics WHERE source_scope='vendor_cloud'"
        ),
        1
    );
}

#[test]
fn a_stream_scoped_reparse_rebuilds_only_that_stream() {
    let tmp = tempfile::tempdir().expect("tmp");
    let a = device();
    import(&a, &fit_drop(tmp.path(), "d", &MONITORING));
    import(
        &a,
        &export_with_uds(
            tmp.path(),
            "x",
            &uds("2025-06-15", 4000, "2025-06-15T12:00:00.0"),
        ),
    );
    let before = fingerprint(&a);
    let stats =
        sources::reparse_all(a.conn(), Some(&["json:uds".to_string()]), false).expect("reparse");
    assert_eq!((stats.files_seen, stats.files_failed), (1, 0));
    assert_eq!(
        fingerprint(&a),
        before,
        "the rebuilt rows equal the imported ones"
    );
    assert_eq!(stats.status(), "ok");
}
