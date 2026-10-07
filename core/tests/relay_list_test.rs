// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 19d: a device with several relays. A push lands on every site, an emptied site is healed from the
//! store, a pull is the union of the listings with a fall-through to the next site, and `open_sites` reports
//! what it could not open. Synthetic data only, scratch encrypted stores.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{PASSPHRASE, encrypted_copy, fixtures};
use disconect_core::keys::{self, PassphraseSource};
use disconect_core::relay::bundle::{account_for, unpack};
use disconect_core::relay::config::RelayConfig;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use disconect_core::relay::folder::{FolderRelay, Relay, RelayError};
use disconect_core::relay::lan::LanRelay;
use disconect_core::relay::lan_server::LanServer;
use disconect_core::relay::sync::{
    HEAL_BUNDLES_PER_SITE, Site, SiteReport, SiteSpec, SyncError, open_sites, pull_all, push_all, push_strict,
};
use disconect_core::sources::import_path;
use disconect_core::store::{self, Store};
use rusqlite::Connection;

fn master() -> Vec<u8> {
    keys::unlock(&fixtures().join("test.keys.json"), PassphraseSource::Explicit(PASSPHRASE))
        .expect("unlock the fixture key")
        .to_vec()
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
    let secret = keys::unlock(&keys::key_path_for(&db), PassphraseSource::Explicit(PASSPHRASE)).expect("unlock");
    let store = store::open_for_write_with(&db, "test", 5.0, Some(&secret)).expect("open store");
    Device { _dir: dir, store }
}

fn uds(day: &str, steps: i64, end: &str) -> String {
    format!(
        r#"{{"calendarDate":"{day}","totalSteps":{steps},"wellnessEndTimeGmt":"{end}","wellnessStartTimeGmt":"{day}T00:00:00.0"}}"#
    )
}

/// An export folder holding one UDS record.
fn export_with_uds(dir: &Path, name: &str, day: &str, steps: i64, end: &str) -> PathBuf {
    let root = dir.join(name);
    let file = root.join(format!("DI_CONNECT/DI-Connect-Aggregator/UDSFile_{day}_{day}.json"));
    fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
    fs::write(file, format!("[{}]", uds(day, steps, end))).expect("write");
    fs::create_dir_all(root.join("DI_CONNECT/DI-Connect-Uploaded-Files")).expect("mkdir");
    root
}

fn import_day(device: &Device, dir: &Path, day: &str, steps: i64, end: &str) {
    let name = format!("x-{day}-{steps}");
    import_path(device.conn(), &export_with_uds(dir, &name, day, steps, end), None, None).expect("import");
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).expect("count")
}

fn folder_specs(roots: &[&Path]) -> Vec<SiteSpec> {
    roots
        .iter()
        .enumerate()
        .map(|(i, root)| SiteSpec {
            id: format!("{:08x}", i + 1),
            config: RelayConfig::Folder(root.to_string_lossy().into_owned()),
            label: String::new(),
            unavailable: false,
            create_root: false,
            check_address: false,
            not_auto: false,
        })
        .collect()
}

/// Three empty folder roots under `dir`.
fn three_roots(dir: &Path) -> Vec<PathBuf> {
    (1..=3)
        .map(|i| {
            let root = dir.join(format!("site{i}"));
            fs::create_dir_all(&root).expect("mkdir");
            root
        })
        .collect()
}

fn open(roots: &[PathBuf]) -> (Vec<Site>, Vec<SiteReport>) {
    let refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    let (sites, reports) = open_sites(&folder_specs(&refs), &master());
    assert!(reports.iter().all(|r| r.error.is_none()), "{reports:?}");
    (sites, reports)
}

fn listing(root: &Path) -> Vec<String> {
    FolderRelay::new(root).list(&account_for(&master())).expect("list")
}

fn empty_site(root: &Path) {
    fs::remove_dir_all(root.join(account_for(&master()))).expect("empty the site");
}

#[test]
fn a_push_lands_on_three_sites_under_one_name_and_an_emptied_site_is_healed() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let (sites, mut reports) = open(&roots);
    let first = push_all(a.conn(), &master(), &sites, &mut reports).expect("push");
    assert_eq!((first.bundles.len(), first.partial), (1, false));
    let name = &first.bundles[0];
    let object = name.split_once('/').expect("name").1;
    let account = account_for(&master());
    let bytes: Vec<Vec<u8>> = roots.iter().map(|r| fs::read(r.join(&account).join(object)).expect("object")).collect();
    assert!(bytes[0] == bytes[1] && bytes[1] == bytes[2], "identical bytes on every site");
    assert!(reports.iter().all(|r| (r.pushed, r.healed, r.behind, r.error) == (1, 0, 0, None)));
    for root in &roots {
        assert_eq!(listing(root), vec![name.clone()]);
    }

    // a second bundle, then site 2 is emptied by hand: the next run heals exactly its two names
    import_day(&a, tmp.path(), "2025-06-16", 5000, "2025-06-16T12:00:00.0");
    let mut again = vec![SiteReport::new("00000001", "folder"), SiteReport::new("00000002", "folder"), SiteReport::new("00000003", "folder")];
    push_all(a.conn(), &master(), &sites, &mut again).expect("push 2");
    empty_site(&roots[1]);
    assert!(listing(&roots[1]).is_empty());
    let (sites, mut reports) = open(&roots);
    let healed = push_all(a.conn(), &master(), &sites, &mut reports).expect("heal");
    assert!(healed.bundles.is_empty());
    assert_eq!(
        reports.iter().map(|r| (r.pushed, r.healed, r.behind)).collect::<Vec<_>>(),
        vec![(0, 0, 0), (0, 2, 0), (0, 0, 0)]
    );
    assert_eq!(listing(&roots[1]), listing(&roots[0]), "the listing shows every pushed name again");
    // a nothing-to-do run touches nothing
    let (sites, mut reports) = open(&roots);
    push_all(a.conn(), &master(), &sites, &mut reports).expect("quiet");
    assert!(reports.iter().all(|r| (r.pushed, r.healed, r.behind) == (0, 0, 0)));
}

#[test]
fn the_heal_budget_is_sixteen_bundles_a_run_and_the_rest_is_behind() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let a = device();
    let (sites, _) = open(&roots[..1]);
    for day in 1..=20 {
        import_day(&a, tmp.path(), &format!("2025-07-{day:02}"), 1000 + day, &format!("2025-07-{day:02}T12:00:00.0"));
        let mut reports = vec![SiteReport::new("00000001", "folder")];
        push_all(a.conn(), &master(), &sites, &mut reports).expect("push");
    }
    assert_eq!(listing(&roots[0]).len(), 20);
    // a second site is added later: it holds nothing yet
    let (both, mut reports) = open(&roots[..2]);
    push_all(a.conn(), &master(), &both, &mut reports).expect("heal 1");
    assert_eq!((reports[1].healed, reports[1].behind), (HEAL_BUNDLES_PER_SITE, 4));
    assert_eq!((reports[0].healed, reports[0].behind), (0, 0));
    assert_eq!(listing(&roots[1]).len(), 16);
    let mut reports = vec![SiteReport::new("00000001", "folder"), SiteReport::new("00000002", "folder")];
    push_all(a.conn(), &master(), &both, &mut reports).expect("heal 2");
    assert_eq!((reports[1].healed, reports[1].behind), (4, 0));
    assert_eq!(listing(&roots[1]).len(), 20);
    assert_eq!(listing(&roots[1]), listing(&roots[0]));
}

fn steps_of(device: &Device) -> f64 {
    device
        .conn()
        .query_row("SELECT value FROM daily_metrics WHERE metric='steps' AND source_scope='vendor_cloud'", [], |r| r.get(0))
        .expect("steps")
}

#[test]
fn a_repack_after_a_lost_conflict_leaves_the_retired_record_out_and_a_fresh_store_applies_it() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let (a, b) = (device(), device());
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    import_day(&b, tmp.path(), "2025-06-15", 8000, "2025-06-15T21:00:00.0");
    // A publishes to sites 1 and 2; B (the later observation) publishes to site 1 only
    let (a_sites, mut a_reports) = open(&roots[..2]);
    let pushed = push_all(a.conn(), &master(), &a_sites, &mut a_reports).expect("a push");
    let a_name = pushed.bundles[0].clone();
    let original = FolderRelay::new(&roots[1]).get(&a_name).expect("the first copy");
    assert_eq!(unpack(&master(), &a_name, &original).expect("unpack").records.len(), 1);
    let (b_sites, mut b_reports) = open(&roots[..1]);
    push_all(b.conn(), &master(), &b_sites, &mut b_reports).expect("b push");
    // A pulls the union: its record loses and is retired
    let (a_sites, mut a_reports) = open(&roots[..2]);
    let pulled = pull_all(a.conn(), &master(), &a_sites, &mut a_reports).expect("a pull");
    assert_eq!((pulled.conflicts, pulled.status), (1, "ok"));
    assert_eq!(steps_of(&a), 8000.0);
    // site 2 is emptied; the heal re-packs A's bundle without the retired record
    empty_site(&roots[1]);
    let mut reports = vec![SiteReport::new("00000001", "folder"), SiteReport::new("00000002", "folder")];
    push_all(a.conn(), &master(), &a_sites, &mut reports).expect("heal");
    assert_eq!((reports[1].healed, reports[1].behind), (1, 0));
    let repacked = FolderRelay::new(&roots[1]).get(&a_name).expect("the healed copy");
    assert_ne!(repacked, original, "a fresh nonce and fewer rows");
    let bundle = unpack(&master(), &a_name, &repacked).expect("the re-packed bundle unpacks");
    assert!(bundle.records.is_empty(), "the retired loser is left out");
    // a fresh store pulls the healed site, then the site that holds the winner's own bundle
    let c = device();
    let mut c_reports = vec![SiteReport::new("00000002", "folder")];
    let (only_two, _) = open_sites(&folder_specs(&[roots[1].as_path()]), &master());
    let first = pull_all(c.conn(), &master(), &only_two, &mut c_reports).expect("c pull the healed site");
    assert_eq!((first.applied.len(), first.rejected.len(), first.status), (1, 0, "ok"));
    assert_eq!(count(c.conn(), "SELECT count(*) FROM raw_records"), 0);
    let (only_one, _) = open_sites(&folder_specs(&[roots[0].as_path()]), &master());
    let second = pull_all(c.conn(), &master(), &only_one, &mut c_reports).expect("c pull the winner's site");
    assert_eq!(second.status, "ok");
    assert_eq!(steps_of(&c), 8000.0, "the winner arrives through its own bundle");
}

#[test]
fn a_pull_falls_through_a_bad_copy_to_the_next_site_and_applies_each_name_once() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let (both, mut reports) = open(&roots[..2]);
    let first = push_all(a.conn(), &master(), &both, &mut reports).expect("push");
    let shared = first.bundles[0].clone();
    // a second bundle goes to site 2 only
    import_day(&a, tmp.path(), "2025-06-16", 5000, "2025-06-16T12:00:00.0");
    let (second_only, mut r2) = open(&roots[1..2]);
    let second = push_all(a.conn(), &master(), &second_only, &mut r2).expect("push 2");
    let lonely = second.bundles[0].clone();
    // site 1's copy of the shared name is damaged
    let object = shared.split_once('/').expect("name").1;
    let path = roots[0].join(account_for(&master())).join(object);
    let mut damaged = fs::read(&path).expect("read");
    let last = damaged.len() - 1;
    damaged[last] ^= 0xff;
    fs::write(&path, damaged).expect("damage");

    let b = device();
    let (sites, mut reports) = open(&roots[..2]);
    let pulled = pull_all(b.conn(), &master(), &sites, &mut reports).expect("pull");
    assert_eq!(pulled.applied.len(), 2, "{pulled:?}");
    assert!(pulled.applied.contains(&shared) && pulled.applied.contains(&lonely));
    assert!(pulled.rejected.is_empty(), "a bad copy on one site is not a rejection");
    assert_eq!(pulled.status, "ok");
    // BL-4b: the counter marks a site only when the name ends rejected
    assert_eq!((reports[0].rejected, reports[0].pulled), (0, 0));
    assert_eq!((reports[1].rejected, reports[1].pulled), (0, 2));
    assert_eq!(count(b.conn(), "SELECT count(*) FROM relay_bundles WHERE status='rejected'"), 0);
    assert_eq!(count(b.conn(), "SELECT count(*) FROM relay_bundles WHERE direction='pulled' AND status='applied'"), 2);
}

#[test]
fn a_name_every_site_rejects_is_rejected_once() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let (both, mut reports) = open(&roots[..2]);
    let pushed = push_all(a.conn(), &master(), &both, &mut reports).expect("push");
    let object = pushed.bundles[0].split_once('/').expect("name").1.to_string();
    for root in &roots[..2] {
        fs::write(root.join(account_for(&master())).join(&object), b"not a bundle").expect("damage");
    }
    let b = device();
    let (sites, mut reports) = open(&roots[..2]);
    let pulled = pull_all(b.conn(), &master(), &sites, &mut reports).expect("pull");
    assert_eq!((pulled.applied.len(), pulled.rejected.len(), pulled.status), (0, 1, "partial"));
    assert_eq!((reports[0].rejected, reports[1].rejected), (1, 1));
}

fn booked(conn: &Connection, name: &str) -> String {
    conn.query_row(
        "SELECT noted_at FROM relay_bundles WHERE name=? AND status='rejected'",
        [name],
        |r| r.get(0),
    )
    .expect("the rejected booking")
}

#[test]
fn a_rejected_name_is_not_fetched_again_for_a_day_and_the_run_is_ok() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let (sites, mut reports) = open(&roots[..1]);
    let first = push_all(a.conn(), &master(), &sites, &mut reports).expect("push").bundles[0].clone();
    let object = first.split_once('/').expect("name").1.to_string();
    fs::write(roots[0].join(account_for(&master())).join(&object), b"not a bundle").expect("damage");

    let b = device();
    let (sites, mut reports) = open(&roots[..1]);
    let run1 = pull_all(b.conn(), &master(), &sites, &mut reports).expect("pull 1");
    assert_eq!((run1.rejected.len(), run1.status, reports[0].rejected), (1, "partial", 1));
    // a second bundle arrives: the garbage is held back (nothing fetched, nothing counted), the run is clean
    import_day(&a, tmp.path(), "2025-06-16", 5000, "2025-06-16T12:00:00.0");
    let (sites, mut reports) = open(&roots[..1]);
    let second = push_all(a.conn(), &master(), &sites, &mut reports).expect("push 2").bundles[0].clone();
    let (sites, mut reports) = open(&roots[..1]);
    let run2 = pull_all(b.conn(), &master(), &sites, &mut reports).expect("pull 2");
    assert_eq!(run2.applied, vec![second]);
    assert!(run2.rejected.is_empty(), "{run2:?}");
    assert_eq!((run2.status, reports[0].rejected, reports[0].pulled), ("ok", 0, 1));
    // a booking 23 h old still holds the name back; one 25 h old is retried once and booked again with a new time
    let at = |hours: u64| disconect_core::time::iso_from_unix(disconect_core::time::now_unix() - hours * 3600);
    b.conn()
        .execute("UPDATE relay_bundles SET noted_at=? WHERE name=?", rusqlite::params![at(23), first])
        .expect("age");
    let (sites, mut reports) = open(&roots[..1]);
    let run3 = pull_all(b.conn(), &master(), &sites, &mut reports).expect("pull 3");
    assert_eq!((run3.rejected.len(), run3.status, reports[0].rejected), (0, "ok", 0));
    b.conn()
        .execute("UPDATE relay_bundles SET noted_at=? WHERE name=?", rusqlite::params![at(25), first])
        .expect("age");
    let (sites, mut reports) = open(&roots[..1]);
    let run4 = pull_all(b.conn(), &master(), &sites, &mut reports).expect("pull 4");
    assert_eq!((run4.rejected.len(), run4.status, reports[0].rejected), (1, "partial", 1));
    assert!(booked(b.conn(), &first) > at(1), "the booking carries the new time");
}

#[test]
fn a_copy_damaged_on_site_one_and_good_on_site_two_marks_site_one_nothing() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let (both, mut reports) = open(&roots[..2]);
    let name = push_all(a.conn(), &master(), &both, &mut reports).expect("push").bundles[0].clone();
    let object = name.split_once('/').expect("name").1;
    fs::write(roots[0].join(account_for(&master())).join(object), b"not a bundle").expect("damage");
    let b = device();
    let (sites, mut reports) = open(&roots[..2]);
    let pulled = pull_all(b.conn(), &master(), &sites, &mut reports).expect("pull");
    assert_eq!(pulled.applied, vec![name]);
    assert!(pulled.rejected.is_empty());
    assert_eq!(pulled.status, "ok");
    assert_eq!((reports[0].rejected, reports[0].pulled), (0, 0));
    assert_eq!((reports[1].rejected, reports[1].pulled), (0, 1));
}

#[test]
fn a_chains_last_at_is_the_newest_applied_bundles_created_utc() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let a = device();
    for (day, steps) in [("2025-06-15", 4000), ("2025-06-16", 5000)] {
        import_day(&a, tmp.path(), day, steps, &format!("{day}T12:00:00.0"));
        let (sites, mut reports) = open(&roots[..1]);
        push_all(a.conn(), &master(), &sites, &mut reports).expect("push");
    }
    let b = device();
    let (sites, mut reports) = open(&roots[..1]);
    assert_eq!(pull_all(b.conn(), &master(), &sites, &mut reports).expect("pull").applied.len(), 2);
    // pin two distinct header times (the pushes above may share a second), the newer one on the second bundle
    b.conn()
        .execute(
            "UPDATE relay_bundles SET created_utc=CASE device_seq WHEN 1 THEN '2026-03-01T10:00:00Z' ELSE '2026-03-03T08:30:00Z' END \
             WHERE status='applied'",
            [],
        )
        .expect("set times");
    let report = disconect_core::relay::sync::status(b.conn()).expect("status");
    assert_eq!(report.chains.len(), 1);
    assert_eq!(report.chains[0].bundles, 2);
    assert_eq!(report.chains[0].last_at.as_deref(), Some("2026-03-03T08:30:00Z"));
    let value = disconect_core::relay::sync::status_value(&report);
    assert_eq!(value["chains"][0]["last_at"], "2026-03-03T08:30:00Z");
}

#[test]
fn open_sites_reports_what_it_cannot_open_and_never_fails() {
    let tmp = tempfile::tempdir().expect("tmp");
    let real = tmp.path().join("real");
    fs::create_dir_all(&real).expect("mkdir");
    let spec = |id: &str, config: RelayConfig, unavailable: bool| SiteSpec { id: id.into(), config, label: String::new(), unavailable, create_root: false, check_address: false, not_auto: false };
    let folder = |p: &Path| RelayConfig::Folder(p.to_string_lossy().into_owned());
    let mut specs = vec![
        spec("00000001", folder(&real), false),
        spec("00000002", folder(&tmp.path().join("not mounted")), false),
        spec("00000003", folder(&real), true),
        spec("00000004", RelayConfig::Lan("https://127.0.0.1:9".into()), false),
        spec("00000005", RelayConfig::Lan("http://127.0.0.1:9".into()), false),
        spec("00000006", RelayConfig::Lan("http://127.0.0.1:9/".into()), false),
        spec("00000007", RelayConfig::Lan("nonsense".into()), false),
    ];
    #[cfg(unix)]
    {
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        specs.push(spec("00000008", folder(&link), false));
        // a file is not a folder
        let file = tmp.path().join("file");
        fs::write(&file, b"x").expect("file");
        specs.push(spec("00000009", folder(&file), false));
    }
    let (sites, reports) = open_sites(&specs, &master());
    let words: Vec<(&str, &str, Option<&str>)> = reports.iter().map(|r| (r.id.as_str(), r.kind, r.error)).collect();
    #[cfg(unix)]
    assert_eq!(
        words,
        vec![
            ("00000001", "folder", None),
            ("00000002", "folder", Some("unavailable")),
            ("00000003", "folder", Some("unavailable")),
            ("00000004", "lan", Some("bad_url")),
            ("00000005", "lan", None),
            ("00000006", "lan", Some("same_relay")),
            ("00000007", "lan", Some("bad_url")),
            ("00000008", "folder", Some("same_relay")),
            ("00000009", "folder", Some("unavailable")),
        ]
    );
    assert_eq!(sites.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), ["00000001", "00000005"]);
    assert_eq!(sites.iter().map(|s| (s.report, s.kind)).collect::<Vec<_>>(), [(0, "folder"), (4, "lan")]);
    assert!(!tmp.path().join("not mounted").exists(), "a missing root is never created");
}

#[test]
fn nothing_is_booked_when_no_site_can_take_a_bundle() {
    let tmp = tempfile::tempdir().expect("tmp");
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let spec = SiteSpec {
        id: "00000001".into(),
        config: RelayConfig::Folder(tmp.path().join("gone").to_string_lossy().into_owned()),
        label: String::new(),
        unavailable: false,
        create_root: false,
        check_address: false,
            not_auto: false,
    };
    let (sites, mut reports) = open_sites(&[spec], &master());
    let result = push_all(a.conn(), &master(), &sites, &mut reports).expect("push");
    assert!(result.partial && result.bundles.is_empty());
    assert_eq!(reports[0].error, Some("unavailable"));
    assert_eq!(count(a.conn(), "SELECT count(*) FROM relay_bundles"), 0);
    assert_eq!(count(a.conn(), "SELECT count(*) FROM relay_seen"), 0);
    // the legacy single folder (create_root) is created by its first put, as ever
    let legacy = SiteSpec {
        id: "default".into(),
        config: RelayConfig::Folder(tmp.path().join("made").to_string_lossy().into_owned()),
        label: String::new(),
        unavailable: false,
        create_root: true,
        check_address: false,
            not_auto: false,
    };
    let (sites, mut reports) = open_sites(&[legacy], &master());
    let result = push_all(a.conn(), &master(), &sites, &mut reports).expect("push");
    assert!(!result.partial && result.bundles.len() == 1);
    assert!(tmp.path().join("made").is_dir());
}

// ---------------------------------------------------------------- 19d review fixes

fn name_in(account: &str, tail: char) -> String {
    format!("{account}/{}", tail.to_string().repeat(32))
}

#[test]
fn heal_ignores_a_stale_account_row() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let (sites, mut reports) = open(&roots[..1]);
    let first = push_all(a.conn(), &master(), &sites, &mut reports).expect("push");
    // a key rotation whose forget failed left the old account's bundle booked and linked
    let foreign = name_in(&"f".repeat(64), 'e');
    a.conn()
        .execute(
            "INSERT INTO relay_bundles(name, direction, status, device_id, device_seq, prev, created_utc, noted_at, bytes, records) \
             VALUES(?, 'pushed', 'applied', 'deadbeefdeadbeef', 99, NULL, '2025-06-15T12:00:00Z', '2025-06-15T12:00:00Z', 10, 1)",
            [&foreign],
        )
        .expect("seed the foreign row");
    let linked = a
        .conn()
        .execute("UPDATE relay_seen SET bundle = ? WHERE bundle = ?", [&foreign, &first.bundles[0]])
        .expect("link");
    assert!(linked > 0);
    let (sites, mut again) = open(&roots[..1]);
    push_all(a.conn(), &master(), &sites, &mut again).expect("the run does not fail");
    assert_eq!((again[0].error, again[0].healed, again[0].behind), (None, 0, 0));
    assert!(!listing(&roots[0]).contains(&foreign), "the foreign name is never healed");
}

#[test]
fn put_refuses_a_root_that_vanished() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let (sites, mut reports) = open(&roots[..2]);
    fs::remove_dir_all(&roots[0]).expect("unmount");
    let pushed = push_all(a.conn(), &master(), &sites, &mut reports).expect("a run with one site left");
    assert_eq!(pushed.bundles.len(), 1, "the other site took it");
    assert_eq!((reports[0].error, reports[0].pushed), (Some("missing"), 0));
    assert_eq!((reports[1].error, reports[1].pushed), (None, 1));
    assert!(!roots[0].exists(), "nothing recreated the root");

    // the only site: the old NotFound error is raised, nothing created or booked
    let b = device();
    import_day(&b, tmp.path(), "2025-06-16", 5000, "2025-06-16T12:00:00.0");
    let (sites, mut reports) = open(&roots[2..3]);
    fs::remove_dir_all(&roots[2]).expect("unmount");
    let error = push_strict(b.conn(), &master(), &sites, &mut reports).expect_err("strict");
    assert!(matches!(&error, SyncError::Relay(RelayError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound), "{error:?}");
    assert_eq!(reports[0].error, Some("missing"));
    assert!(!roots[2].exists());
    assert_eq!(count(b.conn(), "SELECT count(*) FROM relay_bundles"), 0);
}

#[test]
fn the_site_words_are_stable() {
    use std::io::ErrorKind as K;
    let io = |kind: K| RelayError::Io(kind.into());
    let table: Vec<(RelayError, &str)> = vec![
        (RelayError::TooLarge, "too_large"),
        (RelayError::BadName, "bad_name"),
        (RelayError::Unreachable, "unreachable"),
        (RelayError::Status(500), "unreachable"),
        (RelayError::Unauthorized { skew_s: 600 }, "refused"),
        (RelayError::Unverified, "unverified"),
        (io(K::NotFound), "missing"),
        (io(K::NotADirectory), "missing"),
        (io(K::PermissionDenied), "no_permission"),
        (io(K::ConnectionRefused), "io_error"),
        (io(K::Other), "io_error"),
    ];
    for (error, word) in table {
        assert_eq!(error.site_word(), word, "{error:?}");
    }
    // the stored `rejected` reason keeps the Python class name
    assert_eq!(io(K::NotFound).reason(), "FileNotFoundError");
}

#[test]
fn a_public_lan_url_is_bad_url() {
    let spec = |id: &str, url: &str, check: bool| SiteSpec {
        id: id.into(),
        config: RelayConfig::Lan(url.into()),
        label: String::new(),
        unavailable: false,
        create_root: false,
        check_address: check,
            not_auto: false,
    };
    let specs = vec![
        spec("00000001", "http://8.8.8.8:24816", true),
        spec("00000002", "http://mac.local:24816", true),
        spec("00000003", "http://192.168.1.20:24816", true),
        spec("00000004", "http://127.0.0.1:24816", true),
        spec("00000005", "http://169.254.1.1:24816", true),
        spec("00000006", "http://8.8.4.4:24816", false),
    ];
    let (sites, reports) = open_sites(&specs, &master());
    let words: Vec<Option<&str>> = reports.iter().map(|r| r.error).collect();
    assert_eq!(words, vec![Some("bad_url"), Some("bad_url"), None, None, Some("bad_url"), None]);
    assert_eq!(sites.len(), 3);
}

#[test]
fn an_evicted_copy_is_not_healed_again() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let (sites, mut reports) = open(&roots[..1]);
    let first = push_all(a.conn(), &master(), &sites, &mut reports).expect("push");
    let account = account_for(&master());
    let object = first.bundles[0].split_once('/').expect("name").1.to_string();
    let folder = roots[0].join(&account);
    // iCloud evicts the file: a placeholder `.<name>.icloud` stays
    fs::rename(folder.join(&object), folder.join(format!(".{object}.icloud"))).expect("evict");
    assert!(listing(&roots[0]).is_empty(), "a get would fail: the listing does not show it");
    let (sites, mut again) = open(&roots[..1]);
    push_all(a.conn(), &master(), &sites, &mut again).expect("run");
    assert_eq!((again[0].healed, again[0].behind, again[0].error), (0, 0, None));
    assert!(!folder.join(&object).exists(), "no second copy was written beside the placeholder");
    // without the placeholder the same run heals it
    fs::remove_file(folder.join(format!(".{object}.icloud"))).expect("gone");
    let (sites, mut third) = open(&roots[..1]);
    push_all(a.conn(), &master(), &sites, &mut third).expect("run");
    assert_eq!(third[0].healed, 1);
    // a pull keeps `list`: an evicted copy is not offered to a reader
    let fresh = account_for(&master());
    fs::rename(folder.join(&object), folder.join(format!(".{object}.icloud"))).expect("evict");
    assert!(FolderRelay::new(&roots[0]).list(&fresh).expect("list").is_empty());
    assert_eq!(FolderRelay::new(&roots[0]).list_present(&fresh).expect("present"), vec![first.bundles[0].clone()]);
}

fn silent() -> disconect_core::relay::lan_server::Logger {
    Arc::new(|_, _| {})
}

fn lan_spec(url: &str) -> SiteSpec {
    SiteSpec {
        id: "00000003".into(),
        config: RelayConfig::Lan(url.into()),
        label: "mac".into(),
        unavailable: false,
        create_root: false,
        check_address: true,
            not_auto: false,
    }
}

#[test]
fn lan_site_in_a_list_syncs_with_the_folders() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let lan_folder = tmp.path().join("lan");
    let server = LanServer::start("127.0.0.1:0", &lan_folder, &master(), silent()).expect("serve");
    let addr = server.local_addr();
    let url = format!("http://{addr}");
    let specs = |url: &str| {
        let mut specs = folder_specs(&[roots[0].as_path(), roots[1].as_path()]);
        specs.push(lan_spec(url));
        specs
    };
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let (sites, mut reports) = open_sites(&specs(&url), &master());
    assert!(reports.iter().all(|r| r.error.is_none()), "{reports:?}");
    assert_eq!(reports[2].label, "mac");
    let run1 = push_all(a.conn(), &master(), &sites, &mut reports).expect("run 1");
    assert_eq!((run1.bundles.len(), run1.partial), (1, false));
    assert!(reports.iter().all(|r| (r.pushed, r.error) == (1, None)), "{reports:?}");
    assert_eq!(FolderRelay::new(&lan_folder).list(&account_for(&master())).expect("list").len(), 1);

    // run 2: the server is gone; the folders still take the bundle and the lan site says why
    server.stop();
    import_day(&a, tmp.path(), "2025-06-16", 5000, "2025-06-16T12:00:00.0");
    let (sites, mut reports) = open_sites(&specs(&url), &master());
    let run2 = push_all(a.conn(), &master(), &sites, &mut reports).expect("run 2");
    assert_eq!(run2.bundles.len(), 1, "booked: the folders took it");
    assert_eq!((reports[0].pushed, reports[0].error), (1, None));
    assert_eq!((reports[1].pushed, reports[1].error), (1, None));
    assert_eq!((reports[2].pushed, reports[2].error), (0, Some("unreachable")));
    assert!(reports.iter().any(|r| r.error.is_some()), "the run is partial");

    // the server is back on the same address: the next run heals the name it missed
    let server = LanServer::start(&addr.to_string(), &lan_folder, &master(), silent()).expect("serve again");
    let (sites, mut reports) = open_sites(&specs(&url), &master());
    push_all(a.conn(), &master(), &sites, &mut reports).expect("run 3");
    assert_eq!((reports[2].healed, reports[2].error), (1, None));
    assert_eq!(FolderRelay::new(&lan_folder).list(&account_for(&master())).expect("list").len(), 2);
    server.stop();
}

/// A LAN relay whose reads fail while `down` is set (the list still answers: the Mac went away between the
/// listing and the fetch).
struct Flaky {
    inner: LanRelay,
    down: Arc<AtomicBool>,
}

impl Relay for Flaky {
    fn put(&self, name: &str, data: &[u8]) -> Result<(), RelayError> {
        self.inner.put(name, data)
    }
    fn get(&self, name: &str) -> Result<Vec<u8>, RelayError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(RelayError::Unreachable);
        }
        self.inner.get(name)
    }
    fn list(&self, account: &str) -> Result<Vec<String>, RelayError> {
        self.inner.list(account)
    }
    fn delete(&self, name: &str) -> Result<(), RelayError> {
        self.inner.delete(name)
    }
}

#[test]
fn an_unreachable_lan_site_keeps_the_name_pending() {
    let tmp = tempfile::tempdir().expect("tmp");
    let roots = three_roots(tmp.path());
    let lan_folder = tmp.path().join("lan");
    let server = LanServer::start("127.0.0.1:0", &lan_folder, &master(), silent()).expect("serve");
    let url = format!("http://{}", server.local_addr());
    // A pushes to the LAN site only
    let a = device();
    import_day(&a, tmp.path(), "2025-06-15", 4000, "2025-06-15T12:00:00.0");
    let (lan_only, mut lan_reports) = open_sites(&[lan_spec(&url)], &master());
    let pushed = push_all(a.conn(), &master(), &lan_only, &mut lan_reports).expect("push");
    assert_eq!(pushed.bundles.len(), 1);
    let name = pushed.bundles[0].clone();

    // B lists two empty folders and the LAN site; the LAN site lists the name, then cannot be reached
    let b = device();
    let down = Arc::new(AtomicBool::new(true));
    let (mut sites, mut reports) = open(&roots[..2]);
    sites.push(Site {
        id: "00000003".into(),
        kind: "lan",
        relay: Box::new(Flaky { inner: LanRelay::new(&url, &master()).expect("client"), down: Arc::clone(&down) }),
        report: 2,
    });
    reports.push(SiteReport::new("00000003", "lan"));
    let first = pull_all(b.conn(), &master(), &sites, &mut reports).expect("pull");
    assert!(first.applied.is_empty() && first.rejected.is_empty(), "{first:?}");
    assert_eq!(first.status, "partial");
    assert_eq!(reports[2].error, Some("unreachable"));
    assert_eq!(reports[2].rejected, 0);
    assert_eq!((reports[0].error, reports[1].error), (None, None));
    assert_eq!(count(b.conn(), "SELECT count(*) FROM relay_bundles"), 0, "no row, rejected or other: the name is still pending");

    // the Mac is back: the same name is pulled
    down.store(false, Ordering::SeqCst);
    let mut again = vec![SiteReport::new("00000001", "folder"), SiteReport::new("00000002", "folder"), SiteReport::new("00000003", "lan")];
    let second = pull_all(b.conn(), &master(), &sites, &mut again).expect("pull again");
    assert_eq!((second.applied.clone(), second.status), (vec![name], "ok"));
    assert_eq!((again[2].pulled, again[2].error), (1, None));
    server.stop();
}
