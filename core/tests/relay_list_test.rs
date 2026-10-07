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
use disconect_core::relay::folder::{FolderRelay, Relay};
use disconect_core::relay::sync::{
    HEAL_BUNDLES_PER_SITE, Site, SiteReport, SiteSpec, open_sites, pull_all, push_all,
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
            unavailable: false,
            create_root: false,
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
    assert_eq!((reports[0].rejected, reports[0].pulled), (1, 0));
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

#[test]
fn open_sites_reports_what_it_cannot_open_and_never_fails() {
    let tmp = tempfile::tempdir().expect("tmp");
    let real = tmp.path().join("real");
    fs::create_dir_all(&real).expect("mkdir");
    let spec = |id: &str, config: RelayConfig, unavailable: bool| SiteSpec { id: id.into(), config, unavailable, create_root: false };
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
        unavailable: false,
        create_root: false,
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
        unavailable: false,
        create_root: true,
    };
    let (sites, mut reports) = open_sites(&[legacy], &master());
    let result = push_all(a.conn(), &master(), &sites, &mut reports).expect("push");
    assert!(!result.partial && result.bundles.len() == 1);
    assert!(tmp.path().join("made").is_dir());
}
