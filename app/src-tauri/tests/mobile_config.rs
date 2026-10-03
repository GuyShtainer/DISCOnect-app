// SPDX-License-Identifier: AGPL-3.0-or-later
//! The merged Tauri configuration per platform, read by Tauri's own parser (`tauri_utils::config::parse`,
//! what `tauri-build` runs): the macOS app keeps its name, identifier and bundled cores; the iOS
//! app (`tauri.ios.conf.json`, merged as a JSON Merge Patch, RFC 7396) bundles no core and carries
//! the dev identifier and the display name. No iOS toolchain is needed to read this; compiling
//! for iOS is a different matter and is not tested here.

use std::path::Path;

use tauri_utils::config::{parse::read_from, BundleResources, Config};
use tauri_utils::platform::Target;

/// `tauri.conf.json` plus the target's platform file, merged as `tauri-build` merges them, and how many
/// files that took.
fn merged(target: Target) -> (Config, usize) {
    let (value, files) =
        read_from(target, Path::new(env!("CARGO_MANIFEST_DIR"))).expect("the configuration reads");
    (
        serde_json::from_value(value).expect("the merged configuration is valid for Tauri"),
        files.len(),
    )
}

#[test]
fn macos_is_unchanged_and_still_bundles_both_cores() {
    let (config, files) = merged(Target::MacOS);
    assert_eq!(
        files, 1,
        "no macOS platform file: the Mac app is exactly tauri.conf.json"
    );
    assert_eq!(config.product_name.as_deref(), Some("disconect-app"));
    assert_eq!(config.identifier, "org.disconect.app");
    let Some(BundleResources::Map(map)) = config.bundle.resources else {
        panic!("macOS keeps the resource map")
    };
    assert_eq!(map.len(), 2);
    assert!(
        map.contains_key("resources/disconect-core/")
            && map.contains_key("resources/hearthbeat-core/")
    );
    assert_eq!(config.app.windows[0].title, "DISCOnect");
}

#[test]
fn ios_bundles_no_core_and_is_a_dev_app_called_disconect() {
    let (config, files) = merged(Target::Ios);
    assert_eq!(files, 2, "tauri.ios.conf.json was merged");
    assert_eq!(config.product_name.as_deref(), Some("DISCOnect"));
    assert_eq!(config.identifier, "org.disconect.app.dev");
    // an array patch replaces the macOS map outright (a merge patch merges objects only)
    assert_eq!(config.bundle.resources, Some(BundleResources::List(vec![])));
    assert_eq!(config.app.windows[0].title, "DISCOnect");
}
