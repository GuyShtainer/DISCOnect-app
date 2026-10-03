// SPDX-License-Identifier: AGPL-3.0-or-later
//! The app's egress guards (Bet 15 slice 1, ADR 0010), each one a test that names its rule. They hold the
//! line "nothing in this app opens a network connection except `src/coach/egress.rs`" before any coach code
//! exists, so the first slice that adds a socket cannot also add a second path unnoticed.
//!
//! The model is `disconect-core/tests/serve_test.rs::the_dependency_tree_has_no_network_crate_but_the_lan_relays_client`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tauri_utils::config::{parse::read_from, Config, DisabledCspModificationKind};
use tauri_utils::platform::Target;

fn manifest() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn app_dir() -> PathBuf {
    manifest().join("..")
}

fn text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn merged(target: Target) -> Config {
    let (value, _files) = read_from(target, manifest()).expect("the configuration reads");
    serde_json::from_value(value).expect("the merged configuration is valid for Tauri")
}

fn files_under(root: &Path, extension: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == extension) {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

fn csp_map(csp: &str) -> BTreeMap<String, String> {
    csp.split(';')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(|d| {
            let (name, sources) = d.split_once(' ').unwrap_or((d, ""));
            (name.to_string(), sources.split_whitespace().collect::<Vec<_>>().join(" "))
        })
        .collect()
}

// ---- the webview ---------------------------------------------------------------------------------

#[test]
fn csp_is_exactly_the_ten_directives_on_every_platform() {
    let expected: BTreeMap<String, String> = [
        ("default-src", "'self'"),
        ("script-src", "'self'"),
        ("style-src", "'self' 'unsafe-inline'"),
        ("img-src", "'self' data:"),
        ("font-src", "'self'"),
        ("connect-src", "ipc: http://ipc.localhost"),
        ("object-src", "'none'"),
        ("base-uri", "'none'"),
        ("form-action", "'none'"),
        ("frame-src", "'none'"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for target in [Target::MacOS, Target::Ios] {
        let config = merged(target);
        let csp = config.app.security.csp.expect("a CSP is configured").to_string();
        assert_eq!(csp_map(&csp), expected, "{target:?}");
        assert!(config.app.security.dev_csp.is_none(), "a dev-only CSP would hide what a release enforces");
    }
}

#[test]
fn the_global_tauri_object_is_off_and_tauri_may_not_skip_csp_rewriting() {
    let config = merged(Target::MacOS);
    assert!(!config.app.with_global_tauri, "withGlobalTauri puts the IPC bridge on window");
    assert_eq!(
        config.app.security.dangerous_disable_asset_csp_modification,
        DisabledCspModificationKind::Flag(false)
    );
}

#[test]
fn the_main_window_is_built_in_setup_so_it_can_carry_the_navigation_hooks() {
    let config = merged(Target::MacOS);
    let window = &config.app.windows[0];
    assert!(!window.create, "an auto-created window would have no navigation hook");
    assert_eq!(window.label, "main", "capabilities/default.json names this label");
    let lib = text(&manifest().join("src/lib.rs"));
    assert!(lib.contains("WebviewWindowBuilder::from_config("));
    assert!(lib.contains(".on_navigation(coach::egress_guard::navigation_allowed)"));
    assert!(lib.contains(".on_new_window(|_url, _features| NewWindowResponse::Deny)"));
}

#[test]
fn capabilities_grant_core_default_to_the_main_window_and_nothing_else() {
    let dir = manifest().join("capabilities");
    let files = files_under(&dir, "json");
    assert_eq!(files.len(), 1, "one capability file: {files:?}");
    let caps: Value = serde_json::from_str(&text(&files[0])).expect("json");
    assert_eq!(caps["permissions"], serde_json::json!(["core:default"]));
    assert_eq!(caps["windows"], serde_json::json!(["main"]));
    assert!(caps.get("webviews").is_none() && caps.get("remote").is_none(), "no remote origin gets IPC");
}

// ---- plugins and the dependency tree -------------------------------------------------------------

/// The keys of one `[section]` of a Cargo manifest (no TOML parser in the tree: the manifest is simple).
fn cargo_section_keys(manifest_text: &str, section: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let mut inside = false;
    for line in manifest_text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == format!("[{section}]");
        } else if inside && !line.starts_with('#') {
            if let Some((key, _)) = line.split_once('=') {
                keys.insert(key.trim().to_string());
            }
        }
    }
    keys
}

#[test]
fn npm_plugins_and_cargo_plugins_are_the_same_set() {
    let package: Value = serde_json::from_str(&text(&app_dir().join("package.json"))).expect("json");
    let mut npm = BTreeSet::new();
    for section in ["dependencies", "devDependencies"] {
        for name in package[section].as_object().into_iter().flat_map(|o| o.keys()) {
            if let Some(plugin) = name.strip_prefix("@tauri-apps/plugin-") {
                npm.insert(plugin.to_string());
            }
        }
    }
    let cargo: BTreeSet<String> = cargo_section_keys(&text(&manifest().join("Cargo.toml")), "dependencies")
        .iter()
        .filter_map(|name| name.strip_prefix("tauri-plugin-").map(str::to_string))
        .collect();
    assert_eq!(npm, cargo, "a JS plugin without its Rust half is dead code that still ships; the reverse is an unused permission surface");
}

/// `[[package]]` blocks of a lock file: name -> the names it depends on.
fn lock_graph(lock: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for block in lock.split("[[package]]").skip(1) {
        let name = block
            .lines()
            .find_map(|l| l.strip_prefix("name = \"").and_then(|r| r.strip_suffix('"')))
            .expect("every package has a name");
        let deps = graph.entry(name.to_string()).or_default();
        let mut in_deps = false;
        for line in block.lines() {
            if line.starts_with("dependencies = [") {
                in_deps = true;
            } else if in_deps && line == "]" {
                in_deps = false;
            } else if in_deps {
                let entry = line.trim().trim_end_matches(',').trim_matches('"');
                deps.insert(entry.split(' ').next().unwrap_or_default().to_string());
            }
        }
    }
    graph
}

fn dependents_of(graph: &BTreeMap<String, BTreeSet<String>>, name: &str) -> BTreeSet<String> {
    graph.iter().filter(|(_, deps)| deps.contains(name)).map(|(n, _)| n.clone()).collect()
}

/// The crates this build compiles for the host (`cargo tree`, from the lock file; no network is needed once
/// the build has run).
fn host_crates() -> BTreeSet<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .args(["tree", "--locked", "--prefix", "none", "-e", "normal,build", "--manifest-path"])
        .arg(manifest().join("Cargo.toml"))
        .output()
        .expect("cargo tree runs");
    assert!(out.status.success(), "cargo tree: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split(' ').next())
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect()
}

#[test]
fn the_lock_file_has_no_telemetry_updater_websocket_or_native_tls_crate() {
    let graph = lock_graph(&text(&manifest().join("Cargo.lock")));
    for banned in [
        "curl",
        "tungstenite",
        "tokio-tungstenite",
        "tauri-plugin-updater",
        "sentry",
        "sentry-core",
        "native-tls",
        "openssl",
    ] {
        assert!(!graph.contains_key(banned), "{banned} would be a second network or telemetry path");
    }
}

#[test]
fn reqwest_and_hyper_are_not_in_the_desktop_build_and_reach_the_lock_only_through_tauris_mobile_proxy() {
    // `tauri` lists `reqwest` (so `hyper`) under `cfg(any(target_os = "android", all(target_vendor = "apple",
    // not(target_os = "macos"))))`: its dev-server proxy on phones. The lock file spans every target, so the
    // ban is on the host tree, and the lock may hold them only below `tauri`. A phone shell (ADR 0010, revisit)
    // must re-check this per target.
    let host = host_crates();
    for banned in ["reqwest", "hyper"] {
        assert!(!host.contains(banned), "{banned} is compiled into the desktop app");
    }
    let graph = lock_graph(&text(&manifest().join("Cargo.lock")));
    assert_eq!(dependents_of(&graph, "reqwest"), BTreeSet::from(["tauri".to_string()]));
    assert!(dependents_of(&graph, "hyper").is_subset(&BTreeSet::from(["hyper-util".to_string(), "reqwest".to_string()])));
}

#[test]
fn the_http_client_is_ureq_and_rustls_is_only_its_tls() {
    let graph = lock_graph(&text(&manifest().join("Cargo.lock")));
    let manifest_text = text(&manifest().join("Cargo.toml"));
    // slice 4: the app takes ureq (default features off) for `coach/egress.rs`, with rustls and the OS trust store
    let ureq_line = manifest_text
        .lines()
        .find(|l| l.trim_start().starts_with("ureq"))
        .expect("the app crate depends on ureq since slice 4");
    assert!(ureq_line.contains("default-features = false"), "{ureq_line}");
    assert!(ureq_line.contains("\"rustls\"") && ureq_line.contains("\"platform-verifier\""), "{ureq_line}");
    assert!(!ureq_line.contains("native-tls"), "{ureq_line}");
    let direct = cargo_section_keys(&manifest_text, "dependencies");
    for tls_crate in ["rustls", "ring", "aws-lc-rs", "webpki-roots", "rustls-platform-verifier", "native-tls"] {
        assert!(!direct.contains(tls_crate), "{tls_crate} must arrive only as ureq's TLS, not as a direct dependency");
    }
    // rustls is in the lock, and the only crates that depend on it are ureq and ureq's platform verifier
    assert_eq!(
        dependents_of(&graph, "rustls"),
        BTreeSet::from(["ureq".to_string(), "rustls-platform-verifier".to_string()]),
        "rustls must be ureq's TLS and nothing else's"
    );
    assert_eq!(dependents_of(&graph, "rustls-platform-verifier"), BTreeSet::from(["ureq".to_string()]));
    // the crypto provider is `ring` (no cmake or Go toolchain); aws-lc-rs is not in the tree
    assert!(graph.contains_key("ring"), "ring is rustls's provider");
    assert!(!graph.contains_key("aws-lc-rs") && !graph.contains_key("aws-lc-sys"), "aws-lc needs cmake/Go to build");
    // and the host build still has no second HTTP client
    let host = host_crates();
    for banned in ["reqwest", "hyper", "h2", "isahc", "attohttpc", "minreq", "surf"] {
        assert!(!host.contains(banned), "{banned} is compiled into the desktop app");
    }
}

// ---- the sources ---------------------------------------------------------------------------------

/// Everything before the first `#[cfg(test)]` (test modules sit at the end of a file in this crate).
fn non_test_code(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

#[test]
fn network_types_appear_only_in_the_coach_egress_module() {
    let src = manifest().join("src");
    let egress = src.join("coach").join("egress.rs");
    assert!(egress.is_file(), "the one egress file exists");
    for path in files_under(&src, "rs") {
        if path == egress {
            continue;
        }
        let code = text(&path);
        for word in ["ureq::", "std::net", "TcpStream", "TcpListener", "reqwest"] {
            assert!(!code.contains(word), "{} names `{word}` outside coach/egress.rs", path.display());
        }
    }
}

#[test]
fn child_processes_are_spawned_only_by_the_sidecar_module() {
    // `std::process::id()` (a unique temp-folder name) is not a spawn; naming `Command` or `Stdio` is.
    // Verified when this test was written: `src/sidecar.rs` is the only file that names `Command` (it starts the
    // bundled core); `lib.rs` and `inproc.rs` do not. `tests/inproc.rs` spawns the CLI, but a test file is not
    // shipped code and is outside `src/`.
    let src = manifest().join("src");
    let sidecar = src.join("sidecar.rs");
    assert!(sidecar.is_file(), "the one spawning file exists");
    let files = files_under(&src, "rs");
    assert!(files.len() >= 6, "the sources are where the test looks: {files:?}");
    for path in files {
        if path == sidecar {
            continue;
        }
        let code = text(&path);
        for word in ["Command::new", "process::Command", "std::process::{", "process::{", "Stdio::", "tokio::process"] {
            assert!(!code.contains(word), "{} names `{word}` outside sidecar.rs", path.display());
        }
    }
    assert!(text(&sidecar).contains("Command::new("), "the pin would be empty if the sidecar stopped spawning");
}

#[test]
fn the_coach_module_never_prints_logs_or_formats_with_debug() {
    let coach = manifest().join("src").join("coach");
    let files = files_under(&coach, "rs");
    assert!(files.len() >= 4, "mod, egress, egress_guard, prompt: {files:?}");
    for path in files {
        let source = text(&path);
        let code = non_test_code(&source);
        for word in ["println!", "eprintln!", "dbg!", "log::", "tracing::", "core.note", "{:?}"] {
            assert!(!code.contains(word), "{} contains `{word}` (a key or a body could ride on it)", path.display());
        }
    }
}

#[test]
fn the_frontend_has_no_network_or_navigation_primitive() {
    let words = [
        "fetch(",
        "XMLHttpRequest",
        "WebSocket",
        "sendBeacon",
        "EventSource",
        "navigator.serviceWorker",
        "window.open",
        "location.href =",
        "location.assign",
        "<a href=\"http",
        "target=\"_blank\"",
        "_blank",
    ];
    let mut sources = files_under(&app_dir().join("src"), "ts");
    assert!(sources.len() >= 4, "the TypeScript sources are where the test looks: {sources:?}");
    sources.push(app_dir().join("index.html"));
    for path in sources {
        let code = text(&path);
        for word in words {
            assert!(!code.contains(word), "{} contains `{word}`", path.display());
        }
    }
}
