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
#[cfg_attr(target_os = "ios", ignore = "runs the host `cargo tree` (cargo and rustc are not on the simulator PATH) to pin the DESKTOP build graph, which an iOS run does not change")]
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
#[cfg_attr(target_os = "ios", ignore = "runs the host `cargo tree` (cargo and rustc are not on the simulator PATH) to pin the DESKTOP build graph, which an iOS run does not change")]
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
    // `src/sidecar.rs` starts the bundled core. `src/coach/open_fixed.rs` (Bet 17) is the one spawner the
    // hand-off and the support screen now share, opening one of a closed set of fixed sites in the system
    // browser — `handoff.rs` carried this spawn alone until Bet 17 factored it out so `support.rs` could
    // reuse it without a second `Command::new`. No other file names `Command` or `Stdio`. `tests/inproc.rs`
    // spawns the CLI, but a test file is not shipped code and is outside `src/`.
    let src = manifest().join("src");
    let sidecar = src.join("sidecar.rs");
    let open_fixed = src.join("coach").join("open_fixed.rs");
    let handoff = src.join("coach").join("handoff.rs");
    let support = src.join("coach").join("support.rs");
    assert!(sidecar.is_file(), "the one spawning file exists");
    assert!(open_fixed.is_file(), "the fixed-site opener exists");
    assert!(handoff.is_file() && support.is_file(), "the hand-off and the support screen exist");
    let files = files_under(&src, "rs");
    assert!(files.len() >= 6, "the sources are where the test looks: {files:?}");
    for path in files {
        if path == sidecar || path == open_fixed {
            continue;
        }
        let code = text(&path);
        for word in ["Command::new", "process::Command", "std::process::{", "process::{", "Stdio::", "tokio::process"] {
            assert!(!code.contains(word), "{} names `{word}` outside sidecar.rs or open_fixed.rs", path.display());
        }
    }
    assert!(text(&sidecar).contains("Command::new("), "the pin would be empty if the sidecar stopped spawning");

    // open_fixed.rs spawns exactly once, and only ever the fixed `/usr/bin/open` binary: no string built
    // from input ever reaches `Command::new`, and no second egress route hides in the same file.
    let open_fixed_code = text(&open_fixed);
    let spawns: Vec<&str> = open_fixed_code.match_indices("Command::new(").map(|(i, _)| &open_fixed_code[i..]).collect();
    assert_eq!(spawns.len(), 1, "open_fixed.rs spawns exactly once: {spawns:?}");
    assert!(
        spawns[0].starts_with("Command::new(\"/usr/bin/open\")"),
        "open_fixed.rs's one spawn names the fixed opener literally: {}",
        &spawns[0][..spawns[0].len().min(60)]
    );
    // The `&'static str` type is what keeps a runtime string out of the spawn; `String::leak`/`Box::leak`
    // would manufacture one, so no coach file may name `leak`, and only the two closed tables may call in.
    for path in files_under(&src.join("coach"), "rs") {
        let code = text(&path);
        let non_test = non_test_code(&code);
        for call in [".leak(", "::leak("] {
            assert!(!non_test.contains(call), "{} calls `{call}` in non-test code", path.display());
        }
        let calls = non_test.matches("open_fixed(").count();
        if path == handoff || path == support {
            assert_eq!(calls, 1, "{} calls open_fixed exactly once", path.display());
        } else if path != open_fixed {
            assert_eq!(calls, 0, "{} calls open_fixed; only handoff.rs and support.rs may", path.display());
        }
    }
    let open_fixed_non_test = non_test_code(&open_fixed_code);
    for word in ["egress", "ureq", "Url::parse"] {
        assert!(!open_fixed_non_test.contains(word), "open_fixed.rs's non-test code names `{word}`");
    }
    for line in open_fixed_non_test.lines() {
        if line.contains("format!(") {
            assert!(!line.to_lowercase().contains("http"), "a format! in open_fixed.rs's non-test code names a URL scheme: {line}");
        }
    }

    // handoff.rs and support.rs delegate the spawn to open_fixed.rs: neither names Command or Stdio any more.
    for (name, path) in [("handoff.rs", &handoff), ("support.rs", &support)] {
        let code = text(path);
        for word in ["Command", "Stdio"] {
            assert!(!code.contains(word), "{name} names `{word}`: the spawn must live only in open_fixed.rs");
        }
    }
}

#[test]
fn handoff_never_touches_egress_and_handoff_build_never_touches_the_key_or_the_provider() {
    // Bet 15c slice 1, evidence (a): the hand-off works while the coach is off and opens no egress of its own.
    let handoff = manifest().join("src").join("coach").join("handoff.rs");
    let handoff_code = text(&handoff);
    let handoff_non_test = non_test_code(&handoff_code);
    for word in ["egress", "send(", "ureq", "Egress"] {
        assert!(!handoff_non_test.contains(word), "handoff.rs's non-test code names `{word}`");
    }

    // `commands.rs::handoff_build` (and its blocking half) never reads the provider settings, the key or the
    // egress module: sliced from `fn handoff_build` to the next `#[tauri::command]` attribute, so the slice
    // holds exactly `handoff_build` and `handoff_build_blocking`, never `handoff_open`.
    let commands = manifest().join("src").join("coach").join("commands.rs");
    let commands_code = text(&commands);
    let start = commands_code.find("fn handoff_build").expect("handoff_build exists in commands.rs");
    let rest = &commands_code[start..];
    let end = rest[1..].find("#[tauri::command]").map_or(rest.len(), |i| i + 1);
    let body = &rest[..end];
    for word in ["provider", "KeyHolder", "egress"] {
        assert!(!body.contains(word), "handoff_build's body names `{word}`: it must not touch the key or egress");
    }
}

#[test]
fn support_and_open_fixed_never_touch_egress_and_the_support_commands_never_touch_the_key_or_the_provider() {
    // Bet 17, the same shape as the hand-off's guard above: the support screen opens no network connection
    // of its own, and its two commands in commands.rs never read the provider settings, the key or egress.
    let support = manifest().join("src").join("coach").join("support.rs");
    let open_fixed = manifest().join("src").join("coach").join("open_fixed.rs");
    for path in [&support, &open_fixed] {
        let code = text(path);
        let non_test = non_test_code(&code);
        for word in ["egress", "send(", "ureq", "Egress", "Url::parse"] {
            assert!(!non_test.contains(word), "{} non-test code names `{word}`", path.display());
        }
        for line in non_test.lines() {
            if line.contains("format!(") {
                assert!(!line.to_lowercase().contains("http"), "a format! in {} non-test code names a URL scheme: {line}", path.display());
            }
        }
    }

    // `commands.rs::support_sites` and `support_open`: each sliced from its own `fn` to the next
    // `#[tauri::command]` attribute, the same slicing `handoff_build` uses above.
    let commands = manifest().join("src").join("coach").join("commands.rs");
    let commands_code = text(&commands);
    for fn_name in ["fn support_sites", "fn support_open"] {
        let start = commands_code.find(fn_name).unwrap_or_else(|| panic!("{fn_name} exists in commands.rs"));
        let rest = &commands_code[start..];
        let end = rest[1..].find("#[tauri::command]").map_or(rest.len(), |i| i + 1);
        let body = &rest[..end];
        for word in ["provider", "KeyHolder", "egress"] {
            assert!(!body.contains(word), "{fn_name}'s body names `{word}`: it must not touch the key or egress");
        }
    }
}

#[test]
fn bundle_resources_are_exactly_the_two_core_sidecars() {
    // No test pinned `bundle.resources` before Bet 17; it is the one door through which a bundled binary
    // reaches the shipped app, and the two paths here are the only entries that door may ever carry.
    let config: Value = serde_json::from_str(&text(&manifest().join("tauri.conf.json"))).expect("tauri.conf.json parses as json");
    let resources = config["bundle"]["resources"].as_object().expect("bundle.resources is a map");
    let keys: BTreeSet<String> = resources.keys().cloned().collect();
    assert_eq!(
        keys,
        BTreeSet::from(["resources/hearthbeat-core/".to_string(), "resources/disconect-core/".to_string()])
    );
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

// ---- the Import drop (pitch 7b-3) -------------------------------------------------------------------

#[test]
fn the_webview_names_no_import_path_and_the_debug_doors_exist_only_in_debug_builds() {
    let src = manifest().join("src");
    // the drop is handled in Rust: no command anywhere takes a path, and the import module registers none
    let drop_rs = text(&src.join("import_drop.rs"));
    assert!(!non_test_code(&drop_rs).contains("#[tauri::command]"), "import_drop.rs registers no command");
    let lib = text(&src.join("lib.rs"));
    assert!(lib.contains("tauri::DragDropEvent::Drop { paths, .. }"), "the OS drop reaches Rust");
    for path in files_under(&src, "rs") {
        let code = text(&path);
        if let Some(line) = code.lines().find(|l| l.contains("fn ") && l.contains("path: String")) {
            panic!("{} has a function taking a path as a string, a webview-shaped door: {line}", path.display());
        }
    }
    // every debug env name appears only in lib.rs, each inside an item that starts at a `#[cfg(debug_assertions)]`
    // line (the item is the text from that attribute to the next top-level closing brace); a `#[cfg(test)]` item may
    // name one anywhere. Whole files are read and every `DISCONECT_DEBUG_*` spelling is checked, not a list: lib.rs
    // has a test module in its middle, and cutting each file at its first `#[cfg(test)]` once hid every door (12-D
    // review S1).
    let doors = debug_env_names(&lib);
    assert!(doors.len() >= 7, "the check reads lib.rs's debug doors: {doors:?}");
    for path in files_under(&src, "rs") {
        let code = text(&path);
        for (at, _) in code.match_indices("DISCONECT_DEBUG_") {
            let name = debug_env_names(&code[at..]).into_iter().next().unwrap_or_default();
            let line_start = code[..at].rfind('\n').map_or(0, |i| i + 1);
            if code[line_start..at].trim_start().starts_with("//") {
                continue; // a doc comment naming the variable
            }
            let gate = ["#[cfg(debug_assertions)]", "#[cfg(test)]"]
                .into_iter()
                .filter_map(|attr| code[..at].rfind(attr).map(|i| (i, attr)))
                .max();
            let head = gate.map_or("\n}\n", |(i, _)| &code[i..at]);
            assert!(!head.contains("\n}\n"), "{name} sits outside a `#[cfg(debug_assertions)]` item: {}", path.display());
            if gate.is_some_and(|(_, attr)| attr == "#[cfg(debug_assertions)]") {
                assert!(path.ends_with("lib.rs"), "{name} appears outside lib.rs: {}", path.display());
            }
        }
    }
}

/// Every `DISCONECT_DEBUG_*` name a source spells out.
fn debug_env_names(code: &str) -> BTreeSet<String> {
    code.match_indices("DISCONECT_DEBUG_")
        .map(|(at, prefix)| {
            let rest = &code[at + prefix.len()..];
            let len = rest.find(|c: char| !(c.is_ascii_uppercase() || c == '_')).unwrap_or(rest.len());
            format!("{prefix}{}", &rest[..len])
        })
        .collect()
}

// ---- one web client on the phone (12-D item 5) -----------------------------------------------------------

#[test]
fn an_ios_release_cannot_compile_with_tauris_dev_server_proxy() {
    // `dev` is false only with `tauri/custom-protocol` (the tauri CLI sets it for a release); without it tauri's
    // dev-server proxy (`reqwest`/`hyper`, a second web client) would ship in the phone's release build.
    let lib = text(&manifest().join("src").join("lib.rs"));
    let lines: Vec<&str> = lib.lines().collect();
    let at = lines
        .iter()
        .position(|l| *l == "#[cfg(all(dev, target_os = \"ios\", not(debug_assertions)))]")
        .expect("lib.rs has the pin's #[cfg(all(dev, target_os = \"ios\", not(debug_assertions)))] line");
    assert!(lines[at + 1].starts_with("compile_error!("), "the pin's cfg line is followed directly by compile_error!: {}", lines[at + 1]);
}

// ---- the page's door to the core, and what the page hears about a drag (7b-3 review) -----------------

/// The method literals a TypeScript source passes to `call(...)` / `call<T>(...)` or names as `method: "..."`.
fn called_methods(ts: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let bytes = ts.as_bytes();
    let literal_at = |from: usize| -> Option<String> {
        let rest = ts[from..].trim_start();
        let rest = rest.strip_prefix('"')?;
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    };
    for (at, _) in ts.match_indices("call") {
        let mut i = at + 4;
        if bytes.get(i) == Some(&b'<') {
            let mut depth = 0;
            while i < bytes.len() {
                match bytes[i] {
                    b'<' => depth += 1,
                    b'>' => {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        }
        if bytes.get(i) == Some(&b'(') {
            if let Some(m) = literal_at(i + 1) {
                found.insert(m);
            }
        }
    }
    for (at, _) in ts.match_indices("method:") {
        if let Some(m) = literal_at(at + 7) {
            found.insert(m);
        }
    }
    found
}

fn allowed_methods_in_lib() -> BTreeSet<String> {
    let lib = text(&manifest().join("src").join("lib.rs"));
    let body = lib.split("pub const ALLOWED_METHODS: &[&str] = &[").nth(1).expect("the allow-list is in lib.rs").split("];").next().expect("closed list");
    body.split('"').skip(1).step_by(2).map(str::to_string).collect()
}

#[test]
fn the_generic_core_door_forwards_only_the_methods_the_page_calls_and_never_import_run() {
    let allowed = allowed_methods_in_lib();
    assert!(allowed.len() >= 10, "the list was parsed: {allowed:?}");
    let mut used = BTreeSet::new();
    for path in files_under(&app_dir().join("src"), "ts") {
        used.extend(called_methods(&text(&path)));
    }
    assert!(used.contains("data.today") && used.contains("key.unlock"), "the scanner sees the calls: {used:?}");
    // the phone's own method is on the phone's list only (the next test); the desktop list is the first one
    used.remove("pair.forget");
    assert!(used.is_subset(&allowed), "a method the page calls is missing from ALLOWED_METHODS: {:?}", used.difference(&allowed).collect::<Vec<_>>());
    assert!(!allowed.contains("import.run"), "an import starts only from the OS drop, never from the page");
    let lib = text(&manifest().join("src").join("lib.rs"));
    let core_call = lib.split("async fn core_call(").nth(1).expect("core_call").split("\n}\n").next().expect("body");
    assert!(core_call.contains("method_refusal(&method)?"), "core_call checks the list before it reaches the core");
    // the refusal is fixed and never echoes the method
    let err = disconect_app_lib::method_refusal("import.run").expect_err("off the list");
    assert_eq!((err.code.as_str(), err.message.as_str()), ("refused", "that method is not available to the page"));
    assert!(disconect_app_lib::method_refusal("data.today").is_ok());
}

#[test]
fn the_phones_method_list_drops_the_four_server_side_methods_and_adds_only_forget() {
    let lib = text(&manifest().join("src").join("lib.rs"));
    let mut lists = lib.split("pub const ALLOWED_METHODS: &[&str] = &[").skip(1).map(|t| t.split("];").next().expect("closed list"));
    let names = |body: &str| -> BTreeSet<String> { body.split('"').skip(1).step_by(2).map(str::to_string).collect() };
    let (desktop, phone) = (names(lists.next().expect("the desktop list")), names(lists.next().expect("the phone list")));
    assert!(lists.next().is_none(), "two lists, one per platform");
    let dropped: BTreeSet<String> = desktop.difference(&phone).cloned().collect();
    assert_eq!(dropped, ["pair.confirm", "pair.offer", "relay.addresses", "relay.serve"].map(String::from).into_iter().collect(), "only the four server-side methods go");
    let added: BTreeSet<String> = phone.difference(&desktop).cloned().collect();
    assert_eq!(added, ["pair.forget"].map(String::from).into_iter().collect(), "the phone's list adds only its own forget method");
    let page = app_dir().join("src").join("app.ts");
    assert!(text(&page).contains("\"pair.forget\""), "the page calls the method the phone's list adds");
}

#[test]
fn the_page_hears_a_drag_only_as_a_bare_over_flag_and_a_release_build_drops_debug_flags() {
    let lib = text(&manifest().join("src").join("lib.rs"));
    let emits: Vec<&str> = lib.lines().filter(|l| l.contains("\"core://drag\"")).collect();
    assert_eq!(emits.len(), 1, "one place emits core://drag: {emits:?}");
    assert!(emits[0].contains("json!({ \"over\": over })") && !emits[0].contains("paths"), "{}", emits[0]);
    // nothing in the page listens to the window's own drag events (they deliver the dragged paths to the page)
    for path in files_under(&app_dir().join("src"), "ts") {
        assert!(!text(&path).contains("tauri://drag"), "{} listens to a tauri drag event", path.display());
    }
    // a release build ignores `--debug-*` typed on the command line
    let args = lib.split("fn launch_args()").nth(1).expect("launch_args").split("\n}\n").next().expect("body");
    let at = args.find("args = release_args(args)").expect("the filter");
    assert!(args[..at].trim_end().ends_with("if !cfg!(debug_assertions) {"), "the filter is release-only");
    // 7b-5: `--debug-window` sets the window size only inside a debug-only item, and only in the window build
    let door = "--debug-window";
    for (n, _) in lib.match_indices(door) {
        let line_start = lib[..n].rfind('\n').map_or(0, |i| i + 1);
        if lib[line_start..n].trim_start().starts_with("//") {
            continue;
        }
        let attr = lib[..n].rfind("#[cfg(debug_assertions)]").expect("--debug-window sits after a debug-only attribute");
        assert!(!lib[attr..n].contains("\n}\n"), "--debug-window sits outside a `#[cfg(debug_assertions)]` item");
    }
    assert!(lib.contains("fn debug_window_size") && lib.contains("config.width = w;"), "the door sets the built window's size");
}
