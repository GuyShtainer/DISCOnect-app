// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where the webview may navigate (Bet 15, pitch risk M1). The CSP does not cover top-level
//! navigation or `window.open`, so the main window is built in `setup` with this predicate as its
//! `on_navigation` hook and a deny-all `on_new_window` hook. A pure function so it is unit-tested.

use tauri::Url;

/// The devUrl port (`build.devUrl` in `tauri.conf.json`); only a debug build serves from it.
const DEV_PORT: u16 = 1420;

/// True only for the app's own origin: the `tauri` custom protocol on `localhost` (macOS, Linux, iOS),
/// `http(s)://tauri.localhost` or `http(s)://ipc.localhost` (Windows, Android), and the dev server at
/// `http://localhost:1420` **in a debug build only**. Everything else, including `file:`, `data:`,
/// `javascript:` and every other host or port, is refused; in a release build so is the dev server, which
/// no release serves from.
pub fn navigation_allowed(url: &Url) -> bool {
    navigation_allowed_with(url, cfg!(debug_assertions))
}

/// [`navigation_allowed`] with the build kind spelled out, so a test can assert the release rule from a debug
/// build.
pub fn navigation_allowed_with(url: &Url, debug: bool) -> bool {
    let host = url.host_str();
    match url.scheme() {
        "tauri" => host == Some("localhost") && url.port().is_none(),
        "http" | "https" => match host {
            Some("tauri.localhost" | "ipc.localhost") => url.port().is_none(),
            Some("localhost") => debug && url.scheme() == "http" && url.port() == Some(DEV_PORT),
            _ => false,
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The release rule: the one that ships.
    fn allowed(text: &str) -> bool {
        navigation_allowed_with(&Url::parse(text).expect("a url"), false)
    }

    /// The debug rule: the same, plus the dev server.
    fn allowed_in_debug(text: &str) -> bool {
        navigation_allowed_with(&Url::parse(text).expect("a url"), true)
    }

    #[test]
    fn the_apps_own_origins_are_allowed() {
        assert!(allowed("tauri://localhost"));
        assert!(allowed("tauri://localhost/index.html#/today"));
        assert!(allowed("http://tauri.localhost/"));
        assert!(allowed("https://tauri.localhost/"));
        assert!(allowed("http://ipc.localhost/core_call"));
    }

    #[test]
    fn the_dev_server_is_allowed_in_a_debug_build_only() {
        for url in ["http://localhost:1420/x", "http://localhost:1420"] {
            assert!(allowed_in_debug(url), "{url} in debug");
            assert!(!allowed(url), "{url} in release");
        }
        // debug adds nothing else
        assert!(!allowed_in_debug("https://localhost:1420"));
        assert!(!allowed_in_debug("http://localhost:8080"));
        assert!(!allowed_in_debug("http://127.0.0.1:1420/"));
        assert!(allowed_in_debug("tauri://localhost"));
        // the plain entry point follows the build it is compiled into
        let dev = Url::parse("http://localhost:1420/").expect("a url");
        assert_eq!(navigation_allowed(&dev), cfg!(debug_assertions));
    }

    #[test]
    fn every_other_host_scheme_or_port_is_refused() {
        assert!(!allowed("https://example.com"));
        assert!(!allowed("http://example.com/"));
        assert!(!allowed("http://localhost:8080"));
        assert!(!allowed("http://localhost"));
        assert!(!allowed("https://localhost:1420"));
        assert!(!allowed("file:///etc/hosts"));
        assert!(!allowed("data:text/html,<p>x</p>"));
        assert!(!allowed("javascript:alert(1)"));
        assert!(!allowed("about:blank"));
        assert!(!allowed("ws://localhost:1420"));
        assert!(!allowed("tauri://evil.example"));
    }

    #[test]
    fn look_alike_hosts_and_userinfo_tricks_are_refused() {
        assert!(!allowed("http://tauri.localhost.evil.example/"));
        assert!(!allowed("http://evil.example/tauri.localhost"));
        assert!(!allowed("http://tauri.localhost@evil.example/"));
        assert!(!allowed("http://localhost.evil.example:1420/"));
        assert!(!allowed("http://127.0.0.1:1420/"));
        assert!(!allowed("http://tauri.localhost:8080/"));
    }
}
