// SPDX-License-Identifier: AGPL-3.0-or-later
//! Support channels (Bet 17, donations only; the sponsor-message tier is cut — see ADR 0012). A closed
//! enum of fixed `https` sites the maintainer takes support through, `match`ed to `&'static str` literals
//! and opened in the system browser through [`super::open_fixed::open_fixed`], the one spawner this crate
//! shares with [`super::handoff`] besides `sidecar.rs`. This module opens no network connection of its own
//! and touches neither [`super::settings`] nor [`super::key`] nor the coach's one choke point for the rest.
//!
//! **The table ships empty.** Which channels exist, if any, is Guy's decision, not this bet's: shipping a
//! default would make it the author's choice instead. Adding one later is five edits, all in plain sight:
//! one arm on [`SupportSite`]; one row each in [`site`], [`host`] and [`name`]; the arm listed in [`SITES`]
//! (what the screen actually shows — an arm missing there ships invisible); and one row in
//! `identity.ts`'s `SUPPORT_SITES` mirror (drift-pinned the same way `PROVIDERS` pins `handoff.rs`, by
//! `test_lint_app.py`). The literal test below picks up a new arm by itself — it passes vacuously today
//! because [`SITES`] is empty, and starts enforcing the day an arm exists.

use serde::{Deserialize, Serialize};

use super::commands::CoachError;
use super::open_fixed::{self, OpenError};

/// One of the maintainer's support channels. Closed; the IPC boundary carries this, never a URL. Empty
/// today on purpose (see the module doc): a channel is added here first, then in [`site`], [`host`] and
/// [`name`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportSite {}

/// The one fixed `https` address [`open_support_site`] opens for `s`. No scheme, host or path is ever built
/// from anything but this `match`. Vacuous today: `SupportSite` has no arm, so there is nothing to match.
pub fn site(s: SupportSite) -> &'static str {
    match s {}
}

/// The host of [`site`], for the card to show before the click. Vacuous today.
pub fn host(s: SupportSite) -> &'static str {
    match s {}
}

/// The plain name shown on the card (no logo, no channel colour: the same position `handoff.rs` takes for
/// its five chats). Vacuous today.
pub fn name(s: SupportSite) -> &'static str {
    match s {}
}

/// Every channel this build ships, for an exhaustive pass over all of them (the test below, and the
/// command that lists them for the screen). Empty today; see the module doc.
pub const SITES: [SupportSite; 0] = [];

/// Why [`open_support_site`] could not open the site. Closed; every message is fixed text, holds no url,
/// and names no payment or tax word (legal review condition 2, 2026-10-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportError {
    /// The browser did not open, or exited non-zero.
    OpenFailed,
    /// Not macOS: there is no fixed-site opener for this target.
    Unsupported,
}

impl SupportError {
    /// A stable short code, for the frontend to switch on.
    pub fn code(&self) -> &'static str {
        match self {
            SupportError::OpenFailed => "open_failed",
            SupportError::Unsupported => "unsupported",
        }
    }

    /// A fixed, user-facing message. Holds no url.
    pub fn message(&self) -> &'static str {
        match self {
            SupportError::OpenFailed => "the browser could not be opened",
            SupportError::Unsupported => "this computer has no fixed-site opener for a support channel",
        }
    }
}

impl From<OpenError> for SupportError {
    fn from(e: OpenError) -> Self {
        match e {
            OpenError::OpenFailed => SupportError::OpenFailed,
            OpenError::Unsupported => SupportError::Unsupported,
        }
    }
}

impl From<SupportError> for CoachError {
    fn from(e: SupportError) -> Self {
        CoachError::plain(e.code(), e.message(), None)
    }
}

/// Open `site(s)` in the system browser. No network connection of its own: the one call out is
/// [`super::open_fixed::open_fixed`].
pub fn open_support_site(s: SupportSite) -> Result<(), SupportError> {
    open_fixed::open_fixed(site(s)).map_err(SupportError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    /// Every site is a plain `https` literal with the host [`host`] names, no port, query, fragment or
    /// userinfo, and a non-empty name. Passes vacuously today ([`SITES`] is empty); it starts enforcing the
    /// day a channel is added (see the module doc).
    #[test]
    fn every_site_has_a_name_a_host_and_one_fixed_plain_https_site() {
        for s in SITES {
            let url = Url::parse(site(s)).unwrap_or_else(|e| panic!("{s:?}: {e}"));
            assert_eq!(url.scheme(), "https", "{s:?}");
            assert_eq!(url.host_str(), Some(host(s)), "{s:?}");
            assert_eq!(url.port(), None, "{s:?}");
            assert_eq!(url.query(), None, "{s:?}");
            assert_eq!(url.fragment(), None, "{s:?}");
            assert!(url.username().is_empty() && url.password().is_none(), "{s:?}");
            assert!(!name(s).is_empty(), "{s:?}");
        }
    }

    /// `SupportSite` round-trips through serde the way `ProviderId` does. Vacuous today, same reason — and
    /// written so the compiler's own "uninhabited type" reachability analysis does not warn about a `SITES`
    /// of length zero (a bare `let back: SupportSite = …` binding would, even unreached inside the loop).
    #[test]
    fn every_site_round_trips_through_serde_and_the_table_ships_empty() {
        for s in SITES {
            let json = serde_json::to_string(&s).unwrap();
            assert!(serde_json::from_str::<SupportSite>(&json).is_ok());
        }
        assert_eq!(SITES.len(), 0, "the table ships empty: the channels are Guy's decision");
    }

    /// The one property an empty enum has: it refuses every wire value. `support_open` therefore cannot be
    /// called with anything today — not a made-up id, not a number, not null.
    #[test]
    fn the_empty_enum_refuses_every_wire_value() {
        for wire in ["\"kofi\"", "\"\"", "0", "null", "{}", "[]"] {
            assert!(serde_json::from_str::<SupportSite>(wire).is_err(), "{wire} was accepted");
        }
    }
}
