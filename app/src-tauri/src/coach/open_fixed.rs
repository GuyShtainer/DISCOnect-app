// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one spawn this crate uses besides `sidecar.rs` (Bet 17 factors it out of `handoff.rs`, which used
//! to be the second one): opens a fixed `https` site in the system browser (`/usr/bin/open`). Both
//! [`super::handoff`] and [`super::support`] call [`open_fixed`] with a `&'static str` literal from their
//! own closed `match`; no string ever reaches this file except that literal, so no path, subdomain, flag
//! or other URL scheme can ride along on anything runtime-read.

/// Why [`open_fixed`] could not open the site. Closed; every message is fixed text and holds no url.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// `/usr/bin/open` ran and exited with a non-zero status, or could not be spawned at all.
    OpenFailed,
    /// Not macOS: there is no fixed-site opener for this target.
    Unsupported,
}

impl OpenError {
    /// A stable short code, for a caller to switch on.
    pub fn code(&self) -> &'static str {
        match self {
            OpenError::OpenFailed => "open_failed",
            OpenError::Unsupported => "unsupported",
        }
    }

    /// A fixed, user-facing message. Holds no url.
    pub fn message(&self) -> &'static str {
        match self {
            OpenError::OpenFailed => "the browser could not be opened",
            OpenError::Unsupported => "this computer has no fixed-site opener",
        }
    }
}

/// Open `site` in the system browser: the one spawn in this file, and its only argument. `site` is always a
/// `&'static str` literal from a caller's own closed `match` — never a string built from anything read at
/// runtime.
#[cfg(target_os = "macos")]
pub fn open_fixed(site: &'static str) -> Result<(), OpenError> {
    use std::process::{Command, Stdio};
    let status = Command::new("/usr/bin/open")
        .arg(site)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| OpenError::OpenFailed)?;
    if status.success() {
        Ok(())
    } else {
        Err(OpenError::OpenFailed)
    }
}

/// Not macOS: there is no fixed-site opener for this target.
#[cfg(not(target_os = "macos"))]
pub fn open_fixed(_site: &'static str) -> Result<(), OpenError> {
    Err(OpenError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_errors_have_distinct_non_empty_codes_and_messages() {
        let errors = [OpenError::OpenFailed, OpenError::Unsupported];
        let codes: std::collections::BTreeSet<_> = errors.iter().map(OpenError::code).collect();
        let messages: std::collections::BTreeSet<_> = errors.iter().map(OpenError::message).collect();
        assert_eq!(codes.len(), errors.len());
        assert_eq!(messages.len(), errors.len());
        assert!(codes.iter().all(|c| !c.is_empty()) && messages.iter().all(|m| !m.is_empty()));
    }
}
