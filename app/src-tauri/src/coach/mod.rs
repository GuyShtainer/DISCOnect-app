// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-app AI coaching (Bet 15, ADR 0010). Off by default; the only module that may open a network
//! connection is [`egress`] (`tests/egress_guards.rs` enforces it), and nothing in here logs.
//!
//! What a tool answer may carry out of the machine is decided by three pure modules, in this order:
//! [`views::project`] (an allowlist projection), [`schema::validate`] (a fail-closed positive schema) and
//! [`caps::fit`] (byte budgets). [`gate::gate_tool`] runs a clamped tool call through the projection, then
//! `fit`, then the schema (the shrunken value is what gets validated); it is the one gate both [`chat_loop`]
//! and [`handoff`] use.
//!
//! The loop (slice 5): [`prompt`] is the system prompt, [`wire`] the chat-completions format, [`chat_loop`] one
//! question end to end with its window manager, [`commands::coach_ask`] the Tauri command over it.
//!
//! The probe (slice 6): [`probe`] asks an endpoint whether it calls tools and how much prompt it reads.
//!
//! The hand-off (Bet 15c slice 1): [`handoff`] builds the same five tool answers as one text block for the
//! user's own chat, and opens one of five fixed sites in the system browser. It opens no network connection
//! itself and does not touch [`settings`], [`key`] or [`provider`]: the hand-off works while the coach is off.
//!
//! Support channels (Bet 17, donations only): [`support`] is a closed, empty-today table of fixed sites, on
//! the same shape as [`handoff`]'s five chats; [`open_fixed`] is the one spawner the two share besides
//! `sidecar.rs`.
//!
//! Provider plumbing (slice 4): [`settings`] holds the non-secret provider settings (`Off` by default),
//! [`key`] the user's key (OS keychain or session memory), [`egress`] the one choke point. [`provider`] is
//! how a caller gets an egress: `None` means the coach is off and the caller must send nothing.

pub mod caps;
pub mod commands;
pub mod egress;
pub mod egress_guard;
pub mod gate;
pub mod handoff;
pub mod key;
pub mod open_fixed;
pub mod probe;
pub mod prompt;
pub mod schema;
pub mod settings;
pub mod support;
pub mod views;
pub mod wire;
#[path = "loop.rs"]
pub mod chat_loop;

use egress::{Egress, Endpoint, Real};
use settings::Settings;

/// The egress the settings call for, built by `make` from the validated endpoint. `Off` (and an address that
/// fails the egress rules) is `None` **without calling `make`**: no client object exists while the coach is off.
pub fn provider_with(settings: &Settings, make: impl FnOnce(Endpoint) -> Box<dyn Egress>) -> Option<Box<dyn Egress>> {
    Endpoint::from_settings(settings).ok().map(make)
}

/// The real network egress for these settings, or `None` (off or unusable address).
pub fn provider(settings: &Settings) -> Option<Box<dyn Egress>> {
    provider_with(settings, |endpoint| Box::new(Real::new(endpoint)))
}

#[cfg(test)]
mod tests {
    use super::egress::{Fake, Inbound, Outbound};
    use super::settings::Mode;
    use super::*;
    use std::sync::Arc;

    /// An egress that forwards to a shared [`Fake`] so the test can count what the provider plumbing sent.
    struct Shared(Arc<Fake>);
    impl Egress for Shared {
        fn send(&self, out: Outbound) -> Result<Inbound, egress::EgressError> {
            self.0.send(out)
        }
    }

    fn settings(mode: Mode) -> Settings {
        Settings { mode, base_url: "http://127.0.0.1:11434/v1".into(), model: "m".into(), ..Settings::default() }
    }

    #[test]
    fn off_builds_nothing_and_a_caller_that_honours_none_sends_zero() {
        let fake = Arc::new(Fake::new());
        let built = std::cell::Cell::new(0);
        let off = provider_with(&settings(Mode::Off), |_| {
            built.set(built.get() + 1);
            Box::new(Shared(fake.clone()))
        });
        assert!(off.is_none(), "off is None");
        assert_eq!(built.get(), 0, "the factory is never called while off");
        assert_eq!(fake.count(), 0);
        assert!(provider(&settings(Mode::Off)).is_none());

        let on = provider_with(&settings(Mode::Local), |_| Box::new(Shared(fake.clone()))).expect("local is on");
        let url = Endpoint::parse("http://127.0.0.1:11434/v1").unwrap().join("chat/completions").unwrap();
        fake.push(Ok(Inbound { status: 200, body: b"{}".to_vec() }));
        assert!(on.send(Outbound { url, bearer: None, body: b"{}".to_vec() }).is_ok());
        assert_eq!(fake.count(), 1);

        // an address the egress rules refuse is also "no provider", not a half-built one
        let bad = Settings { base_url: "http://example.com".into(), ..settings(Mode::Cloud) };
        assert!(provider(&bad).is_none());
    }
}
