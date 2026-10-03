// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-app AI coaching (Bet 15, ADR 0010). Off by default; the only module that may open a network
//! connection is [`egress`] (`tests/egress_guards.rs` enforces it), and nothing in here logs.

pub mod prompt;
