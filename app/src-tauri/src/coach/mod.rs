// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-app AI coaching (Bet 15, ADR 0010). Off by default; the only module that may open a network
//! connection is [`egress`] (`tests/egress_guards.rs` enforces it), and nothing in here logs.
//!
//! What a tool answer may carry out of the machine is decided by three pure modules, in this order:
//! [`views::project`] (an allowlist projection), [`schema::validate`] (a fail-closed positive schema) and
//! [`caps::fit`] (byte budgets).

pub mod caps;
pub mod egress;
pub mod egress_guard;
pub mod prompt;
pub mod schema;
pub mod views;
