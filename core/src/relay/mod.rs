// SPDX-License-Identifier: AGPL-3.0-or-later
//! The blind relay client (ADR 0005, pitch 10; the twin of `disconect/relay/`): encrypted
//! raw-record bundles between the user's devices through a dumb object store the user controls.
//!
//! The relay sees only ciphertext under an account id derived from the master key. Two things
//! travel: `raw_records` and the coverage claims in `export_ranges`; everything else is
//! recomputed by the normal import path on the receiving side. The wire format is the Python
//! core's (`docs/relay-protocol.md`): each core must read the other's bundles.

pub mod bundle;
pub mod config;
pub mod folder;
pub mod lan;
pub mod lan_server;
pub mod pair_routes;
pub mod sync;
