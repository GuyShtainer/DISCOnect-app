// SPDX-License-Identifier: AGPL-3.0-or-later
//! The product's only internet egress point (Bet 15, ADR 0010). Slice 4 puts the one choke point
//! here (`send(request) -> response`, with a test double); until then nothing in the app opens a
//! socket, and `tests/egress_guards.rs` fails the build if any other source file names a network type.

/// Placeholder so the path exists for the source guard; slice 4 gives it the client and the choke point.
pub struct Egress;
