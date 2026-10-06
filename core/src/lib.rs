// SPDX-License-Identifier: AGPL-3.0-or-later
//! DISCOnect Rust core, slice 1a (the key file, the write lock and the SQLCipher store) and 1b (the FIT decoder) and slice 2B (the account-export ingest) and slice 2C (the relay client).
//!
//! The Python core is the oracle: this crate opens the same store with the same key file.
//!
//! Slice 3A adds the `serve` transport and its start-up methods (`serve`, `keychain`, `wirejson`,
//! `identity`, `contract`). Nothing here prints to stdout: the protocol stream is the only one.
#![deny(clippy::print_stdout)]

pub mod canon;
pub mod clock;
pub mod contract;
pub mod export;
pub mod fit;
pub mod home;
pub mod identity;
pub mod keychain;
#[cfg(target_os = "ios")]
pub mod keychain_leftovers;
pub mod keys;
pub mod live;
pub mod mcp;
pub mod mcp_args;
pub mod mcp_start;
pub mod mcp_tools;
pub mod model;
pub mod pair;
pub mod pair_client;
pub mod read;
pub mod redact;
pub mod relay;
pub mod serve;
pub mod sources;
pub mod store;
pub mod time;
pub mod wirejson;
pub mod write_lock;
pub mod writer;
