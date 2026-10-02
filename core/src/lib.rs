// SPDX-License-Identifier: AGPL-3.0-or-later
//! DISCOnect Rust core, slice 1a (the key file, the write lock and the SQLCipher store) and 1b (the FIT decoder) and slice 2B (the account-export ingest).
//!
//! The Python core is the oracle: this crate opens the same store with the same key file.

pub mod canon;
pub mod clock;
pub mod export;
pub mod fit;
pub mod keys;
pub mod model;
pub mod redact;
pub mod sources;
pub mod store;
pub mod time;
pub mod write_lock;
pub mod writer;
