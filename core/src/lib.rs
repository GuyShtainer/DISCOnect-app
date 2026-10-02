// SPDX-License-Identifier: AGPL-3.0-or-later
//! DISCOnect Rust core, slice 1a: the key file, the write lock and the SQLCipher store.
//!
//! The Python core is the oracle: this crate opens the same store with the same key file.

pub mod keys;
pub mod store;
pub mod time;
pub mod write_lock;
