// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::crypto::blake3::{blake3_derive_key, blake3_hash, blake3_hash_xof, blake3_keyed_hash};
use core::sync::atomic::{AtomicU64, Ordering};

static HASH_COUNT: AtomicU64 = AtomicU64::new(0);
static BYTES_HASHED: AtomicU64 = AtomicU64::new(0);

pub(super) fn hash(data: &[u8], output: &mut [u8; 32]) {
    let result = blake3_hash(data);
    output.copy_from_slice(&result);
    HASH_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_HASHED.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub(super) fn hash_xof(data: &[u8], output: &mut [u8], len: usize) {
    blake3_hash_xof(data, &mut output[..len]);
    HASH_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_HASHED.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub(super) fn keyed_hash(key: &[u8; 32], data: &[u8], output: &mut [u8; 32]) {
    let result = blake3_keyed_hash(key, data);
    output.copy_from_slice(&result);
    HASH_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_HASHED.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub(super) fn derive_key(context: &[u8], input: &[u8], output: &mut [u8; 32]) {
    let ctx = core::str::from_utf8(context).unwrap_or("nonos");
    blake3_derive_key(ctx, input, output);
    HASH_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_HASHED.fetch_add(input.len() as u64, Ordering::Relaxed);
}

pub(super) fn get_stats() -> (u64, u64) {
    (HASH_COUNT.load(Ordering::Relaxed), BYTES_HASHED.load(Ordering::Relaxed))
}
