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

use crate::crypto::sha3::keccak256 as crypto_keccak256;
use crate::crypto::sha3::{sha3_256 as crypto_sha3_256, sha3_512 as crypto_sha3_512};
use core::sync::atomic::{AtomicU64, Ordering};

static HASH_COUNT: AtomicU64 = AtomicU64::new(0);
static BYTES_HASHED: AtomicU64 = AtomicU64::new(0);

pub(super) fn sha3_256(data: &[u8], output: &mut [u8; 32]) {
    let result = crypto_sha3_256(data);
    output.copy_from_slice(&result);
    HASH_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_HASHED.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub(super) fn sha3_512(data: &[u8], output: &mut [u8; 64]) {
    let result = crypto_sha3_512(data);
    output.copy_from_slice(&result);
    HASH_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_HASHED.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub(super) fn keccak_256(data: &[u8], output: &mut [u8; 32]) {
    let result = crypto_keccak256(data);
    output.copy_from_slice(&result);
    HASH_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_HASHED.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub(super) fn get_stats() -> (u64, u64) {
    (HASH_COUNT.load(Ordering::Relaxed), BYTES_HASHED.load(Ordering::Relaxed))
}
