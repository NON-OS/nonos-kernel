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

extern crate alloc;
use alloc::vec::Vec;
use core::ptr;

use crate::crypto::hash::blake3_hash;
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};

use super::constants::DOM_COMMIT;

pub fn commit(value: &[u8], nonce32: &[u8; 32]) -> [u8; 32] {
    let mut t = Vec::with_capacity(DOM_COMMIT.len() + 8 + value.len() + 32);
    t.extend_from_slice(DOM_COMMIT);
    t.extend_from_slice(&(value.len() as u64).to_le_bytes());
    t.extend_from_slice(value);
    t.extend_from_slice(nonce32);
    let c = blake3_hash(&t);

    for b in t.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();

    c
}

pub fn verify_commitment(commitment: &[u8; 32], value: &[u8], nonce32: &[u8; 32]) -> bool {
    &commit(value, nonce32) == commitment
}

pub fn commit_u64(value: u64, nonce32: &[u8; 32]) -> [u8; 32] {
    commit(&value.to_le_bytes(), nonce32)
}
