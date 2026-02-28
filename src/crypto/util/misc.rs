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
use super::entropy::get_entropy;

pub fn secure_random_u64() -> u64 {
    let entropy = get_entropy(8);
    if entropy.len() >= 8 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&entropy[..8]);
        u64::from_le_bytes(bytes)
    } else {
        unsafe { core::arch::x86_64::_rdtsc() }
    }
}

pub fn secure_random_u32() -> u32 {
    (secure_random_u64() >> 32) as u32
}

pub fn secure_random_bytes(buffer: &mut [u8]) {
    let entropy = get_entropy(buffer.len());
    buffer.copy_from_slice(&entropy[..buffer.len()]);
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn secure_zero(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
