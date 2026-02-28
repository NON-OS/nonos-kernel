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

use crate::crypto::hash;

const MAX_MEMORY_REGION_SIZE: usize = 16 * 1024 * 1024;
const MIN_VALID_ADDR: usize = 0x1000;

pub fn hash_memory_region(start_addr: usize, size: usize, out: &mut [u8; 32]) -> Result<(), &'static str> {
    if start_addr < MIN_VALID_ADDR {
        return Err("Invalid address: null or low memory");
    }

    if size == 0 {
        return Err("Invalid size: zero");
    }
    if size > MAX_MEMORY_REGION_SIZE {
        return Err("Invalid size: exceeds maximum allowed region");
    }

    let end_addr = start_addr.checked_add(size).ok_or("Address overflow")?;
    if end_addr < start_addr {
        return Err("Address overflow");
    }

    // SAFETY: Validated address range, caller ensures memory is mapped and readable.
    let data = unsafe { core::slice::from_raw_parts(start_addr as *const u8, size) };
    *out = hash::sha256(data);
    Ok(())
}

pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // SAFETY: Volatile write prevents optimizer from removing zeroing.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

pub fn secure_erase_memory_region(start_addr: usize, size: usize) -> Result<(), &'static str> {
    if start_addr < MIN_VALID_ADDR {
        return Err("Invalid address: null or low memory");
    }

    if size == 0 {
        return Err("Invalid size: zero");
    }
    if size > MAX_MEMORY_REGION_SIZE {
        return Err("Invalid size: exceeds maximum allowed region");
    }

    let end_addr = start_addr.checked_add(size).ok_or("Address overflow")?;
    if end_addr < start_addr {
        return Err("Address overflow");
    }

    // SAFETY: Validated address range, caller ensures memory is mapped and writable.
    let data = unsafe { core::slice::from_raw_parts_mut(start_addr as *mut u8, size) };
    secure_zero(data);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    Ok(())
}
