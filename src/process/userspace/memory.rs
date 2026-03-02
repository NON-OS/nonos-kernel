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

use alloc::string::String;
use alloc::vec::Vec;
use super::context::with_user_access;

const USER_SPACE_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

const KERNEL_SPACE_START: u64 = 0xFFFF_8000_0000_0000;

#[inline]
fn is_user_address(addr: u64) -> bool {
    addr <= USER_SPACE_MAX
}

#[inline]
fn is_user_range(addr: u64, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let end = addr.saturating_add(len as u64 - 1);
    is_user_address(addr) && is_user_address(end) && end >= addr
}

pub fn read_user<T: Copy>(addr: u64) -> Option<T> {
    // Validate address is in user range
    if !is_user_address(addr) {
        return None;
    }

    // Check alignment
    let align = core::mem::align_of::<T>() as u64;
    if align > 0 && addr % align != 0 {
        return None;
    }

    // Check range doesn't overflow into kernel space
    let size = core::mem::size_of::<T>();
    if !is_user_range(addr, size) {
        return None;
    }

    with_user_access(|| {
        // SAFETY: We have validated that:
        // 1. The address is in user space
        // 2. The address is properly aligned for type T
        // 3. The entire read range is in user space
        // 4. with_user_access disables SMAP protection for this operation
        // 5. We use volatile read to prevent compiler reordering
        unsafe { Some(core::ptr::read_volatile(addr as *const T)) }
    })
}

pub fn write_user<T: Copy>(addr: u64, value: T) -> bool {
    // Validate address is in user range
    if !is_user_address(addr) {
        return false;
    }

    // Check alignment
    let align = core::mem::align_of::<T>() as u64;
    if align > 0 && addr % align != 0 {
        return false;
    }

    // Check range doesn't overflow into kernel space
    let size = core::mem::size_of::<T>();
    if !is_user_range(addr, size) {
        return false;
    }

    with_user_access(|| {
        // SAFETY: We have validated that:
        // 1. The address is in user space
        // 2. The address is properly aligned for type T
        // 3. The entire write range is in user space
        // 4. with_user_access disables SMAP protection for this operation
        // 5. We use volatile write to prevent compiler reordering
        unsafe {
            core::ptr::write_volatile(addr as *mut T, value);
        }
        true
    })
}

pub fn copy_from_user(dst: &mut [u8], src_addr: u64) -> Result<usize, ()> {
    if !is_user_range(src_addr, dst.len()) {
        return Err(());
    }

    with_user_access(|| {
        // SAFETY: We have validated that the entire source range is in user space.
        // We read byte-by-byte using volatile reads to handle potential page faults.
        unsafe {
            let src = src_addr as *const u8;
            for (i, byte) in dst.iter_mut().enumerate() {
                *byte = core::ptr::read_volatile(src.add(i));
            }
        }
        Ok(dst.len())
    })
}

pub fn copy_to_user(dst_addr: u64, src: &[u8]) -> Result<usize, ()> {
    if !is_user_range(dst_addr, src.len()) {
        return Err(());
    }

    with_user_access(|| {
        // SAFETY: We have validated that the entire destination range is in user space.
        // We write byte-by-byte using volatile writes to handle potential page faults.
        unsafe {
            let dst = dst_addr as *mut u8;
            for (i, &byte) in src.iter().enumerate() {
                core::ptr::write_volatile(dst.add(i), byte);
            }
        }
        Ok(src.len())
    })
}

pub fn read_user_string(addr: u64, max_len: usize) -> Option<String> {
    if !is_user_address(addr) {
        return None;
    }

    let mut result = Vec::with_capacity(max_len.min(4096)); // Cap allocation

    with_user_access(|| {
        // SAFETY: We validate each byte is in user space before reading.
        // We stop at null terminator or max_len.
        unsafe {
            let ptr = addr as *const u8;
            for i in 0..max_len {
                // Check each address individually for safety
                let byte_addr = addr.saturating_add(i as u64);
                if !is_user_address(byte_addr) {
                    break;
                }
                let byte = core::ptr::read_volatile(ptr.add(i));
                if byte == 0 {
                    break;
                }
                result.push(byte);
            }
        }
    });

    String::from_utf8(result).ok()
}

pub fn read_user_string_array(
    array_addr: u64,
    max_count: usize,
    max_str_len: usize,
) -> Option<Vec<String>> {
    if !is_user_address(array_addr) {
        return None;
    }

    let mut result = Vec::with_capacity(max_count.min(256));

    for i in 0..max_count {
        let ptr_addr = array_addr.saturating_add((i * 8) as u64);

        // Read the string pointer
        let str_ptr: u64 = read_user(ptr_addr)?;

        // Null pointer terminates the array
        if str_ptr == 0 {
            break;
        }

        // Read the string
        let s = read_user_string(str_ptr, max_str_len)?;
        result.push(s);
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_user_address() {
        assert!(is_user_address(0));
        assert!(is_user_address(0x1000));
        assert!(is_user_address(USER_SPACE_MAX));
        assert!(!is_user_address(USER_SPACE_MAX + 1));
        assert!(!is_user_address(KERNEL_SPACE_START));
    }

    #[test]
    fn test_is_user_range() {
        assert!(is_user_range(0, 0));
        assert!(is_user_range(0, 4096));
        assert!(is_user_range(USER_SPACE_MAX, 1));
        assert!(!is_user_range(USER_SPACE_MAX, 2));
        assert!(!is_user_range(u64::MAX - 10, 100));
    }
}
