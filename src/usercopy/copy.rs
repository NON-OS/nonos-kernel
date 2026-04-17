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

use super::error::UsercopyError;
use super::validate::{validate_user_read, validate_user_write};
use super::fault::did_fault;

pub fn copy_from_user(user_ptr: u64, dst: &mut [u8]) -> Result<(), UsercopyError> {
    crate::arch::x86_64::idt::without_interrupts(|| {
        validate_user_read(user_ptr, dst.len())?;
        unsafe { do_copy_from_user(user_ptr, dst) }
    })
}

pub fn copy_to_user(user_ptr: u64, src: &[u8]) -> Result<(), UsercopyError> {
    crate::arch::x86_64::idt::without_interrupts(|| {
        validate_user_write(user_ptr, src.len())?;
        unsafe { do_copy_to_user(user_ptr, src) }
    })
}

pub fn read_user_value<T: Copy>(user_ptr: u64) -> Result<T, UsercopyError> {
    let size = core::mem::size_of::<T>();
    let align = core::mem::align_of::<T>();
    if align > 1 && (user_ptr as usize) % align != 0 {
        return Err(UsercopyError::MisalignedAddress);
    }
    crate::arch::x86_64::idt::without_interrupts(|| {
        validate_user_read(user_ptr, size)?;
        let mut value: T = unsafe { core::mem::zeroed() };
        let dst = unsafe {
            core::slice::from_raw_parts_mut(&mut value as *mut T as *mut u8, size)
        };
        unsafe { do_copy_from_user(user_ptr, dst)?; }
        Ok(value)
    })
}

pub fn write_user_value<T: Copy>(user_ptr: u64, value: &T) -> Result<(), UsercopyError> {
    let size = core::mem::size_of::<T>();
    let align = core::mem::align_of::<T>();
    if align > 1 && (user_ptr as usize) % align != 0 {
        return Err(UsercopyError::MisalignedAddress);
    }
    crate::arch::x86_64::idt::without_interrupts(|| {
        validate_user_write(user_ptr, size)?;
        let src = unsafe {
            core::slice::from_raw_parts(value as *const T as *const u8, size)
        };
        unsafe { do_copy_to_user(user_ptr, src) }
    })
}

unsafe fn do_copy_from_user(src: u64, dst: &mut [u8]) -> Result<(), UsercopyError> {
    let src_ptr = src as *const u8;
    for (i, byte) in dst.iter_mut().enumerate() {
        *byte = core::ptr::read_volatile(src_ptr.add(i));
        if did_fault() {
            dst.fill(0);
            return Err(UsercopyError::PageFault);
        }
    }
    Ok(())
}

unsafe fn do_copy_to_user(dst: u64, src: &[u8]) -> Result<(), UsercopyError> {
    let dst_ptr = dst as *mut u8;
    for (i, byte) in src.iter().enumerate() {
        core::ptr::write_volatile(dst_ptr.add(i), *byte);
        if did_fault() {
            return Err(UsercopyError::PageFault);
        }
    }
    Ok(())
}

const MAX_USER_COPY_SIZE: usize = 16 * 1024 * 1024;

pub fn read_user_bytes(user_ptr: u64, len: usize) -> Result<alloc::vec::Vec<u8>, UsercopyError> {
    if len > MAX_USER_COPY_SIZE {
        return Err(UsercopyError::SizeTooLarge);
    }
    let mut buf = alloc::vec![0u8; len];
    copy_from_user(user_ptr, &mut buf)?;
    Ok(buf)
}

pub fn write_user_bytes(user_ptr: u64, data: &[u8]) -> Result<(), UsercopyError> {
    copy_to_user(user_ptr, data)
}

const MAX_STRING_LEN: usize = 4096;

pub fn read_user_string(user_ptr: u64, max_len: usize) -> Result<alloc::string::String, UsercopyError> {
    let safe_len = max_len.min(MAX_STRING_LEN);
    if safe_len == 0 { return Ok(alloc::string::String::new()); }
    let mut buf = alloc::vec![0u8; safe_len];
    let actual_len = crate::arch::x86_64::idt::without_interrupts(|| {
        validate_user_read(user_ptr, safe_len)?;
        let mut len = 0usize;
        for i in 0..safe_len {
            let addr = user_ptr.checked_add(i as u64).ok_or(UsercopyError::AddressOverflow)?;
            if addr > 0x0000_7FFF_FFFF_FFFF { return Err(UsercopyError::InvalidAddress); }
            let byte = unsafe { core::ptr::read_volatile(addr as *const u8) };
            if did_fault() {
                buf.fill(0);
                return Err(UsercopyError::PageFault);
            }
            if byte == 0 { break; }
            buf[i] = byte;
            len = i + 1;
        }
        Ok(len)
    })?;
    buf.truncate(actual_len);
    alloc::string::String::from_utf8(buf).map_err(|_| UsercopyError::InvalidUtf8)
}
