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

use crate::capabilities::{Capability, CapabilityToken};
use crate::syscall::SyscallResult;

#[inline]
pub fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

#[inline]
pub fn require_capability(cap: Capability) -> Result<CapabilityToken, SyscallResult> {
    let Some(proc) = crate::process::current_process() else {
        return Err(errno(1));
    };
    let token = proc.capability_token();
    if !token.is_valid() {
        return Err(errno(1));
    }
    if !token.grants(cap) {
        return Err(errno(1));
    }
    Ok(token)
}

#[inline]
pub fn has_capability(cap: Capability) -> bool {
    crate::process::current_process()
        .map(|p| {
            let tok = p.capability_token();
            tok.is_valid() && tok.grants(cap)
        })
        .unwrap_or(false)
}

pub fn parse_string_from_user(addr: u64, max_len: usize) -> Result<String, &'static str> {
    if addr == 0 {
        return Err("Null pointer");
    }
    // SAFETY: addr is validated as non-null, bounds checked by max_len
    unsafe {
        let mut v = Vec::with_capacity(64);
        let mut i = 0usize;
        loop {
            if i >= max_len {
                return Err("String too long");
            }
            let b = core::ptr::read((addr as *const u8).add(i));
            if b == 0 {
                break;
            }
            v.push(b);
            i += 1;
        }
        let s = core::str::from_utf8(&v).map_err(|_| "Invalid UTF-8")?;
        Ok(String::from(s))
    }
}

pub fn parse_string_array_from_user(addr: u64, max_count: usize) -> Result<Vec<String>, &'static str> {
    if addr == 0 {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let mut i = 0usize;
    loop {
        if i >= max_count {
            break;
        }
        let ptr_addr = addr + (i * 8) as u64;
        // SAFETY: bounds checked by max_count
        let ptr = unsafe { core::ptr::read(ptr_addr as *const u64) };
        if ptr == 0 {
            break;
        }
        match parse_string_from_user(ptr, 4096) {
            Ok(s) => result.push(s),
            Err(_) => break,
        }
        i += 1;
    }
    Ok(result)
}
