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
use crate::usercopy::{copy_from_user, read_user_value, UsercopyError};

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
    if !token.is_valid() || !token.grants(cap) {
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

fn usercopy_to_syscall_err(e: UsercopyError) -> &'static str {
    match e {
        UsercopyError::NullPointer => "Null pointer",
        UsercopyError::InvalidAddress => "Invalid address",
        UsercopyError::PageNotMapped => "Page not mapped",
        UsercopyError::PageNotUser => "Page not user accessible",
        UsercopyError::PageFault => "Page fault",
        UsercopyError::SizeTooLarge => "Size too large",
        _ => "Memory access error",
    }
}

/// # Safety
/// Safely parses a null-terminated string from user space with page validation.
pub fn parse_string_from_user(addr: u64, max_len: usize) -> Result<String, &'static str> {
    if addr == 0 {
        return Err("Null pointer");
    }

    let mut buf = Vec::with_capacity(64);
    let mut i = 0usize;

    while i < max_len {
        let mut byte = [0u8; 1];
        copy_from_user(addr + i as u64, &mut byte).map_err(usercopy_to_syscall_err)?;

        if byte[0] == 0 {
            break;
        }
        buf.push(byte[0]);
        i += 1;
    }

    if i >= max_len {
        return Err("String too long");
    }

    core::str::from_utf8(&buf).map(String::from).map_err(|_| "Invalid UTF-8")
}

/// # Safety
/// Safely parses a null-terminated array of string pointers from user space.
pub fn parse_string_array_from_user(
    addr: u64,
    max_count: usize,
) -> Result<Vec<String>, &'static str> {
    if addr == 0 {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();

    for i in 0..max_count {
        let ptr_addr = addr + (i * 8) as u64;
        let ptr: u64 = read_user_value(ptr_addr).map_err(usercopy_to_syscall_err)?;

        if ptr == 0 {
            break;
        }

        match parse_string_from_user(ptr, 4096) {
            Ok(s) => result.push(s),
            Err(_) => break,
        }
    }

    Ok(result)
}
