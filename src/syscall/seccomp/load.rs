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

use super::filter::SeccompFilter;
use super::types::{SockFilter, SockFprog};
use crate::usercopy::read_user_value;
use alloc::vec::Vec;

pub fn load_filter_from_user(prog_ptr: u64, flags: u32) -> Result<SeccompFilter, i32> {
    let fprog: SockFprog = read_user_value(prog_ptr).map_err(|_| 14)?;
    if fprog.len == 0 || fprog.len > 4096 {
        return Err(22);
    }
    if fprog.filter == 0 {
        return Err(14);
    }
    let mut instructions = Vec::with_capacity(fprog.len as usize);
    for i in 0..fprog.len as usize {
        let filter_ptr = fprog.filter + (i * core::mem::size_of::<SockFilter>()) as u64;
        let filter: SockFilter = read_user_value(filter_ptr).map_err(|_| 14)?;
        instructions.push(filter);
    }
    let filter = SeccompFilter::new(instructions, flags);
    filter.validate()?;
    Ok(filter)
}

pub fn create_allow_all_filter() -> SeccompFilter {
    let instructions = alloc::vec![SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x7fff0000 }];
    SeccompFilter::new(instructions, 0)
}

pub fn create_deny_all_filter() -> SeccompFilter {
    let instructions = alloc::vec![SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x00000000 }];
    SeccompFilter::new(instructions, 0)
}

pub fn create_syscall_whitelist(syscalls: &[i32]) -> SeccompFilter {
    let mut instructions = Vec::new();
    instructions.push(SockFilter { code: 0x20, jt: 0, jf: 0, k: 0 });
    for (i, &syscall) in syscalls.iter().enumerate() {
        let jump_count = (syscalls.len() - i - 1) as u8;
        instructions.push(SockFilter { code: 0x15, jt: jump_count + 1, jf: 0, k: syscall as u32 });
    }
    instructions.push(SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x00000000 });
    instructions.push(SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x7fff0000 });
    SeccompFilter::new(instructions, 0)
}
