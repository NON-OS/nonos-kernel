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

use super::storage::get_tls_entry;
use super::types::{UserDesc, GDT_ENTRY_TLS_ENTRIES, GDT_ENTRY_TLS_MIN};
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value};

pub fn handle_get_thread_area(u_info: u64) -> SyscallResult {
    if u_info == 0 {
        return errno(14);
    }
    let desc: UserDesc = match read_user_value(u_info) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let entry_number = desc.entry_number as usize;
    if entry_number < GDT_ENTRY_TLS_MIN || entry_number >= GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES
    {
        return errno(22);
    }
    let tid = crate::process::current_tid() as u64;
    let tls_desc = match get_tls_entry(tid, entry_number) {
        Ok(e) => e,
        Err(e) => return errno(e),
    };
    let out_desc = UserDesc {
        entry_number: desc.entry_number,
        base_addr: tls_desc.base as u32,
        limit: tls_desc.limit,
        flags: tls_desc.flags,
    };
    if write_user_value(u_info, &out_desc).is_err() {
        return errno(14);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn get_thread_area_kernel(tid: u64, entry_number: usize) -> Result<UserDesc, i32> {
    if entry_number < GDT_ENTRY_TLS_MIN || entry_number >= GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES
    {
        return Err(22);
    }
    let tls_desc = get_tls_entry(tid, entry_number)?;
    Ok(UserDesc {
        entry_number: entry_number as u32,
        base_addr: tls_desc.base as u32,
        limit: tls_desc.limit,
        flags: tls_desc.flags,
    })
}

pub fn get_tls_base_kernel(tid: u64, entry_number: usize) -> Result<u64, i32> {
    let tls_desc = get_tls_entry(tid, entry_number)?;
    Ok(tls_desc.base)
}

pub fn is_tls_slot_valid(tid: u64, entry_number: usize) -> bool {
    get_tls_entry(tid, entry_number).map(|e| e.valid).unwrap_or(false)
}

pub fn get_all_tls_descriptors(tid: u64) -> [Option<UserDesc>; GDT_ENTRY_TLS_ENTRIES] {
    let mut result = [None; GDT_ENTRY_TLS_ENTRIES];
    for i in 0..GDT_ENTRY_TLS_ENTRIES {
        let entry_num = GDT_ENTRY_TLS_MIN + i;
        if let Ok(tls_desc) = get_tls_entry(tid, entry_num) {
            if tls_desc.valid {
                result[i] = Some(UserDesc {
                    entry_number: entry_num as u32,
                    base_addr: tls_desc.base as u32,
                    limit: tls_desc.limit,
                    flags: tls_desc.flags,
                });
            }
        }
    }
    result
}

pub fn count_active_tls_slots(tid: u64) -> usize {
    (0..GDT_ENTRY_TLS_ENTRIES).filter(|&i| is_tls_slot_valid(tid, GDT_ENTRY_TLS_MIN + i)).count()
}
