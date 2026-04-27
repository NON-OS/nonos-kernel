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

use super::gdt::install_tls_descriptor;
use super::storage::{find_free_tls_slot, set_tls_entry};
use super::types::{TlsDescriptor, UserDesc, GDT_ENTRY_TLS_ENTRIES, GDT_ENTRY_TLS_MIN};
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value};

pub fn handle_set_thread_area(u_info: u64) -> SyscallResult {
    if u_info == 0 {
        return errno(14);
    }
    let mut desc: UserDesc = match read_user_value(u_info) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let tid = crate::process::current_tid() as u64;
    let entry_number = if desc.entry_number == u32::MAX {
        match find_free_tls_slot(tid) {
            Some(idx) => idx as u32,
            None => return errno(28),
        }
    } else {
        if (desc.entry_number as usize) < GDT_ENTRY_TLS_MIN
            || (desc.entry_number as usize) >= GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES
        {
            return errno(22);
        }
        desc.entry_number
    };
    let tls_desc = TlsDescriptor {
        base: desc.base_addr as u64,
        limit: desc.limit,
        flags: desc.flags,
        selector: ((entry_number as u16) << 3) | 3,
        valid: !desc.seg_not_present(),
    };
    if let Err(e) = set_tls_entry(tid, entry_number as usize, tls_desc) {
        return errno(e);
    }
    install_tls_descriptor(entry_number as usize, &desc);
    desc.entry_number = entry_number;
    if write_user_value(u_info, &desc).is_err() {
        return errno(14);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn set_thread_area_kernel(
    tid: u64,
    entry_number: usize,
    base: u64,
    limit: u32,
    flags: u32,
) -> Result<(), i32> {
    if entry_number < GDT_ENTRY_TLS_MIN || entry_number >= GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES
    {
        return Err(22);
    }
    let tls_desc = TlsDescriptor {
        base,
        limit,
        flags,
        selector: ((entry_number as u16) << 3) | 3,
        valid: flags & (1 << 5) == 0,
    };
    set_tls_entry(tid, entry_number, tls_desc)?;
    let desc = UserDesc { entry_number: entry_number as u32, base_addr: base as u32, limit, flags };
    install_tls_descriptor(entry_number, &desc);
    Ok(())
}

pub fn clear_thread_area(tid: u64, entry_number: usize) -> Result<(), i32> {
    set_tls_entry(tid, entry_number, TlsDescriptor::default())?;
    let empty_desc = UserDesc { entry_number: entry_number as u32, ..Default::default() };
    install_tls_descriptor(entry_number, &empty_desc);
    Ok(())
}

pub fn allocate_tls_for_thread(tid: u64, base: u64) -> Result<usize, i32> {
    let entry = find_free_tls_slot(tid).ok_or(28)?;
    set_thread_area_kernel(tid, entry, base, 0xfffff, 0x51)?;
    Ok(entry)
}
