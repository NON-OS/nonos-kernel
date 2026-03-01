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

use x86_64::VirtAddr;

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;

pub const PROT_NONE: u64 = 0;
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;

pub fn handle_mprotect(addr: u64, len: u64, prot: u64) -> SyscallResult {
    if addr & 0xFFF != 0 {
        return errno(22);
    }

    if len == 0 {
        return errno(22);
    }

    let proc = match crate::process::current_process() {
        Some(p) => p,
        None => return errno(1),
    };

    use crate::memory::paging::PagePermissions;
    let mut page_flags = PagePermissions::READ.union(PagePermissions::USER);

    if (prot & PROT_WRITE) != 0 {
        page_flags = page_flags.union(PagePermissions::WRITE);
    }

    if (prot & PROT_EXEC) != 0 {
        page_flags = page_flags.union(PagePermissions::EXECUTE);
    }

    if (prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0 {
        crate::log::log_warning!("mprotect: W^X violation denied for addr 0x{:x}", addr);
        return errno(1);
    }

    let num_pages = (len + 4095) / 4096;

    for i in 0..num_pages {
        let page_addr = VirtAddr::new(addr + i * 4096);

        {
            let mem = proc.memory.lock();
            let mut found = false;
            for vma in &mem.vmas {
                if page_addr >= vma.start && page_addr < vma.end {
                    found = true;
                    break;
                }
            }
            if !found {
                return errno(12);
            }
        }

        if let Err(_) = crate::memory::paging::update_page_protection(page_addr, page_flags) {
            return errno(14);
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
