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

use crate::memory::addr::VirtAddr;

use crate::syscall::dispatch::errno;
use crate::syscall::SyscallResult;

pub fn handle_mmio_map(phys_addr: u64, size: u64, flags: u64) -> SyscallResult {
    let Some(proc) = crate::process::current_process() else {
        return errno(1);
    };

    if !proc.capability_token().grants(crate::capabilities::Capability::Hardware) {
        return errno(1);
    }

    if size == 0 || size > 0x1000_0000 {
        return errno(22);
    }

    if phys_addr & 0xFFF != 0 {
        return errno(22);
    }

    let writable = (flags & 0x1) != 0;
    let uncacheable = (flags & 0x2) != 0;

    let phys = phys_addr;

    let cache_disabled = uncacheable;

    if phys < 0x100000 && !(phys >= 0xA0000 && phys < 0xC0000) {
        return errno(1);
    }

    if phys >= 0x100000 && phys < 0x1000000 {
        return errno(1);
    }

    if phys >= 0xFEE0_0000 && phys < 0xFEE1_0000 {
        return errno(1);
    }

    if phys >= 0xFEC0_0000 && phys < 0xFED0_0000 {
        return errno(1);
    }

    let page_size = 4096u64;
    let num_pages = (size + page_size - 1) / page_size;

    static NEXT_MMIO_VADDR: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0x0000_7F00_0000_0000);

    let virt_base =
        NEXT_MMIO_VADDR.fetch_add(num_pages * page_size, core::sync::atomic::Ordering::SeqCst);

    if virt_base > 0x0000_7FFF_FFFF_0000 {
        return errno(12);
    }

    for i in 0..num_pages {
        let page_phys = phys_addr + i * page_size;
        let page_virt = virt_base + i * page_size;

        // MMIO mappings: never executable (NX implicit by omitting
        // EXECUTE). `cache_disabled` correctly maps to NO_CACHE on the
        // page-table flag; the previous code path mis-routed this
        // through the `executable` parameter. User-accessible because
        // the syscall is exposed to userland (still gated by the
        // hardware capability check upstream).
        let mut perms = crate::memory::paging::types::PagePermissions::READ
            | crate::memory::paging::types::PagePermissions::USER;
        if writable {
            perms = perms | crate::memory::paging::types::PagePermissions::WRITE;
        }
        if cache_disabled {
            perms = perms | crate::memory::paging::types::PagePermissions::NO_CACHE;
        }
        if let Err(_) = crate::memory::paging::manager::map_page(
            VirtAddr::new(page_virt),
            crate::memory::addr::PhysAddr::new(page_phys),
            perms,
        ) {
            for j in 0..i {
                let unmap_virt = virt_base + j * page_size;
                let _ = crate::memory::paging::manager::unmap_page(VirtAddr::new(unmap_virt));
            }
            return errno(12);
        }
    }

    SyscallResult { value: virt_base as i64, capability_consumed: false, audit_required: true }
}
