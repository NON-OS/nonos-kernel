// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

/*
 * Pre-ExitBootServices allocations
 *
 * All memory must be allocated before ExitBootServices. After that call
 * UEFI memory services are gone. This is the last chance to grab pages.
 */

use core::mem::size_of;
use uefi::prelude::*;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::table::runtime::ResetType;

use super::timing::read_tsc;
use super::types::{flags, CryptoHandoff};
use crate::log::logger::{log_error, log_warn};

pub const MAX_MMAP_ENTRIES: usize = 512;

pub const MMAP_PAGES: usize =
    (MAX_MMAP_ENTRIES * size_of::<super::jump::MemoryMapEntry>() + 0xFFF) / 0x1000;

pub fn fatal_alloc_error(st: &SystemTable<Boot>, msg: &str) -> ! {
    log_error("handoff", msg);
    st.runtime_services()
        .reset(ResetType::COLD, Status::OUT_OF_RESOURCES, None);
}

pub fn detect_cpu_security_features() -> (bool, bool, bool) {
    let cpuid_result = core::arch::x86_64::__cpuid_count(7, 0);
    let smep = (cpuid_result.ebx & (1 << 7)) != 0;
    let smap = (cpuid_result.ebx & (1 << 20)) != 0;
    let umip = (cpuid_result.ecx & (1 << 2)) != 0;
    (smep, smap, umip)
}

pub fn estimate_tsc_frequency(bs: &uefi::table::boot::BootServices) -> u64 {
    let tsc_start = read_tsc();
    let _ = bs.stall(10_000);
    let tsc_end = read_tsc();
    if tsc_end > tsc_start {
        (tsc_end - tsc_start) * 100
    } else {
        0
    }
}

pub struct HandoffAllocations {
    pub boothandoff_addr: u64,
    pub stack_addr: u64,
    pub stack_top: usize,
    pub mmap_addr: u64,
    pub cmdline_addr: u64,
}

pub fn allocate_handoff_resources(
    st: &SystemTable<Boot>,
    cmdline: Option<&str>,
) -> HandoffAllocations {
    let bs = st.boot_services();

    let bh_addr = match bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1) {
        Ok(addr) => addr,
        Err(_) => fatal_alloc_error(st, "Failed to allocate BootHandoff page"),
    };

    let stack_pages: usize = 8;
    let stack_addr =
        match bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, stack_pages) {
            Ok(addr) => addr,
            Err(_) => fatal_alloc_error(st, "Failed to allocate kernel stack"),
        };
    let stack_top = (stack_addr as usize) + (stack_pages * 0x1000);

    let mmap_addr =
        match bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, MMAP_PAGES) {
            Ok(addr) => addr,
            Err(_) => fatal_alloc_error(st, "Failed to allocate memory map buffer"),
        };

    let cmdline_addr = allocate_cmdline(bs, cmdline);

    HandoffAllocations {
        boothandoff_addr: bh_addr,
        stack_addr,
        stack_top,
        mmap_addr,
        cmdline_addr,
    }
}

fn allocate_cmdline(bs: &uefi::table::boot::BootServices, cmdline: Option<&str>) -> u64 {
    if let Some(s) = cmdline {
        let cmd_bytes = s.as_bytes();
        let cmd_len = cmd_bytes.len() + 1;
        let cmd_pages = (cmd_len + 0xFFF) / 0x1000;
        if let Ok(cmd_addr) =
            bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, cmd_pages)
        {
            unsafe {
                let ptr = cmd_addr as *mut u8;
                core::ptr::copy_nonoverlapping(cmd_bytes.as_ptr(), ptr, cmd_bytes.len());
                core::ptr::write_volatile(ptr.add(cmd_bytes.len()), 0u8);
            }
            return cmd_addr;
        }
        log_warn("handoff", "cmdline allocation failed; proceeding without");
    }
    0
}

pub fn build_handoff_flags(
    fb_available: bool,
    acpi_available: bool,
    crypto: &CryptoHandoff,
    tpm_measured: bool,
    smep: bool,
    smap: bool,
    umip: bool,
) -> u64 {
    let mut f: u64 = 0;
    if fb_available { f |= flags::FB_AVAILABLE; }
    if acpi_available { f |= flags::ACPI_AVAILABLE; }
    if crypto.secure_boot { f |= flags::SECURE_BOOT; }
    if crypto.zk_attested { f |= flags::ZK_ATTESTED; }
    if tpm_measured { f |= flags::TPM_MEASURED; }
    if smep { f |= flags::SMEP; }
    if smap { f |= flags::SMAP; }
    if umip { f |= flags::UMIP; }
    f |= flags::WX;
    f |= flags::NXE;
    f |= flags::IDMAP_PRESERVED;
    f
}
