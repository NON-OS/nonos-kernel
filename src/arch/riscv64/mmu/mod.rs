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

pub mod attributes;
pub mod sv39;
pub mod sv48;
pub mod table;

pub use attributes::{PageAttributes, PteFlags};
pub use sv39::{Sv39, VA_BITS_39};
pub use sv48::{Sv48, VA_BITS_48};
pub use table::PageTable;

use core::arch::asm;

use super::boot::info::BootInfo;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

static mut KERNEL_L2: PageTable = PageTable::new();
static mut KERNEL_L1: [PageTable; 4] = [PageTable::new(), PageTable::new(), PageTable::new(), PageTable::new()];
static mut KERNEL_L0: [[PageTable; 512]; 4] = [[PageTable::new(); 512]; 4];

static mut ROOT_TABLE: PageTable = PageTable::new();

pub fn init_mmu(boot_info: &BootInfo) {
    setup_kernel_page_tables(boot_info);
    enable_mmu();
}

fn setup_kernel_page_tables(boot_info: &BootInfo) {
    unsafe {
        let root_ppn = ROOT_TABLE.ppn();
        let l2_ppn = KERNEL_L2.ppn();

        ROOT_TABLE.set_branch(511, l2_ppn);

        for (i, region) in boot_info.memory_regions.iter().enumerate() {
            if i >= 4 {
                break;
            }

            let l1_ppn = KERNEL_L1[i].ppn();
            KERNEL_L2.set_branch(i, l1_ppn);

            let mut phys = region.base;
            let end = region.base + region.size;
            let mut l1_idx = 0;

            while phys < end && l1_idx < 512 {
                let attrs = if region.executable {
                    PageAttributes::kernel_code()
                } else if region.writable {
                    PageAttributes::kernel_data()
                } else {
                    PageAttributes::kernel_rodata()
                };

                let ppn = phys >> 12;
                KERNEL_L1[i].set_leaf(l1_idx, ppn, &attrs);
                phys += sv39::MEGA_PAGE_SIZE as u64;
                l1_idx += 1;
            }
        }

        let satp_val = make_satp(MmuMode::Sv39, 0, root_ppn as usize);
        write_satp(satp_val);
    }
}

fn enable_mmu() {
    unsafe {
        asm!("sfence.vma", options(nostack));
    }
}

pub fn map_page(virt: u64, phys: u64, attrs: PageAttributes) {
    let va = virt as usize;
    let vpn2 = sv39::Sv39::vpn(va, 2);
    let vpn1 = sv39::Sv39::vpn(va, 1);
    let vpn0 = sv39::Sv39::vpn(va, 0);
    let ppn = phys >> 12;

    unsafe {
        if !ROOT_TABLE.is_valid(vpn2) {
            let l2_ppn = KERNEL_L2.ppn();
            ROOT_TABLE.set_branch(vpn2, l2_ppn);
        }

        if !KERNEL_L2.is_valid(vpn1) {
            if vpn1 < 4 {
                let l1_ppn = KERNEL_L1[vpn1].ppn();
                KERNEL_L2.set_branch(vpn1, l1_ppn);
            } else {
                return;
            }
        }

        if vpn1 < 4 && vpn0 < 512 {
            if !KERNEL_L1[vpn1].is_valid(vpn0) {
                let l0_ppn = KERNEL_L0[vpn1][vpn0].ppn();
                KERNEL_L1[vpn1].set_branch(vpn0, l0_ppn);
            }

            KERNEL_L0[vpn1][vpn0].set_leaf(vpn0, ppn, &attrs);
        }
    }

    flush_tlb_page(va);
}

pub fn unmap_page(virt: u64) {
    let _ = virt;
    flush_tlb_page(virt as usize);
}

pub fn flush_tlb_all() {
    unsafe {
        asm!("sfence.vma", options(nostack));
    }
}

pub fn flush_tlb_page(addr: usize) {
    unsafe {
        asm!("sfence.vma {}, zero", in(reg) addr, options(nostack));
    }
}

pub fn flush_tlb_asid(asid: usize) {
    unsafe {
        asm!("sfence.vma zero, {}", in(reg) asid, options(nostack));
    }
}

pub fn read_satp() -> usize {
    let satp: usize;
    unsafe {
        asm!("csrr {}, satp", out(reg) satp, options(nostack));
    }
    satp
}

pub fn write_satp(satp: usize) {
    unsafe {
        asm!(
            "csrw satp, {}",
            "sfence.vma",
            in(reg) satp,
            options(nostack)
        );
    }
}

pub fn current_asid() -> u16 {
    let satp = read_satp();
    ((satp >> 44) & 0xFFFF) as u16
}

pub fn current_ppn() -> usize {
    let satp = read_satp();
    satp & ((1 << 44) - 1)
}

pub fn mmu_mode() -> MmuMode {
    let satp = read_satp();
    let mode = satp >> 60;

    match mode {
        0 => MmuMode::Bare,
        8 => MmuMode::Sv39,
        9 => MmuMode::Sv48,
        10 => MmuMode::Sv57,
        _ => MmuMode::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmuMode {
    Bare,
    Sv39,
    Sv48,
    Sv57,
    Unknown,
}

impl MmuMode {
    pub fn satp_mode(&self) -> usize {
        match self {
            MmuMode::Bare => 0,
            MmuMode::Sv39 => 8,
            MmuMode::Sv48 => 9,
            MmuMode::Sv57 => 10,
            MmuMode::Unknown => 0,
        }
    }

    pub fn va_bits(&self) -> usize {
        match self {
            MmuMode::Bare => 64,
            MmuMode::Sv39 => 39,
            MmuMode::Sv48 => 48,
            MmuMode::Sv57 => 57,
            MmuMode::Unknown => 0,
        }
    }

    pub fn levels(&self) -> usize {
        match self {
            MmuMode::Bare => 0,
            MmuMode::Sv39 => 3,
            MmuMode::Sv48 => 4,
            MmuMode::Sv57 => 5,
            MmuMode::Unknown => 0,
        }
    }
}

pub fn make_satp(mode: MmuMode, asid: u16, ppn: usize) -> usize {
    ((mode.satp_mode() as usize) << 60) | ((asid as usize) << 44) | (ppn & ((1 << 44) - 1))
}
