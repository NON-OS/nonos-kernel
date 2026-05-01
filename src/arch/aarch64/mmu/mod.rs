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
pub mod granule;
pub mod table;
pub mod translation;

pub use attributes::{PageAttributes, MemoryType};
pub use granule::{Granule, GRANULE_4K, GRANULE_16K, GRANULE_64K};
pub use table::PageTable;
pub use translation::{virt_to_phys, phys_to_virt};

use core::arch::asm;

use super::boot::info::BootInfo;

pub fn init_mmu(boot_info: &BootInfo) {
    configure_mair();
    configure_tcr();
    setup_kernel_page_tables(boot_info);
    enable_mmu();
}

fn configure_mair() {
    let mair: u64 = (0x00 << 0)
        | (0x04 << 8)
        | (0x0C << 16)
        | (0x44 << 24)
        | (0xFF << 32)
        | (0xBB << 40);

    unsafe {
        asm!(
            "msr mair_el1, {0}",
            "isb",
            in(reg) mair,
        );
    }
}

fn configure_tcr() {
    let tcr: u64 = (16 << 0)
        | (0b00 << 8)
        | (0b11 << 10)
        | (0b01 << 12)
        | (0b1 << 14)
        | (16 << 16)
        | (0b00 << 24)
        | (0b11 << 26)
        | (0b01 << 28)
        | (0b1 << 30)
        | (0b10 << 32)
        | (0b1 << 36)
        | (0b1 << 37)
        | (0b1 << 38)
        | (0b1 << 39);

    unsafe {
        asm!(
            "msr tcr_el1, {0}",
            "isb",
            in(reg) tcr,
        );
    }
}

static mut KERNEL_L0: PageTable = PageTable::new();
static mut KERNEL_L1: PageTable = PageTable::new();
static mut KERNEL_L2: [PageTable; 4] = [PageTable::new(), PageTable::new(), PageTable::new(), PageTable::new()];
static mut KERNEL_L3: [[PageTable; 512]; 4] = [[PageTable::new(); 512]; 4];

fn setup_kernel_page_tables(boot_info: &BootInfo) {
    unsafe {
        let l0_addr = &KERNEL_L0 as *const _ as u64;
        let l1_addr = &KERNEL_L1 as *const _ as u64;

        KERNEL_L0.set_table(0, l1_addr);

        for (i, region) in boot_info.memory_regions.iter().enumerate() {
            if i >= 4 {
                break;
            }

            let l2_addr = &KERNEL_L2[i] as *const _ as u64;
            KERNEL_L1.set_table(i, l2_addr);

            let mut phys = region.base;
            let end = region.base + region.size;
            let mut l2_idx = 0;

            while phys < end && l2_idx < 512 {
                let attrs = if region.executable {
                    PageAttributes::kernel_code()
                } else if region.writable {
                    PageAttributes::kernel_data()
                } else {
                    PageAttributes::kernel_rodata()
                };

                KERNEL_L2[i].set_block(l2_idx, phys, &attrs);
                phys += 2 * 1024 * 1024;
                l2_idx += 1;
            }
        }

        let device_attrs = PageAttributes::device();
        KERNEL_L1.set_table(510, &KERNEL_L2[3] as *const _ as u64);

        let uart_phys = boot_info.uart_base & !0x1FFFFF;
        KERNEL_L2[3].set_block(0, uart_phys, &device_attrs);

        let gic_phys = boot_info.gic_dist_base & !0x1FFFFF;
        KERNEL_L2[3].set_block(1, gic_phys, &device_attrs);

        set_ttbr1(l0_addr);
        set_ttbr0(l0_addr, 0);
    }
}

fn enable_mmu() {
    unsafe {
        asm!(
            "dsb sy",
            "isb",
        );

        let mut sctlr: u64;
        asm!("mrs {}, sctlr_el1", out(reg) sctlr);

        sctlr |= 1 << 0;
        sctlr |= 1 << 2;
        sctlr |= 1 << 12;

        asm!(
            "msr sctlr_el1, {}",
            "isb",
            in(reg) sctlr,
        );
    }
}

pub fn map_page(virt: u64, phys: u64, attrs: PageAttributes) {
    let l0_idx = ((virt >> 39) & 0x1FF) as usize;
    let l1_idx = ((virt >> 30) & 0x1FF) as usize;
    let l2_idx = ((virt >> 21) & 0x1FF) as usize;
    let l3_idx = ((virt >> 12) & 0x1FF) as usize;

    unsafe {
        if l0_idx >= 4 || l1_idx >= 512 {
            return;
        }

        let l0 = &mut KERNEL_L0;
        if !l0.is_valid(l0_idx) {
            let l1_addr = &KERNEL_L1 as *const _ as u64;
            l0.set_table(l0_idx, l1_addr);
        }

        let l1 = &mut KERNEL_L1;
        if !l1.is_valid(l1_idx) {
            if l1_idx < 4 {
                let l2_addr = &KERNEL_L2[l1_idx] as *const _ as u64;
                l1.set_table(l1_idx, l2_addr);
            } else {
                return;
            }
        }

        if l1_idx < 4 {
            let l2 = &mut KERNEL_L2[l1_idx];
            if !l2.is_valid(l2_idx) && l2_idx < 512 && l1_idx < 4 {
                let l3_addr = &KERNEL_L3[l1_idx][l2_idx] as *const _ as u64;
                l2.set_table(l2_idx, l3_addr);
            }

            if l2_idx < 512 && l1_idx < 4 {
                let l3 = &mut KERNEL_L3[l1_idx][l2_idx];
                l3.set_page(l3_idx, phys, &attrs);
            }
        }
    }

    flush_tlb_page(virt);
}

pub fn unmap_page(virt: u64) {
    let _ = virt;
    flush_tlb_page(virt);
}

pub fn flush_tlb_all() {
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
        );
    }
}

pub fn flush_tlb_page(addr: u64) {
    let page = addr >> 12;
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vaae1is, {0}",
            "dsb ish",
            "isb",
            in(reg) page,
        );
    }
}

pub fn flush_tlb_asid(asid: u16) {
    let asid_val = (asid as u64) << 48;
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi aside1is, {0}",
            "dsb ish",
            "isb",
            in(reg) asid_val,
        );
    }
}

pub fn set_ttbr0(addr: u64, asid: u16) {
    let ttbr = addr | ((asid as u64) << 48);
    unsafe {
        asm!(
            "msr ttbr0_el1, {0}",
            "isb",
            in(reg) ttbr,
        );
    }
}

pub fn set_ttbr1(addr: u64) {
    unsafe {
        asm!(
            "msr ttbr1_el1, {0}",
            "isb",
            in(reg) addr,
        );
    }
}

pub fn read_ttbr0() -> u64 {
    let ttbr: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr);
    }
    ttbr
}

pub fn read_ttbr1() -> u64 {
    let ttbr: u64;
    unsafe {
        asm!("mrs {}, ttbr1_el1", out(reg) ttbr);
    }
    ttbr
}
