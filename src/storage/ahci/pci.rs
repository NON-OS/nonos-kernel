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

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{VirtAddr, PhysAddr};

use crate::memory::nonos_paging::{map_page, PagePermissions};

pub fn pci_config_read(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    // SAFETY: PCI configuration space access via I/O ports
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xCF8u16, in("eax") address);
        let value: u32;
        core::arch::asm!("in eax, dx", out("eax") value, in("dx") 0xCFCu16);
        value
    }
}

pub fn map_mmio_region(phys_addr: u64, size: usize) -> Option<u64> {
    let phys = PhysAddr::new(phys_addr);
    let pages_needed = (size + 4095) / 4096;

    static NEXT_MMIO_ADDR: AtomicU64 = AtomicU64::new(0xFFFF_8800_0000_0000);

    let virt_base = NEXT_MMIO_ADDR.fetch_add((pages_needed * 4096) as u64, Ordering::SeqCst);
    let virt = VirtAddr::new(virt_base);

    for i in 0..pages_needed {
        let page_phys = phys + (i * 4096) as u64;
        let page_virt = virt + (i * 4096) as u64;

        let permissions = PagePermissions::READ | PagePermissions::WRITE |
                         PagePermissions::NO_CACHE | PagePermissions::DEVICE;
        if map_page(page_virt, page_phys, permissions).is_err() {
            return None;
        }
    }

    Some(virt_base)
}
