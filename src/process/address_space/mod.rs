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

mod types;
mod ops;
mod tlb;
mod pcid;

pub use types::*;
pub use ops::*;
pub use tlb::*;
pub use pcid::*;

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::PhysAddr;

static CURRENT_ADDRESS_SPACE: AtomicU64 = AtomicU64::new(0);
#[inline(always)]
pub fn switch_address_space(space: &AddressSpace) {
    let new_cr3 = space.cr3_value();

    let current_cr3: u64;
    // # SAFETY: Reading CR3 is always safe if it just returns the current page table
    // base address. The nomem option is correct because this does not access memory
    // through a pointer. The nostack option is correct because no stack space is used.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) current_cr3, options(nomem, nostack));
    }

    if current_cr3 != new_cr3 {
        // # SAFETY: Writing CR3 is safe when {
        // # new_cr3 contains a valid page table physical address (guaranteed by
        //    AddressSpace::cr3_value() which only returns properly initialized PML4)
        // # The page table hierarchy is correctly set up (ensured by AddressSpace
        //    construction which validates and initializes page tables)
        // # We are in ring 0 (kernel mode) always true in kernel code
        // # The nostack option is correct because no stack space is used.
        // }
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) new_cr3, options(nostack));
        }

        CURRENT_ADDRESS_SPACE.store(space.pml4_phys.as_u64(), Ordering::SeqCst);
    }
}

pub fn current_address_space_phys() -> PhysAddr {
    let cr3: u64;
    // ## SAFETY: Reading CR3 is always safe if it just returns the current page table
    // base address. The nomem option is correct because this does not access memory
    // through a pointer. The nostack option is correct because no stack space is used.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    }
    PhysAddr::new(cr3 & pte_flags::ADDR_MASK)
}

pub fn init() -> Result<(), &'static str> {
    crate::log::info!("[ADDR_SPACE] Initializing address space management...");
    enable_pcid();
    crate::log::info!("[ADDR_SPACE] Address space management initialized");
    Ok(())
}
