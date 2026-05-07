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

use crate::memory::layout::{DIRECTMAP_BASE, DIRECTMAP_SIZE};

use super::read_cr3::read_cr3;
use super::write_cr3::write_cr3;

const PML4_INDEX_LOW_IDENTITY: usize = 0;
const PML4_PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// Drop the bootloader's low-4 GiB identity map. We only call this
// once we know:
//   - kernel text is in the upper half (PML4[511]), so RIP stays
//     valid after the flush;
//   - the boot stack is reached through the directmap, so RSP
//     stays valid too.
// After this returns, no part of the kernel address space points
// into PML4[0]. User CR3s, which clone [256..512], can't inherit
// a low-half mapping by accident.
pub fn clear_low_half() -> Result<(), &'static str> {
    let cr3 = read_cr3();
    let pml4_phys = cr3 & PML4_PHYS_MASK;
    if pml4_phys >= DIRECTMAP_SIZE {
        return Err("clear_low_half: PML4 phys outside directmap window");
    }
    let pml4_virt = DIRECTMAP_BASE + pml4_phys;
    unsafe {
        let pml4 = pml4_virt as *mut u64;
        pml4.add(PML4_INDEX_LOW_IDENTITY).write(0);
        write_cr3(cr3);
    }
    Ok(())
}
