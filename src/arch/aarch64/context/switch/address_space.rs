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

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::arch::ArchOps;
use crate::memory::addr::PhysAddr;
use crate::process::core::ProcessControlBlock;

// PCB::cr3 names the x86 page-table root historically; in the
// arch-neutral form it carries the active address-space root for the
// running arch (TTBR0 phys on aarch64). Zero means "share the kernel
// address space" — used by kernel-thread PCBs and by user PCBs that
// have not yet had a private address space allocated.
pub(super) fn swap_address_space(pcb: &Arc<ProcessControlBlock>) -> Result<(), ()> {
    let root = pcb.cr3.load(Ordering::Relaxed);
    if root == 0 {
        return Ok(());
    }
    // SAFETY: caller has masked IRQs and the root was published by the
    // address-space allocator at PCB creation; the asm-side TLB invalidate
    // is the ArchOps impl's responsibility.
    unsafe {
        <crate::arch::Arch as ArchOps>::switch_address_space(PhysAddr::new(root));
    }
    Ok(())
}
