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
use super::pcid::pcid_enabled;

#[inline(always)]
pub fn invlpg(virt: VirtAddr) {
    // # SAFETY: The INVLPG instruction is safe to execute:
    // 1. It only invalidates TLB entries - it does not access the memory at the address
    // 2. We are in ring 0 (kernel mode) always true in kernel code
    // 3. The nostack option is correct as no stack space is used
    // 4. preserves_flags is correct as INVLPG does not modify RFLAGS
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) virt.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}

#[inline(always)]
pub fn flush_tlb() {
    // # SAFETY: Reading CR3 and writing the same value back is safe:
    // 1. This is the canonical way to flush the TLB on x86_64
    // 2. Writing the same CR3 value does not change the page table base
    // 3. We are in ring 0 (kernel mode) always true in kernel code
    // # The nomem/nostack options are correct as these are pure register operations.
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack));
    }
}

#[inline(always)]
pub fn flush_tlb_pcid(pcid: u16) {
    if pcid_enabled() {
        let descriptor: [u64; 2] = [pcid as u64, 0];
        // # SAFETY: INVPCID instruction is safe to execute:
        // 1. pcid_enabled() verified that PCID support is available
        // 2. The descriptor is a valid stack-allocated array with proper layout
        // 3. Type 1 (single-context invalidation) only invalidates TLB entries
        // 4. We are in ring 0 (kernel mode) always true in kernel code
        // # The nostack option is correct as no additional stack space is used.
        unsafe {
            core::arch::asm!(
                "invpcid {}, [{}]",
                in(reg) 1u64, // Type 1: Single-context invalidation
                in(reg) descriptor.as_ptr(),
                options(nostack)
            );
        }
    } else {
        flush_tlb();
    }
}
