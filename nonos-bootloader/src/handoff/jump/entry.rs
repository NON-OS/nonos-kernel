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

// Architecture-neutral seam for the bootloader -> kernel transfer.
// The real instruction sequence lives in
// `arch::x86_64::asm::handoff_jump.S`. This file 16-byte-aligns
// the stack pointer and delegates to the arch wrapper.

use crate::arch::x86_64::handoff::handoff_jump;

const STACK_ALIGNMENT_MASK: u64 = !0xF;

#[inline(never)]
pub unsafe fn jump_to_kernel(entry_addr: u64, stack_top: u64, boothandoff_ptr: u64) -> ! {
    let stack_aligned = stack_top & STACK_ALIGNMENT_MASK;
    unsafe { handoff_jump(entry_addr, stack_aligned, boothandoff_ptr) }
}
