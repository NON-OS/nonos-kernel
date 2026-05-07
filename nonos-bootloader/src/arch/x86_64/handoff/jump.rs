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

// Rust wrapper for the bootloader -> kernel transfer. The real
// instruction sequence lives in `arch/x86_64/asm/handoff_jump.S`
// (symbol `nonos_arch_handoff_jump`); this is the pure-Rust seam
// everything else calls.
//
// On return the kernel's `_start` runs at `entry` with `rsp =
// stack`, `rdi = handoff` (System V argument 0), and all other
// GPRs zeroed.

unsafe extern "C" {
    fn nonos_arch_handoff_jump(entry: u64, stack: u64, handoff: u64) -> !;
}

#[inline(always)]
pub unsafe fn handoff_jump(entry: u64, stack: u64, handoff: u64) -> ! {
    unsafe { nonos_arch_handoff_jump(entry, stack, handoff) }
}
