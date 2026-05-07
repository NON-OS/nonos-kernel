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

// Rust wrapper for the architectural CR3 install. The real
// instruction lives at the asm boundary in
// `arch/x86_64/asm/load_cr3.S` (symbol `nonos_arch_load_cr3`);
// this file is the pure-Rust seam everything else calls.
//
// Caller invariants (see the asm file for the architectural
// detail): `pml4_phys` is a 4-KiB-aligned PML4 frame whose
// entries cover the bootloader's current execution range,
// interrupts are masked, and ExitBootServices has been called.

unsafe extern "C" {
    fn nonos_arch_load_cr3(pml4_phys: u64);
}

#[inline(always)]
pub unsafe fn load_cr3(pml4_phys: u64) {
    unsafe { nonos_arch_load_cr3(pml4_phys) }
}
