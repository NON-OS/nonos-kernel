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

// Arch-neutral PCB->user dispatcher. The scheduler calls this; each
// arch's `context::switch_*_pcb` does the real work (kernel stack
// install, address space, FPU, eret/sret/iretq). Helpers do not return
// on the user-entry / resume paths; the kernel-thread resume path on
// x86 returns normally.

pub fn switch_to_user_pcb(pid: u32) {
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::context::switch_to_user_pcb_x86_64(pid);
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::context::switch_to_user_pcb_aarch64(pid);
    #[cfg(target_arch = "riscv64")]
    crate::arch::riscv64::context::switch_to_user_pcb_riscv64(pid);
}
