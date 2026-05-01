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

// Architecture-neutral kernel bring-up handoff. Per-arch boot code
// constructs a `KernelHandoff` and passes it to the kernel-core
// `microkernel_init`. The kernel core reads the cross-arch fields
// directly. Operations that are inherently arch-specific (walking an
// EFI memory map, framebuffer init against a UEFI framebuffer, firmware
// table reads) match on the `arch` field to recover the per-arch
// handoff type.

mod arch;
mod console;
mod cpu;
mod framebuffer;
mod measurement;
mod memory;
mod timing;
mod x86_64;

pub use arch::ArchSpecificHandoff;
pub use console::EarlyConsole;
pub use cpu::CpuTopology;
pub use framebuffer::Framebuffer;
pub use measurement::Measurement;
pub use memory::MemoryHandoff;
pub use timing::TimingHandoff;

#[derive(Debug, Clone, Copy)]
pub struct KernelHandoff<'a> {
    pub memory: MemoryHandoff,
    pub cpus: CpuTopology,
    pub console: EarlyConsole,
    pub framebuffer: Option<Framebuffer>,
    pub timing: TimingHandoff,
    pub measurement: Measurement,
    pub arch: ArchSpecificHandoff<'a>,
}
