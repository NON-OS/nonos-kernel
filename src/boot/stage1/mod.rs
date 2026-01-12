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

mod bss;
mod cpu;
mod interrupt;
mod memory;
mod serial;
mod subsystem;
mod types;
#[cfg(test)]
mod tests;

pub use bss::clear_bss;
pub use cpu::{init_cpu_structures, read_apic_id};
pub use interrupt::init_interrupts;
pub use memory::init_memory;
pub use serial::{init_serial, serial_print};
pub use subsystem::{init_core_subsystems, init_module_system, start_scheduler};
pub use types::{BootInfo, FramebufferInfo, MemoryDescriptor, EFI_CONVENTIONAL_MEMORY};
