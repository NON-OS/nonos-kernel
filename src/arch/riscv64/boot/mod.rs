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

pub mod entry;
pub mod info;
pub mod multicore;
pub mod stack;

pub use entry::kernel_entry;
pub use info::{BootInfo, MemoryRegion};
pub use multicore::{start_secondary_harts, secondary_entry};
pub use stack::setup_stack;

use super::{cpu, mmu, plic, timer, uart};

pub fn init(boot_info: &BootInfo) {
    uart::init_uart(boot_info.uart_base);

    uart::puts(b"[BOOT] NONOS RISC-V starting...\n");

    cpu::init_cpu();

    uart::puts(b"[BOOT] CPU initialized\n");

    mmu::init_mmu(boot_info);

    uart::puts(b"[BOOT] MMU configured\n");

    plic::init_plic(boot_info.plic_base);

    uart::puts(b"[BOOT] PLIC initialized\n");

    timer::init_timer();

    uart::puts(b"[BOOT] Timer initialized\n");

    if boot_info.hart_count > 1 {
        multicore::start_secondary_harts(boot_info);
    }

    uart::puts(b"[BOOT] RISC-V initialization complete\n");
}
