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

pub mod dtb_adapter;
pub mod entry;
pub mod info;
pub mod multicore;
pub mod stack;

pub use entry::kernel_entry;
pub use info::{BootInfo, MemoryRegion};
pub use multicore::start_secondary_cpus;
pub use stack::setup_stack;

use super::{cpu, exceptions, gic, mmu, security, timer, uart};

pub fn init(boot_info: &BootInfo) {
    uart::init_uart(boot_info.uart_base);

    uart::puts(b"[BOOT] NONOS ARM64 starting...\n");

    cpu::init_cpu();

    uart::puts(b"[BOOT] CPU initialized\n");

    // VBAR_EL1 before anything that can fault.
    exceptions::install_vbar_el1();

    uart::puts(b"[BOOT] Exception vectors installed\n");

    // PAC / BTI / MTE / SSBS — each self-gates on cpu feature bits.
    security::init_all();

    uart::puts(b"[BOOT] Security mitigations applied\n");

    mmu::init_mmu(boot_info);

    uart::puts(b"[BOOT] MMU configured\n");

    if boot_info.gic_unsupported {
        uart::puts(b"[FATAL] GIC version not supported (only GICv3 implemented)\n");
        cpu::halt();
    }

    gic::init_gic(boot_info.gic_dist_base, boot_info.gic_redist_base);

    uart::puts(b"[BOOT] GIC initialized\n");

    timer::init_timer();

    uart::puts(b"[BOOT] Timer initialized\n");

    // Publish the DTB-resolved timer intid so APs and BSP share one
    // value. install_on_cpu fail-closes on 0 (no DTB / no /timer node).
    timer::configure_preemption_intid(boot_info.timer_phys_intid);

    if timer::install_on_cpu().is_err() {
        uart::puts(b"[FATAL] preemption timer install failed\n");
        cpu::halt();
    }

    uart::puts(b"[BOOT] Preemption timer armed\n");

    if boot_info.cpu_count > 1 {
        multicore::start_secondary_cpus(boot_info);
    }

    uart::puts(b"[BOOT] ARM64 initialization complete\n");
}
