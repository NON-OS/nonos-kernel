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

use core::sync::atomic::Ordering;

use crate::arch::cpu::idle_cpu;
use crate::arch::riscv64::cpu;
use crate::arch::riscv64::interrupts::install_stvec;
use crate::arch::riscv64::plic::init_plic_hart;
use crate::arch::riscv64::timer::init_timer_hart;
use crate::arch::riscv64::uart;
use crate::process::scheduler::smp::api::init_ap_scheduler;

use super::state::HARTS_ONLINE;

// Called from `_riscv64_secondary_start` with a0=hartid, a1=stack_top.
// tp is already set to hartid; sp points at this hart's kernel stack.
// IRQs stay masked through all per-CPU init; idle_cpu unmasks atomically
// with wfi inside the idle loop.
#[no_mangle]
pub extern "C" fn riscv64_ap_entry(_hart_id: u64, _stack_top: u64) -> ! {
    install_stvec();
    cpu::init_cpu();
    init_plic_hart();
    init_timer_hart();

    HARTS_ONLINE.fetch_add(1, Ordering::AcqRel);

    let hart = cpu::id::hart_id();
    uart::puts(b"[BOOT] Hart ");
    uart::putc((b'0' + hart as u8) as char);
    uart::puts(b" online\n");

    init_ap_scheduler(hart);

    loop {
        idle_cpu();
    }
}
