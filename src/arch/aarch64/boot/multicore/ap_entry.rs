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

use crate::arch::aarch64::cpu;
use crate::arch::aarch64::exceptions::install_vbar_el1;
use crate::arch::aarch64::gic::init_gic_cpu;
use crate::arch::aarch64::security;
use crate::arch::aarch64::timer::{init_timer_cpu, install_on_cpu as install_preemption_tick};
use crate::arch::aarch64::uart;
use crate::arch::cpu::idle_cpu;
use crate::process::scheduler::smp::api::init_ap_scheduler;

use super::state::CPUS_ONLINE;

// Called from `_aarch64_secondary_start` with sp pointing at this CPU's
// stack. Order: VBAR before anything that can trap, CPU/SCTLR/CPACR
// next, security mitigations gated by ID-reg checks, then GIC CPU
// interface + timer. IRQs stay masked until idle_cpu unmasks atomically
// with wfi.
#[no_mangle]
pub extern "C" fn aarch64_ap_entry() -> ! {
    install_vbar_el1();
    cpu::init_cpu();
    security::init_all();
    init_gic_cpu();
    init_timer_cpu();
    let _ = install_preemption_tick();

    CPUS_ONLINE.fetch_add(1, Ordering::AcqRel);

    let cpu_id = cpu::id::cpu_id();
    uart::puts(b"[BOOT] CPU ");
    uart::putc((b'0' + cpu_id as u8) as char);
    uart::puts(b" online\n");

    init_ap_scheduler(cpu_id);

    loop {
        idle_cpu();
    }
}
