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
use super::types::CpuState;
use super::constants::{IPI_FLAG_RESCHEDULE, IPI_FLAG_PANIC, IPI_FLAG_STOP};
use super::state::{CPU_DESCRIPTORS, AP_STARTUP_BARRIER};
use super::ipi_handler::{handle_panic_ipi, handle_stop_ipi};

#[no_mangle]
pub unsafe extern "C" fn ap_entry(cpu_id: u32) {
    let _ = unsafe { crate::arch::x86_64::interrupt::apic::init() };

    CPU_DESCRIPTORS[cpu_id as usize].set_state(CpuState::Online);

    AP_STARTUP_BARRIER.fetch_add(1, Ordering::Release);

    // SAFETY: Enable interrupts on AP
    unsafe { core::arch::asm!("sti", options(nostack, nomem)); }

    ap_idle_loop(cpu_id);
}

fn ap_idle_loop(cpu_id: u32) -> ! {
    loop {
        let cpu = &CPU_DESCRIPTORS[cpu_id as usize];
        let pending = cpu.ipi_pending.load(Ordering::Relaxed);

        if pending & IPI_FLAG_RESCHEDULE != 0 {
            cpu.ipi_pending.fetch_and(!IPI_FLAG_RESCHEDULE, Ordering::Relaxed);
            crate::sched::schedule();
        }

        if pending & IPI_FLAG_PANIC != 0 {
            handle_panic_ipi();
        }

        if pending & IPI_FLAG_STOP != 0 {
            handle_stop_ipi();
        }

        // SAFETY: Enter low-power wait state
        unsafe {
            core::arch::asm!("sti; hlt", options(nostack, nomem));
        }

        cpu.idle_cycles.fetch_add(1, Ordering::Relaxed);
    }
}
