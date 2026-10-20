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

//! An AP opening interrupts, telling the boot CPU it is online, reporting,
//! and settling in its idle loop.

use super::idle::ap_idle_loop;
use crate::smp::state::CPU_DESCRIPTORS;

pub(super) fn go_live(cpu_id: u32, user: super::user_setup::Prepared) -> ! {
    // SAFETY: eK@nonos.systems - the IDT, GDT, TSS and per-CPU state above are
    // all in place, so this CPU can now take an interrupt.
    unsafe {
        core::arch::asm!("sti", options(nostack));
    }
    CPU_DESCRIPTORS[cpu_id as usize].set_stage(crate::smp::Stage::InterruptsOn);

    super::online::publish(cpu_id);

    /*
     * Read the part back rather than trust the write above. An AP parked in
     * its idle loop with a timer that never armed looks exactly like a healthy
     * idle AP, and the symptom arrives stages later as a TLB shootdown timeout
     * with nothing pointing back here.
     *
     * After `sti`, and that is not a detail. Printing takes the serial lock,
     * which is a plain spin mutex the boot CPU holds and releases hundreds of
     * times while it brings the system up. An AP contending for it before
     * interrupts are enabled spins with them masked: it answers no timer tick
     * and no shootdown for as long as the boot CPU keeps printing, which is
     * long enough to lose a shootdown round. Reporting here costs the same
     * information and none of that.
     */
    crate::sys::apic::report_local_timer(cpu_id);
    super::tsc_adjust_report::report(cpu_id);
    let apic_id = crate::arch::interrupt_controller::local_id();
    crate::smp::topology::record_core_kind(cpu_id as usize, apic_id);
    CPU_DESCRIPTORS[cpu_id as usize].set_stage(crate::smp::Stage::Reported);
    super::user_setup::finish(cpu_id, user);

    ap_idle_loop(cpu_id);
}
