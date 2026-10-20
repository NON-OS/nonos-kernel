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

use super::idle_steps::{halt_once, take_work};
use crate::smp::state::CPU_DESCRIPTORS;
use core::sync::atomic::Ordering;

/// Where an AP lives when it has nothing to run, and where it takes its
/// first process from (see `take_work`).
///
/// The halt decision is made against the run queue itself, not the reschedule
/// flag alone. A CPU that enqueues work may not know this one is idle and may
/// skip the IPI; if the flag were the only signal, that task would sit
/// unclaimed until some unrelated interrupt happened to land here. The IPI is
/// a latency optimisation, not the correctness condition.
pub(super) fn ap_idle_loop(cpu_id: u32) -> ! {
    let cpu = &CPU_DESCRIPTORS[cpu_id as usize];
    cpu.set_stage(crate::smp::Stage::IdleLoop);
    let runs_user = super::user_setup::is_ready(cpu_id);
    loop {
        /*
         * Interrupts off across the test, so work appearing between the test
         * and the halt cannot be missed.
         * SAFETY: eK@nonos.systems - masking interrupts on this CPU only. The
         * window is closed again by the wait below on every path.
         */
        unsafe {
            core::arch::asm!("cli", options(nostack));
        }

        /*
         * Idle is published before the queue is read. A CPU that enqueues
         * after the read then sees the mark and sends the wake, which stays
         * pending across the masked window and ends the halt at once. A CPU
         * that may not run user code never claims to be idle: the wake goes
         * to one idle CPU only, and it would be spent on this one.
         */
        cpu.idle.store(runs_user, Ordering::SeqCst);

        // Set before the queue is consulted. Consulting it takes a lock with
        // interrupts already masked, which is a place a CPU can stop without
        // anything outside it being able to tell.
        cpu.set_stage(crate::smp::Stage::IdleCheckingQueue);

        if runs_user && take_work(cpu) {
            continue;
        }
        halt_once(cpu);
    }
}
