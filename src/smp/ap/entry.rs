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

use crate::smp::state::CPU_DESCRIPTORS;

/// Entered from the trampoline once this AP is in long mode on its own stack.
///
/// # Safety
/// Called exactly once per AP, by the trampoline, with `cpu_id` the index the
/// BSP wrote into that AP's boot context and a descriptor already published.
#[no_mangle]
pub unsafe extern "C" fn ap_entry(cpu_id: u32) {
    /*
     * Claim this start before anything else. The boot CPU stops waiting for
     * an AP after a deadline and reuses the trampoline for the next one; if it
     * gave up on this AP first, this AP must not run as `cpu_id`, and it must
     * not touch a lock or a shared structure on the way out, because the boot
     * CPU is about to send it INIT. Parking with interrupts masked is all it
     * may do. The stack under it is its own and is never handed out again.
     */
    if !CPU_DESCRIPTORS[cpu_id as usize].boot_claim.ap_enter() {
        loop {
            // SAFETY: eK@nonos.systems - masks and halts this CPU only.
            unsafe { core::arch::asm!("cli", "hlt", options(nostack)) };
        }
    }
    // Before anything on this AP reads the time.
    super::tsc_adjust::align(cpu_id);
    // SAFETY: eK@nonos.systems - once, on this AP, interrupts still masked,
    // with the claim above passed.
    let user = unsafe { super::bring_up::bring_up(cpu_id) };
    super::go_live::go_live(cpu_id, user)
}
