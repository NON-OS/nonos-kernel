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

//! Single canonical exit path. Revokes broker grants, unregisters
//! service endpoints and the per-process inbox, releases the address
//! space when the dying capsule is current, defers the kernel stack
//! free, records exit accounting, and drops the PCB. Idempotent —
//! a racing second caller observes the missing PCB and returns.

use core::sync::atomic::Ordering;

use crate::process::core::{clear_current_if, Pid, ProcessState, CURRENT_PID, PROCESS_TABLE};

pub fn teardown(pid: Pid, exit_code: i32, by_signal: bool) {
    let pcb = match PROCESS_TABLE.find_by_pid(pid) {
        Some(p) => p,
        None => return,
    };

    // Authority surfaces revoke first. All three are pid-keyed and
    // run identically in self-context and cross-pid teardown:
    //   1. Broker grants — a future driver capsule's MMIO/IRQ/DMA
    //      claims would otherwise point at a zombie.
    //   2. Service endpoints — the canonical name is removed from the
    //      registry so `lookup_service` and the cap gate stop routing
    //      to this pid before the next IPC arrives.
    //   3. The per-process inbox `proc.{pid}` — any in-flight messages
    //      destined for it are dropped; the capsule that would have
    //      drained them is dead. Reply inboxes (`endpoint.<u64>`) are
    //      kernel-owned and stay registered for the next instance.
    let self_ctx = CURRENT_PID.load(Ordering::Acquire) == pid;
    let _ = crate::hardware::broker::release_all_for_pid(pid, self_ctx);
    let _ = crate::hardware::broker::irq_release_all_for_pid(pid);
    let _ = crate::hardware::broker::dma_release_all_for_pid(pid, self_ctx);
    let _ = crate::hardware::broker::pio_release_all_for_pid(pid);
    let _ = crate::services::registry::unregister_endpoints_for_pid(pid);
    let _ = crate::ipc::nonos_inbox::unregister_for_pid(pid);

    // The address-space walk consults the active CR3. When the caller
    // is the dying capsule itself the active CR3 is the right one;
    // when another process is killing this one the walk would deref
    // foreign page tables, so skip it. The frame leak on cross-pid
    // kill is older than this consolidation and tracked separately.
    if CURRENT_PID.load(Ordering::Acquire) == pid {
        crate::process::address_space::lifecycle::release(&pcb);
    } else if let Some(asid) = crate::memory::paging::manager::lookup_asid_for_process(pid) {
        let _ = crate::memory::paging::manager::cleanup_address_space(asid);
    }

    // The kernel stack the dying capsule is standing on cannot be
    // freed synchronously here. Defer it; the timer trap drains the
    // queue from a live capsule's stack.
    crate::kernel_core::process_spawn::defer_kernel_stack_release(pid);

    crate::process::accounting::record_exit_from_pcb(&pcb, exit_code, by_signal);
    pcb.exit_code.store(exit_code, Ordering::Release);
    *pcb.state.lock() = ProcessState::Zombie(exit_code);

    crate::process::core::init::reparent_orphans(pid);
    let _ = PROCESS_TABLE.terminate_process(pid);

    clear_current_if(pid);
}
