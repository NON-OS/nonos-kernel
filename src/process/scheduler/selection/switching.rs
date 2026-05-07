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

use super::super::preemption::{CURRENT_TIME_SLICE, DEFAULT_TIME_SLICE};
use core::sync::atomic::Ordering;

pub(crate) fn switch_to_process(pid: u32) {
    use crate::arch::x86_64::gdt;
    use crate::memory::paging::manager::api::switch_to_process_address_space;
    use crate::process::nonos_core::INTERRUPT_SAVED_CONTEXTS;
    use crate::process::nonos_core::{has_saved_fpu_state, init_fpu, restore_fpu_state};
    use crate::process::nonos_core::{ProcessState, CURRENT_PID, PROCESS_TABLE};
    use crate::process::userspace::transitions::{restore_user_context_iretq, return_to_usermode};
    use crate::smp::percpu;

    let pcb = match PROCESS_TABLE.find_by_pid(pid) {
        Some(p) => p,
        None => return,
    };

    // First-entry CPL=3 path. `setup_initial_user_context` stages an
    // iretq frame on the PCB and the per-process kernel stack top
    // alongside it. Take both atomically; the take() guarantees the
    // user-entry path runs at most once per spawn.
    if let Some(frame) = pcb.pending_user_entry.lock().take() {
        crate::sys::serial::print(b"[SCHED] enter-user pid=");
        crate::arch::x86_64::diag::print_hex_u64(pid as u64);
        crate::sys::serial::print(b" rip=");
        crate::arch::x86_64::diag::print_hex_u64(frame.rip);
        crate::sys::serial::print(b" rsp=");
        crate::arch::x86_64::diag::print_hex_u64(frame.rsp);
        crate::sys::serial::println(b"");
        let kstack = pcb.kernel_stack_top.load(Ordering::Acquire);
        if kstack == 0 {
            // Fail closed: a pending user entry without a kernel stack
            // would land any subsequent CPL=3 trap on a stale RSP0 and
            // recurse. Mark the process terminated and drop it.
            *pcb.state.lock() = ProcessState::Terminated(-1);
            return;
        }

        // TSS.RSP0 is what the CPU pulls on a CPL=3 → CPL=0 trap.
        // Update both the GDT/TSS slot for this CPU and the percpu
        // mirror that the syscall fast-path reads via `gs:0x20`.
        let cpu = percpu::current().cpu_id;
        // SAFETY: eK@nonos.systems — `cpu` comes from PerCpuData and is
        // bounded by MAX_CPUS; `set_kernel_stack` validates the index
        // and writes the matching TSS RSP0 entry.
        unsafe {
            if gdt::set_kernel_stack(cpu, kstack).is_err() {
                *pcb.state.lock() = ProcessState::Terminated(-1);
                return;
            }
        }
        percpu::set_kernel_stack(kstack);

        if pcb.cr3.load(Ordering::Relaxed) != 0 {
            if switch_to_process_address_space(pid).is_err() {
                *pcb.state.lock() = ProcessState::Terminated(-1);
                return;
            }
        }

        *pcb.state.lock() = ProcessState::Running;
        CURRENT_PID.store(pid, Ordering::SeqCst);
        CURRENT_TIME_SLICE.store(DEFAULT_TIME_SLICE, Ordering::SeqCst);

        if has_saved_fpu_state(pid) {
            restore_fpu_state(pid);
        } else {
            init_fpu();
        }

        // iretq into CPL=3 with USER_CS / USER_DS, the capsule's ELF
        // entry, and its per-process user stack. `return_to_usermode`
        // is `-> !`; control does not return.
        // SAFETY: eK@nonos.systems — `frame` is a fully-populated
        // `InterruptFrame` on this stack; the asm reads from `rdi`
        // and iretqs immediately, so the borrow lives long enough.
        unsafe { return_to_usermode(&frame as *const _) }
    }

    // Preempt-resume path for a CPL=3 capsule that has already
    // entered user mode and was trapped/IRQ'd back into the kernel.
    // The trap-entry trampoline (today: `timer_trampoline`) captured
    // the full GPR set + iretq frame onto the PCB. `take()` consumes
    // the snapshot so a future resume after the next preempt sees
    // the next captured frame, never a stale one.
    if let Some(saved) = pcb.saved_user_context.lock().take() {
        let kstack = pcb.kernel_stack_top.load(Ordering::Acquire);
        if kstack == 0 {
            *pcb.state.lock() = ProcessState::Terminated(-1);
            return;
        }

        let cpu = percpu::current().cpu_id;
        // SAFETY: eK@nonos.systems — `cpu` comes from PerCpuData and is
        // bounded by MAX_CPUS; `set_kernel_stack` validates the index
        // and writes the matching TSS RSP0 entry.
        unsafe {
            if gdt::set_kernel_stack(cpu, kstack).is_err() {
                *pcb.state.lock() = ProcessState::Terminated(-1);
                return;
            }
        }
        percpu::set_kernel_stack(kstack);

        if pcb.cr3.load(Ordering::Relaxed) != 0 {
            if switch_to_process_address_space(pid).is_err() {
                *pcb.state.lock() = ProcessState::Terminated(-1);
                return;
            }
        }

        *pcb.state.lock() = ProcessState::Running;
        CURRENT_PID.store(pid, Ordering::SeqCst);
        CURRENT_TIME_SLICE.store(DEFAULT_TIME_SLICE, Ordering::SeqCst);

        if has_saved_fpu_state(pid) {
            restore_fpu_state(pid);
        } else {
            init_fpu();
        }

        // Restore 15 GPRs and iretq back into CPL=3 at saved RIP/RSP.
        // `restore_user_context_iretq` is `-> !`.
        // SAFETY: eK@nonos.systems — `saved` is a fully-populated
        // `UserContext` on this stack; the asm consumes it via `rdi`
        // and iretqs without returning, so the borrow lives long
        // enough.
        unsafe { restore_user_context_iretq(&saved as *const _) }
    }

    // Legacy kernel-thread resume path. Used only by
    // `spawn_isolated_service` (kernel threads).
    let ctx = match INTERRUPT_SAVED_CONTEXTS.write().remove(&pid) {
        Some(c) => c,
        None => {
            *pcb.state.lock() = ProcessState::Ready;
            return;
        }
    };

    let has_own_addr_space = pcb.cr3.load(Ordering::Relaxed) != 0;
    *pcb.state.lock() = ProcessState::Running;

    CURRENT_PID.store(pid, Ordering::SeqCst);
    CURRENT_TIME_SLICE.store(DEFAULT_TIME_SLICE, Ordering::SeqCst);

    if has_own_addr_space {
        let _ = switch_to_process_address_space(pid);
    }

    if has_saved_fpu_state(pid) {
        restore_fpu_state(pid);
    } else {
        init_fpu();
    }

    ctx.restore()
}
