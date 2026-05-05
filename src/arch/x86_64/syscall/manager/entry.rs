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

use crate::process::userspace::constants::{USER_CS, USER_DS};
use crate::syscall::contract::{dispatch as contract_dispatch, SyscallArgs};
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::types::errnos;

// SYSCALL/SYSRET register ABI implemented by `syscall_entry_asm`:
//   in  rax     = syscall number
//       rdi     = arg1
//       rsi     = arg2
//       rdx     = arg3
//       r10     = arg4         (rcx is unusable: SYSCALL stomps it with the user RIP)
//       r8      = arg5
//       r9      = arg6
//   out rax     = syscall return value (i64-as-u64)
//   clobber     rcx, r11       (architecturally clobbered by SYSCALL/SYSRET)
//   preserved   rbx, rbp, r12, r13, r14, r15
//                              (user callee-saved; the Rust C-ABI handler
//                               preserves them; the asm does not touch them)
//
// PerCpuData field offsets used through the GS segment register. These
// must track `crate::smp::percpu::types::PerCpuData`:
//   0x00  self_ptr
//   0x08  cpu_id (u32) + apic_id (u32)
//   0x10  current_process (AtomicU64)
//   0x18  current_thread  (AtomicU64)
//   0x20  kernel_stack_top
//   0x28  user_stack_saved
// MSR_GS_BASE / MSR_KERNEL_GS_BASE are programmed by `percpu::init_bsp`
// / `percpu::init_ap` to point at the per-CPU PerCpuData record.
#[unsafe(naked)]
pub extern "C" fn syscall_entry_asm() {
    core::arch::naked_asm!(
        "swapgs",
        "mov gs:0x28, rsp",        // save user rsp
        "mov rsp, gs:0x20",        // switch to per-CPU kernel stack
        "push rbp",                // user rbp (callee-saved)
        "push r11",                // user rflags (CPU put it here)
        "push rcx",                // user rip   (CPU put it here)
        "push r10",                // arg4 slot (also remapped below)
        "push r9",                 // arg6
        "push r8",                 // arg5
        "mov rcx, r10",            // C-ABI arg4 = r10
        "push rax",                // syscall number (also handler arg)
        "mov rdi, rax",
        "call {handler}",
        "add rsp, 8",              // drop pushed rax
        "push rax",                // preserve return value across return_hook
        "mov rdi, rsp",
        "sub rsp, 8",
        "call {return_hook}",
        "add rsp, 8",
        "pop rax",                 // restore return value
        "pop r8",
        "pop r9",
        "pop r10",
        "pop rcx",                 // user rip → rcx (SYSRET reads RIP from rcx)
        "pop r11",                 // user rflags → r11 (SYSRET reads RFLAGS from r11)
        "pop rbp",
        // SYSRET RIP validation: RCX must be canonical user address.
        // User-space ends at 0x0000_7FFF_FFFF_FFFF; bit 47 clear means
        // safe SYSRET, set means take the IRET fallback so we cannot
        // be tricked into SYSRETting to a non-canonical address.
        "bt rcx, 47",
        "jc 2f",
        // SYSRET fast path. STAR is programmed so the CPU loads
        // CS = USER_CS (0x23) and SS = USER_DS (0x1B) on SYSRETQ.
        "mov rsp, gs:0x28",
        "swapgs",
        "sysretq",
        // IRET fallback. Build the iretq five-tuple on the *kernel*
        // stack (we are still on it — gs:0x28 holds the user RSP which
        // we push as the iretq frame's RSP field). Push order, low to
        // high address (= reverse of CPU pop order):
        //   ss      = USER_DS
        //   rsp     = saved user rsp
        //   rflags  = r11 (user rflags)
        //   cs      = USER_CS
        //   rip     = rcx (user rip)
        "2:",
        "push {ss}",
        "push qword ptr gs:0x28",
        "push r11",
        "push {cs}",
        "push rcx",
        "swapgs",
        "iretq",
        handler = sym syscall_handler,
        return_hook = sym super::signal_return::syscall_return_signal_hook,
        cs = const USER_CS as u64,
        ss = const USER_DS as u64,
    );
}

// Bridge from the SYSCALL/SYSRET asm shim above into the shared
// contract dispatch. Future per-arch shims (aarch64 SVC, riscv64 ECALL)
// will mirror this shape: extract the syscall number and six argument
// registers, hand them to `crate::syscall::contract::dispatch`, return
// the packed value to the asm shim. The capability check happens inside
// the contract; an unrecognised syscall number returns `ENOSYS` without
// touching the dispatcher.
#[no_mangle]
pub(super) extern "C" fn syscall_handler(
    number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> u64 {
    let Some(sc) = SyscallNumber::from_u64(number) else {
        return (-(errnos::ENOSYS as i64)) as u64;
    };
    let result = contract_dispatch(sc, SyscallArgs::new([arg1, arg2, arg3, arg4, arg5, arg6]));
    result.value as u64
}
