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

use crate::arch::riscv64::interrupts::frame::TrapFrame;
use crate::process::core::{CURRENT_PID, PROCESS_TABLE};

use super::types::SavedUser;

// Mirror the trap-saved U-mode frame onto the current PCB. Called from
// the interrupt dispatcher only when `frame.is_from_user()`. kernel_sp
// is copied from `pcb.kernel_stack_top` so resume re-primes sscratch.
// Idempotent: a later capture overwrites; scheduler `take()`s the
// freshest snapshot.
//
// gprs index → arch register (matches resume_user.S):
//   0=ra(x1)  1=sp(x2)  2=gp(x3)  3=tp(x4)  4=t0(x5)  5=t1(x6)
//   6=t2(x7)  7=s0(x8)  8=s1(x9)  9=a0(x10) ... 16=a7(x17)
//  17=s2(x18) ... 26=s11(x27) 27=t3(x28) ... 30=t6(x31)
pub fn save_user_frame(frame: &TrapFrame) {
    let pid = CURRENT_PID.load(Ordering::Acquire);
    if pid == 0 {
        return;
    }
    let pcb = match PROCESS_TABLE.find_by_pid(pid) {
        Some(p) => p,
        None => return,
    };
    let kstack = pcb.kernel_stack_top.load(Ordering::Acquire);
    let mut saved = SavedUser::zeroed();
    saved.gprs[0] = frame.ra as u64;
    saved.gprs[1] = frame.sp as u64;
    saved.gprs[2] = frame.gp as u64;
    saved.gprs[3] = frame.tp as u64;
    saved.gprs[4] = frame.t0 as u64;
    saved.gprs[5] = frame.t1 as u64;
    saved.gprs[6] = frame.t2 as u64;
    saved.gprs[7] = frame.s0 as u64;
    saved.gprs[8] = frame.s1 as u64;
    saved.gprs[9] = frame.a0 as u64;
    saved.gprs[10] = frame.a1 as u64;
    saved.gprs[11] = frame.a2 as u64;
    saved.gprs[12] = frame.a3 as u64;
    saved.gprs[13] = frame.a4 as u64;
    saved.gprs[14] = frame.a5 as u64;
    saved.gprs[15] = frame.a6 as u64;
    saved.gprs[16] = frame.a7 as u64;
    saved.gprs[17] = frame.s2 as u64;
    saved.gprs[18] = frame.s3 as u64;
    saved.gprs[19] = frame.s4 as u64;
    saved.gprs[20] = frame.s5 as u64;
    saved.gprs[21] = frame.s6 as u64;
    saved.gprs[22] = frame.s7 as u64;
    saved.gprs[23] = frame.s8 as u64;
    saved.gprs[24] = frame.s9 as u64;
    saved.gprs[25] = frame.s10 as u64;
    saved.gprs[26] = frame.s11 as u64;
    saved.gprs[27] = frame.t3 as u64;
    saved.gprs[28] = frame.t4 as u64;
    saved.gprs[29] = frame.t5 as u64;
    saved.gprs[30] = frame.t6 as u64;
    saved.sepc = frame.sepc as u64;
    saved.sstatus = frame.sstatus as u64;
    saved.kernel_sp = kstack;
    *pcb.saved_user_context.lock() = Some(saved);
}
