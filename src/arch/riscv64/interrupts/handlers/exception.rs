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

use crate::arch::riscv64::cpu::caps;
use crate::arch::riscv64::fpu;
use crate::arch::riscv64::interrupts::cause::ExceptionCode;
use crate::arch::riscv64::interrupts::frame::TrapFrame;
use crate::arch::trap::contract::deliver;

use super::fatal::fatal;

// UserEcall is split out one level up (handlers::dispatch). Everything
// else goes through the cross-arch trap contract, which decides user vs
// kernel policy from frame.sstatus.SPP and the cause projection in
// interrupts::contract::cause.
pub fn dispatch(code: ExceptionCode, frame: &mut TrapFrame) -> ! {
    match code {
        ExceptionCode::SupervisorEcall => fatal(b"S-mode ecall (no S-call ABI)", frame),
        ExceptionCode::MachineEcall => fatal(b"M-mode ecall to S-mode", frame),
        ExceptionCode::IllegalInstruction if frame.is_from_user() => illegal_from_user(frame),
        _ => deliver(frame),
    }
}

// User-mode illegal-instruction. The dominant cause is sstatus.FS=Off
// trapping a first FP op; try lazy enable. The current FP module's
// `current::slot_mut` returns None (the cross-arch task FP slot is not
// yet wired), so `try_enable_for_current_task` returns false here and
// we fatal with a precise reason. When the task slot lands and
// dispatch's signature widens from `-> !` to allow returning, the
// lazy-enable success path resumes the user's trapping instruction
// via sret with sstatus.FS=Dirty in the restored frame.
fn illegal_from_user(frame: &mut TrapFrame) -> ! {
    if caps::is_configured() && (caps::has_f() || caps::has_d()) {
        if fpu::try_enable_for_current_task(frame) {
            // Unreachable today (slot_mut is None). Once the task slot
            // lands and dispatch is `-> ()`, replace this fatal with a
            // plain return so trap.S restores the frame and srets.
            fatal(b"FP lazy enable succeeded but dispatch is still -> !", frame);
        }
        fatal(b"user illegal-instruction (FP lazy enable: no per-task slot)", frame)
    } else if caps::has_v() {
        fatal(b"user illegal-instruction (V lazy enable unimplemented: variable vlenb)", frame)
    } else {
        fatal(b"user illegal-instruction (no FP/V capability)", frame)
    }
}
