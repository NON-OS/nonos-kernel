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

use crate::arch::riscv64::context::save_user_frame;
use crate::arch::riscv64::interrupts::cause::InterruptCode;
use crate::arch::riscv64::interrupts::frame::TrapFrame;
use crate::arch::riscv64::plic::{claim_interrupt, complete_interrupt, dispatch_irq};
use crate::arch::riscv64::timer;
use crate::sys::serial::{print_hex, print_str};

use super::fatal::fatal;

pub fn dispatch(code: InterruptCode, frame: &mut TrapFrame) {
    // Mirror U-mode state to the current PCB before the handler runs.
    // SupervisorTimer/SupervisorExternal can lead to a yield via
    // NEED_RESCHEDULE; on normal sret the snapshot is overwritten on
    // the next trap. is_from_user() reads sstatus.SPP from the frame.
    if frame.is_from_user() {
        save_user_frame(frame);
    }

    match code {
        InterruptCode::SupervisorTimer => timer::handle_timer_interrupt(),
        InterruptCode::SupervisorExternal => handle_external(frame),

        // No kernel-side IPI emitter is wired today; receipt is a stray
        // sip.SSIP write.
        InterruptCode::SupervisorSoftware => fatal(b"S-mode software IPI (no sender wired)", frame),

        // M-mode and U-mode interrupts cannot be delivered to S-mode
        // unless mideleg is misprogrammed.
        InterruptCode::MachineSoftware
        | InterruptCode::MachineTimer
        | InterruptCode::MachineExternal => fatal(b"M-mode interrupt to S-mode", frame),
        InterruptCode::UserSoftware | InterruptCode::UserTimer | InterruptCode::UserExternal => {
            fatal(b"U-mode interrupt to S-mode", frame)
        }

        InterruptCode::Unknown(_) => fatal(b"unknown interrupt code", frame),
    }
}

// PLIC external IRQ. Claim returns 0 when nothing is pending. Always
// complete so the line is released; unhandled is a contract violation
// and halts.
fn handle_external(frame: &mut TrapFrame) {
    let irq = match claim_interrupt() {
        Some(i) if i != 0 => i,
        _ => return,
    };
    if dispatch_irq(irq) {
        complete_interrupt(irq);
        return;
    }
    print_str("[riscv64] unhandled PLIC irq=");
    print_hex(irq as u64);
    print_str("\n");
    complete_interrupt(irq);
    fatal(b"S-mode external", frame)
}
