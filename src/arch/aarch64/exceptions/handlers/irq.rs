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

use crate::arch::aarch64::context::save_user_frame;
use crate::arch::aarch64::exceptions::frame::ExceptionFrame;
use crate::arch::aarch64::gic::{acknowledge_interrupt, dispatch_irq, end_interrupt};
use crate::sys::serial::{print_hex, print_str};

use super::fatal::fatal;

// IAR special intids (1020..1023) self-deassert; nothing to do.
// Real intid: dispatch through the GIC IRQ registry. EOI in both
// dispatched and unhandled cases so the line is released; unhandled
// is a contract violation and halts.
#[no_mangle]
pub extern "C" fn aarch64_exc_irq_current(frame: *mut ExceptionFrame) {
    let frame = unsafe { &*frame };
    handle(frame, b"IRQ EL1")
}

#[no_mangle]
pub extern "C" fn aarch64_exc_irq_lower(frame: *mut ExceptionFrame) {
    let frame = unsafe { &*frame };
    // Mirror EL0 state to the current PCB before the IRQ handler runs.
    // If the scheduler decides to yield (via tick → NEED_RESCHEDULE),
    // the saved snapshot is the most recent user state; on normal eret
    // the snapshot is overwritten on the next trap.
    save_user_frame(frame);
    handle(frame, b"IRQ EL0")
}

fn handle(frame: &ExceptionFrame, tag: &[u8]) {
    let intid = match acknowledge_interrupt() {
        Some(i) => i,
        None => return,
    };
    if dispatch_irq(intid) {
        end_interrupt(intid);
        return;
    }
    print_str("[aarch64] unhandled intid=");
    print_hex(intid as u64);
    print_str("\n");
    end_interrupt(intid);
    fatal(tag, frame)
}
