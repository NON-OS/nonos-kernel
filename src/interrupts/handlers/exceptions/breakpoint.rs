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

use x86_64::structures::idt::InterruptStackFrame;

use super::context::ExceptionContext;
use crate::interrupts::idt::halt_loop;
use crate::interrupts::stats;

const SIGTRAP: i32 = 5;

pub fn handle(frame: InterruptStackFrame) {
    let ctx = ExceptionContext::from_frame(&frame);
    stats::increment_exceptions();

    crate::log::logger::log_info!(
        "BREAKPOINT: rip={:#x} rsp={:#x} cs={:#x}",
        ctx.instruction_pointer,
        ctx.stack_pointer,
        ctx.code_segment
    );

    if ctx.is_user_mode() {
        handle_user_breakpoint(&ctx);
    } else {
        handle_kernel_breakpoint(&ctx);
    }
}

fn handle_user_breakpoint(ctx: &ExceptionContext) {
    crate::log::logger::log_warning!(
        "User process hit breakpoint at {:#x} without debugger attached",
        ctx.instruction_pointer
    );

    if let Some(pcb) = crate::process::current_process() {
        pcb.terminate(SIGTRAP);
    }

    halt_loop();
}

fn handle_kernel_breakpoint(ctx: &ExceptionContext) {
    crate::log::logger::log_info!(
        "Kernel breakpoint at {:#x}",
        ctx.instruction_pointer
    );

    dump_debug_state(ctx);
}

fn dump_debug_state(ctx: &ExceptionContext) {
    crate::log::logger::log_info!(
        "State: rip={:#x} rsp={:#x} rflags={:#x}",
        ctx.instruction_pointer,
        ctx.stack_pointer,
        ctx.cpu_flags
    );

    // SAFETY: Reading debug registers for diagnostic purposes
    unsafe {
        let dr6: u64;
        let dr7: u64;
        core::arch::asm!("mov {}, dr6", out(reg) dr6, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, dr7", out(reg) dr7, options(nostack, preserves_flags));

        if dr6 != 0 || dr7 != 0 {
            crate::log::logger::log_info!(
                "Debug registers: DR6={:#x} DR7={:#x}",
                dr6,
                dr7
            );
        }
    }
}
