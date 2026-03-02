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

#[derive(Debug, Clone, Copy)]
pub struct DebugInfo {
    pub dr6: u64,
    pub breakpoint_0: bool,
    pub breakpoint_1: bool,
    pub breakpoint_2: bool,
    pub breakpoint_3: bool,
    pub single_step: bool,
    pub task_switch: bool,
}

impl DebugInfo {
    pub fn read() -> Self {
        let dr6: u64;
        // SAFETY: Reading DR6 register
        unsafe {
            core::arch::asm!("mov {}, dr6", out(reg) dr6, options(nomem, nostack));
        }
        Self {
            dr6,
            breakpoint_0: (dr6 & 0x01) != 0,
            breakpoint_1: (dr6 & 0x02) != 0,
            breakpoint_2: (dr6 & 0x04) != 0,
            breakpoint_3: (dr6 & 0x08) != 0,
            single_step: (dr6 & 0x4000) != 0,
            task_switch: (dr6 & 0x8000) != 0,
        }
    }

    pub fn clear() {
        // SAFETY: Clearing DR6 is safe and required after handling debug exception
        unsafe {
            core::arch::asm!("mov dr6, {}", in(reg) 0u64, options(nomem, nostack));
        }
    }
}

pub fn handle(frame: InterruptStackFrame) {
    let ctx = ExceptionContext::from_frame(&frame);
    let info = DebugInfo::read();

    if info.single_step {
        handle_single_step(&ctx);
    } else if info.breakpoint_0 || info.breakpoint_1 || info.breakpoint_2 || info.breakpoint_3 {
        handle_hardware_breakpoint(&ctx, &info);
    } else if info.task_switch {
        handle_task_switch(&ctx);
    }

    DebugInfo::clear();
}

fn handle_single_step(_ctx: &ExceptionContext) {
    crate::log::logger::log_debug!("Single step at rip={:#x}", _ctx.instruction_pointer);
}

fn handle_hardware_breakpoint(_ctx: &ExceptionContext, info: &DebugInfo) {
    let bp_num = if info.breakpoint_0 {
        0
    } else if info.breakpoint_1 {
        1
    } else if info.breakpoint_2 {
        2
    } else {
        3
    };
    crate::log::logger::log_debug!(
        "Hardware breakpoint {} at rip={:#x}",
        bp_num,
        _ctx.instruction_pointer
    );
}

fn handle_task_switch(_ctx: &ExceptionContext) {
    crate::log::logger::log_debug!("Task switch debug trap");
}
