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

use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

use crate::interrupts::handlers;

pub extern "x86-interrupt" fn isr_divide_error(frame: InterruptStackFrame) {
    handlers::divide_error(frame);
}

pub extern "x86-interrupt" fn isr_debug(frame: InterruptStackFrame) {
    handlers::debug(frame);
}

pub extern "x86-interrupt" fn isr_nmi(frame: InterruptStackFrame) {
    handlers::nmi(frame);
}

pub extern "x86-interrupt" fn isr_breakpoint(frame: InterruptStackFrame) {
    handlers::breakpoint(frame);
}

pub extern "x86-interrupt" fn isr_overflow(frame: InterruptStackFrame) {
    handlers::overflow(frame);
}

pub extern "x86-interrupt" fn isr_bound_range(frame: InterruptStackFrame) {
    handlers::bound_range_exceeded(frame);
}

pub extern "x86-interrupt" fn isr_invalid_opcode(frame: InterruptStackFrame) {
    handlers::invalid_opcode(frame);
}

pub extern "x86-interrupt" fn isr_device_na(frame: InterruptStackFrame) {
    handlers::device_not_available(frame);
}

pub extern "x86-interrupt" fn isr_double_fault(frame: InterruptStackFrame, code: u64) -> ! {
    handlers::double_fault(frame, code)
}

pub extern "x86-interrupt" fn isr_invalid_tss(frame: InterruptStackFrame, code: u64) {
    handlers::invalid_tss(frame, code);
}

pub extern "x86-interrupt" fn isr_segment_not_present(frame: InterruptStackFrame, code: u64) {
    handlers::segment_not_present(frame, code);
}

pub extern "x86-interrupt" fn isr_stack_segment_fault(frame: InterruptStackFrame, code: u64) {
    handlers::stack_segment_fault(frame, code);
}

pub extern "x86-interrupt" fn isr_gpf(frame: InterruptStackFrame, code: u64) {
    handlers::general_protection_fault(frame, code);
}

pub extern "x86-interrupt" fn isr_page_fault(frame: InterruptStackFrame, code: PageFaultErrorCode) {
    handlers::page_fault(frame, code.bits());
}

pub extern "x86-interrupt" fn isr_x87_fp(frame: InterruptStackFrame) {
    handlers::x87_floating_point(frame);
}

pub extern "x86-interrupt" fn isr_alignment_check(frame: InterruptStackFrame, _error_code: u64) {
    handlers::alignment_check(frame);
}

pub extern "x86-interrupt" fn isr_machine_check(frame: InterruptStackFrame) -> ! {
    handlers::machine_check(frame)
}

pub extern "x86-interrupt" fn isr_simd_fp(frame: InterruptStackFrame) {
    handlers::simd_floating_point(frame);
}

pub extern "x86-interrupt" fn isr_virtualization(frame: InterruptStackFrame) {
    handlers::virtualization(frame);
}

pub extern "x86-interrupt" fn irq_timer(_frame: InterruptStackFrame) {
    handlers::timer();
}

pub extern "x86-interrupt" fn irq_keyboard(_frame: InterruptStackFrame) {
    handlers::keyboard();
}

pub extern "x86-interrupt" fn irq_mouse(_frame: InterruptStackFrame) {
    handlers::mouse();
}

pub extern "x86-interrupt" fn irq_syscall(_frame: InterruptStackFrame) {
    handlers::syscall();
}
