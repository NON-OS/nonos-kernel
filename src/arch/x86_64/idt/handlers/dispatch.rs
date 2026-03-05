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

use crate::arch::x86_64::idt::constants::*;
use crate::arch::x86_64::idt::entry::{InterruptFrame, PageFaultError};
use crate::arch::x86_64::idt::state::{IRQ_HANDLERS, OTHER_HANDLERS, SYSCALL_HANDLER};
use super::utils::{exception_panic, exception_panic_with_cr2, read_cr2};
use super::acknowledge_interrupt;

pub(crate) fn handle_exception(frame: &mut InterruptFrame) {
    let vector = frame.vector as u8;

    match vector {
        VEC_DIVIDE_ERROR => {
            exception_panic("Divide Error (#DE)", frame);
        }
        VEC_DEBUG => {}
        VEC_NMI => {
            exception_panic("Non-Maskable Interrupt (NMI)", frame);
        }
        VEC_BREAKPOINT => {}
        VEC_OVERFLOW => {
            exception_panic("Overflow (#OF)", frame);
        }
        VEC_BOUND_RANGE => {
            exception_panic("BOUND Range Exceeded (#BR)", frame);
        }
        VEC_INVALID_OPCODE => {
            exception_panic("Invalid Opcode (#UD)", frame);
        }
        VEC_DEVICE_NOT_AVAILABLE => {
            exception_panic("Device Not Available (#NM)", frame);
        }
        VEC_DOUBLE_FAULT => {
            exception_panic("Double Fault (#DF)", frame);
        }
        VEC_INVALID_TSS => {
            exception_panic("Invalid TSS (#TS)", frame);
        }
        VEC_SEGMENT_NOT_PRESENT => {
            exception_panic("Segment Not Present (#NP)", frame);
        }
        VEC_STACK_SEGMENT => {
            exception_panic("Stack Segment Fault (#SS)", frame);
        }
        VEC_GENERAL_PROTECTION => {
            exception_panic("General Protection Fault (#GP)", frame);
        }
        VEC_PAGE_FAULT => {
            let cr2 = read_cr2();
            let error = PageFaultError(frame.error_code);
            exception_panic_with_cr2("Page Fault (#PF)", frame, cr2, error);
        }
        VEC_X87_FP => {
            exception_panic("x87 FP Exception (#MF)", frame);
        }
        VEC_ALIGNMENT_CHECK => {
            exception_panic("Alignment Check (#AC)", frame);
        }
        VEC_MACHINE_CHECK => {
            exception_panic("Machine Check (#MC)", frame);
        }
        VEC_SIMD_FP => {
            exception_panic("SIMD FP Exception (#XM)", frame);
        }
        VEC_VIRTUALIZATION => {
            exception_panic("Virtualization Exception (#VE)", frame);
        }
        VEC_CONTROL_PROTECTION => {
            exception_panic("Control Protection (#CP)", frame);
        }
        _ => {}
    }
}

pub(crate) fn handle_irq(frame: &mut InterruptFrame) {
    let irq = (frame.vector as u8) - IRQ_BASE;

    // SAFETY: IRQ_HANDLERS is only written during initialization.
    unsafe {
        if let Some(handler) = IRQ_HANDLERS[irq as usize] {
            handler(irq);
        }
    }

    acknowledge_interrupt(irq);
}

pub(crate) fn handle_syscall(frame: &mut InterruptFrame) {
    // SAFETY: SYSCALL_HANDLER is only written during initialization.
    unsafe {
        if let Some(handler) = SYSCALL_HANDLER {
            handler(frame);
        }
    }
}

pub(crate) fn handle_other(frame: &mut InterruptFrame) {
    let vector = frame.vector as u8;

    // SAFETY: OTHER_HANDLERS is only written during initialization.
    unsafe {
        if let Some(handler) = OTHER_HANDLERS[vector as usize] {
            handler(frame);
        }
    }
}
