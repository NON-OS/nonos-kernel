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

pub const VECTOR_DIVIDE_ERROR: u8 = 0;
pub const VECTOR_DEBUG: u8 = 1;
pub const VECTOR_NMI: u8 = 2;
pub const VECTOR_BREAKPOINT: u8 = 3;
pub const VECTOR_OVERFLOW: u8 = 4;
pub const VECTOR_BOUND_RANGE: u8 = 5;
pub const VECTOR_INVALID_OPCODE: u8 = 6;
pub const VECTOR_DEVICE_NOT_AVAILABLE: u8 = 7;
pub const VECTOR_DOUBLE_FAULT: u8 = 8;
pub const VECTOR_COPROCESSOR_SEGMENT: u8 = 9;
pub const VECTOR_INVALID_TSS: u8 = 10;
pub const VECTOR_SEGMENT_NOT_PRESENT: u8 = 11;
pub const VECTOR_STACK_SEGMENT_FAULT: u8 = 12;
pub const VECTOR_GENERAL_PROTECTION: u8 = 13;
pub const VECTOR_PAGE_FAULT: u8 = 14;
pub const VECTOR_RESERVED_15: u8 = 15;
pub const VECTOR_X87_FLOATING_POINT: u8 = 16;
pub const VECTOR_ALIGNMENT_CHECK: u8 = 17;
pub const VECTOR_MACHINE_CHECK: u8 = 18;
pub const VECTOR_SIMD_FLOATING_POINT: u8 = 19;
pub const VECTOR_VIRTUALIZATION: u8 = 20;
pub const VECTOR_CONTROL_PROTECTION: u8 = 21;

pub const VECTOR_TIMER: u8 = 32;
pub const VECTOR_KEYBOARD: u8 = 33;
pub const VECTOR_CASCADE: u8 = 34;
pub const VECTOR_COM2: u8 = 35;
pub const VECTOR_COM1: u8 = 36;
pub const VECTOR_LPT2: u8 = 37;
pub const VECTOR_FLOPPY: u8 = 38;
pub const VECTOR_LPT1: u8 = 39;
pub const VECTOR_RTC: u8 = 40;
pub const VECTOR_FREE_9: u8 = 41;
pub const VECTOR_FREE_10: u8 = 42;
pub const VECTOR_FREE_11: u8 = 43;
pub const VECTOR_MOUSE: u8 = 44;
pub const VECTOR_FPU: u8 = 45;
pub const VECTOR_PRIMARY_ATA: u8 = 46;
pub const VECTOR_SECONDARY_ATA: u8 = 47;

pub const VECTOR_SYSCALL: u8 = 0x80;

pub const VECTOR_APIC_SPURIOUS: u8 = 0xFF;
pub const VECTOR_APIC_ERROR: u8 = 0xFE;
pub const VECTOR_APIC_THERMAL: u8 = 0xFD;
pub const VECTOR_APIC_PERFORMANCE: u8 = 0xFC;
pub const VECTOR_APIC_LINT0: u8 = 0xFB;
pub const VECTOR_APIC_LINT1: u8 = 0xFA;

pub const EXCEPTION_VECTOR_START: u8 = 0;
pub const EXCEPTION_VECTOR_END: u8 = 31;
pub const IRQ_VECTOR_START: u8 = 32;
pub const IRQ_VECTOR_END: u8 = 47;
pub const USER_VECTOR_START: u8 = 48;
pub const USER_VECTOR_END: u8 = 0xEF;

#[inline]
pub const fn is_exception(vector: u8) -> bool {
    vector <= EXCEPTION_VECTOR_END
}

#[inline]
pub const fn is_irq(vector: u8) -> bool {
    vector >= IRQ_VECTOR_START && vector <= IRQ_VECTOR_END
}

#[inline]
pub const fn is_user_allocatable(vector: u8) -> bool {
    vector >= USER_VECTOR_START && vector <= USER_VECTOR_END
}

#[inline]
pub const fn irq_to_vector(irq: u8) -> u8 {
    IRQ_VECTOR_START + irq
}

#[inline]
pub const fn vector_to_irq(vector: u8) -> Option<u8> {
    if is_irq(vector) {
        Some(vector - IRQ_VECTOR_START)
    } else {
        None
    }
}

pub const fn exception_name(vector: u8) -> &'static str {
    match vector {
        VECTOR_DIVIDE_ERROR => "Divide Error",
        VECTOR_DEBUG => "Debug",
        VECTOR_NMI => "Non-Maskable Interrupt",
        VECTOR_BREAKPOINT => "Breakpoint",
        VECTOR_OVERFLOW => "Overflow",
        VECTOR_BOUND_RANGE => "Bound Range Exceeded",
        VECTOR_INVALID_OPCODE => "Invalid Opcode",
        VECTOR_DEVICE_NOT_AVAILABLE => "Device Not Available",
        VECTOR_DOUBLE_FAULT => "Double Fault",
        VECTOR_COPROCESSOR_SEGMENT => "Coprocessor Segment Overrun",
        VECTOR_INVALID_TSS => "Invalid TSS",
        VECTOR_SEGMENT_NOT_PRESENT => "Segment Not Present",
        VECTOR_STACK_SEGMENT_FAULT => "Stack-Segment Fault",
        VECTOR_GENERAL_PROTECTION => "General Protection Fault",
        VECTOR_PAGE_FAULT => "Page Fault",
        VECTOR_X87_FLOATING_POINT => "x87 Floating-Point Exception",
        VECTOR_ALIGNMENT_CHECK => "Alignment Check",
        VECTOR_MACHINE_CHECK => "Machine Check",
        VECTOR_SIMD_FLOATING_POINT => "SIMD Floating-Point Exception",
        VECTOR_VIRTUALIZATION => "Virtualization Exception",
        VECTOR_CONTROL_PROTECTION => "Control Protection Exception",
        _ => "Reserved",
    }
}

pub const fn exception_has_error_code(vector: u8) -> bool {
    matches!(
        vector,
        VECTOR_DOUBLE_FAULT
            | VECTOR_INVALID_TSS
            | VECTOR_SEGMENT_NOT_PRESENT
            | VECTOR_STACK_SEGMENT_FAULT
            | VECTOR_GENERAL_PROTECTION
            | VECTOR_PAGE_FAULT
            | VECTOR_ALIGNMENT_CHECK
            | VECTOR_CONTROL_PROTECTION
    )
}

pub const fn exception_is_fatal(vector: u8) -> bool {
    matches!(
        vector,
        VECTOR_DIVIDE_ERROR
            | VECTOR_INVALID_OPCODE
            | VECTOR_DOUBLE_FAULT
            | VECTOR_GENERAL_PROTECTION
            | VECTOR_MACHINE_CHECK
    )
}
