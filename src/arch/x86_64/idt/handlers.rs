// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::arch::asm;
use core::sync::atomic::Ordering;

use crate::arch::x86_64::idt::constants::*;
use crate::arch::x86_64::idt::entry::{InterruptFrame, PageFaultError};
use crate::arch::x86_64::idt::state::*;

macro_rules! exception_stub_no_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub(crate) unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push 0",
                "push {}",
                "jmp interrupt_common",
                const $vector,
            );
        }
    };
}

macro_rules! exception_stub_with_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub(crate) unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push {}",
                "jmp interrupt_common",
                const $vector,
            );
        }
    };
}

macro_rules! irq_stub {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub(crate) unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push 0",
                "push {}",
                "jmp interrupt_common",
                const $vector,
            );
        }
    };
}

exception_stub_no_error!(isr_divide_error, 0);
exception_stub_no_error!(isr_debug, 1);
exception_stub_no_error!(isr_nmi, 2);
exception_stub_no_error!(isr_breakpoint, 3);
exception_stub_no_error!(isr_overflow, 4);
exception_stub_no_error!(isr_bound_range, 5);
exception_stub_no_error!(isr_invalid_opcode, 6);
exception_stub_no_error!(isr_device_not_available, 7);
exception_stub_with_error!(isr_double_fault, 8);
exception_stub_no_error!(isr_coprocessor_segment, 9);
exception_stub_with_error!(isr_invalid_tss, 10);
exception_stub_with_error!(isr_segment_not_present, 11);
exception_stub_with_error!(isr_stack_segment, 12);
exception_stub_with_error!(isr_general_protection, 13);
exception_stub_with_error!(isr_page_fault, 14);
exception_stub_no_error!(isr_reserved_15, 15);
exception_stub_no_error!(isr_x87_fp, 16);
exception_stub_with_error!(isr_alignment_check, 17);
exception_stub_no_error!(isr_machine_check, 18);
exception_stub_no_error!(isr_simd_fp, 19);
exception_stub_no_error!(isr_virtualization, 20);
exception_stub_with_error!(isr_control_protection, 21);
exception_stub_no_error!(isr_reserved_22, 22);
exception_stub_no_error!(isr_reserved_23, 23);
exception_stub_no_error!(isr_reserved_24, 24);
exception_stub_no_error!(isr_reserved_25, 25);
exception_stub_no_error!(isr_reserved_26, 26);
exception_stub_no_error!(isr_reserved_27, 27);
exception_stub_no_error!(isr_reserved_28, 28);
exception_stub_no_error!(isr_reserved_29, 29);
exception_stub_no_error!(isr_reserved_30, 30);
exception_stub_no_error!(isr_reserved_31, 31);

irq_stub!(isr_irq0, 32);
irq_stub!(isr_irq1, 33);
irq_stub!(isr_irq2, 34);
irq_stub!(isr_irq3, 35);
irq_stub!(isr_irq4, 36);
irq_stub!(isr_irq5, 37);
irq_stub!(isr_irq6, 38);
irq_stub!(isr_irq7, 39);
irq_stub!(isr_irq8, 40);
irq_stub!(isr_irq9, 41);
irq_stub!(isr_irq10, 42);
irq_stub!(isr_irq11, 43);
irq_stub!(isr_irq12, 44);
irq_stub!(isr_irq13, 45);
irq_stub!(isr_irq14, 46);
irq_stub!(isr_irq15, 47);

irq_stub!(isr_generic_48, 48);
irq_stub!(isr_syscall, 0x80);

#[unsafe(naked)]
#[no_mangle]
unsafe extern "C" fn interrupt_common() {
    core::arch::naked_asm!(
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov ax, ds",
        "push rax",
        "mov ax, 0x10",
        "mov ds, ax",
        "mov es, ax",
        "mov rdi, rsp",
        "call interrupt_dispatch",
        "pop rax",
        "mov ds, ax",
        "mov es, ax",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "add rsp, 16",
        "iretq",
    );
}

#[no_mangle]
extern "C" fn interrupt_dispatch(frame: &mut InterruptFrame) {
    let vector = frame.vector as usize;

    if vector < IDT_ENTRIES {
        INTERRUPT_COUNTS[vector].fetch_add(1, Ordering::Relaxed);
    }
    TOTAL_INTERRUPTS.fetch_add(1, Ordering::Relaxed);

    if vector < 32 {
        EXCEPTION_COUNT.fetch_add(1, Ordering::Relaxed);
        handle_exception(frame);
    } else if vector < 48 {
        IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
        handle_irq(frame);
    } else if vector == 0x80 {
        handle_syscall(frame);
    } else {
        handle_other(frame);
    }
}

fn handle_exception(frame: &mut InterruptFrame) {
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

fn handle_irq(frame: &mut InterruptFrame) {
    let irq = (frame.vector as u8) - IRQ_BASE;

    // SAFETY: IRQ_HANDLERS is only written during initialization.
    unsafe {
        if let Some(handler) = IRQ_HANDLERS[irq as usize] {
            handler(irq);
        }
    }

    send_eoi(irq);
}

fn handle_syscall(frame: &mut InterruptFrame) {
    // SAFETY: SYSCALL_HANDLER is only written during initialization.
    unsafe {
        if let Some(handler) = SYSCALL_HANDLER {
            handler(frame);
        }
    }
}

fn handle_other(frame: &mut InterruptFrame) {
    let vector = frame.vector as u8;

    // SAFETY: OTHER_HANDLERS is only written during initialization.
    unsafe {
        if let Some(handler) = OTHER_HANDLERS[vector as usize] {
            handler(frame);
        }
    }
}

#[inline]
fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: Reading CR2 is safe and does not modify system state.
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

fn exception_panic(_name: &str, _frame: &InterruptFrame) -> ! {
    // SAFETY: Disabling interrupts before halt.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }

    loop {
        // SAFETY: Halting the CPU in an infinite loop.
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

fn exception_panic_with_cr2(
    _name: &str,
    _frame: &InterruptFrame,
    _cr2: u64,
    _error: PageFaultError,
) -> ! {
    // SAFETY: Disabling interrupts before halt.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }

    loop {
        // SAFETY: Halting the CPU in an infinite loop.
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

pub(crate) fn send_eoi(irq: u8) {
    // SAFETY: Writing to PIC ports to signal end of interrupt.
    unsafe {
        if irq >= 8 {
            outb(PIC2_COMMAND, PIC_EOI);
        }
        outb(PIC1_COMMAND, PIC_EOI);
    }
}

#[inline]
pub(crate) unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Caller ensures port access is valid.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
pub(crate) unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller ensures port access is valid.
    unsafe {
        let value: u8;
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
        value
    }
}

#[inline]
pub(crate) fn io_wait() {
    // SAFETY: Writing to port 0x80 is a standard I/O delay technique.
    unsafe {
        outb(0x80, 0);
    }
}

pub(crate) use isr_divide_error as isr_0;
pub(crate) use isr_debug as isr_1;
pub(crate) use isr_nmi as isr_2;
pub(crate) use isr_breakpoint as isr_3;
pub(crate) use isr_overflow as isr_4;
pub(crate) use isr_bound_range as isr_5;
pub(crate) use isr_invalid_opcode as isr_6;
pub(crate) use isr_device_not_available as isr_7;
pub(crate) use isr_double_fault as isr_8;
pub(crate) use isr_coprocessor_segment as isr_9;
pub(crate) use isr_invalid_tss as isr_10;
pub(crate) use isr_segment_not_present as isr_11;
pub(crate) use isr_stack_segment as isr_12;
pub(crate) use isr_general_protection as isr_13;
pub(crate) use isr_page_fault as isr_14;
pub(crate) use isr_reserved_15 as isr_15;
pub(crate) use isr_x87_fp as isr_16;
pub(crate) use isr_alignment_check as isr_17;
pub(crate) use isr_machine_check as isr_18;
pub(crate) use isr_simd_fp as isr_19;
pub(crate) use isr_virtualization as isr_20;
pub(crate) use isr_control_protection as isr_21;
pub(crate) use isr_reserved_22 as isr_22;
pub(crate) use isr_reserved_23 as isr_23;
pub(crate) use isr_reserved_24 as isr_24;
pub(crate) use isr_reserved_25 as isr_25;
pub(crate) use isr_reserved_26 as isr_26;
pub(crate) use isr_reserved_27 as isr_27;
pub(crate) use isr_reserved_28 as isr_28;
pub(crate) use isr_reserved_29 as isr_29;
pub(crate) use isr_reserved_30 as isr_30;
pub(crate) use isr_reserved_31 as isr_31;
pub(crate) use isr_irq0 as isr_32;
pub(crate) use isr_irq1 as isr_33;
pub(crate) use isr_irq2 as isr_34;
pub(crate) use isr_irq3 as isr_35;
pub(crate) use isr_irq4 as isr_36;
pub(crate) use isr_irq5 as isr_37;
pub(crate) use isr_irq6 as isr_38;
pub(crate) use isr_irq7 as isr_39;
pub(crate) use isr_irq8 as isr_40;
pub(crate) use isr_irq9 as isr_41;
pub(crate) use isr_irq10 as isr_42;
pub(crate) use isr_irq11 as isr_43;
pub(crate) use isr_irq12 as isr_44;
pub(crate) use isr_irq13 as isr_45;
pub(crate) use isr_irq14 as isr_46;
pub(crate) use isr_irq15 as isr_47;
