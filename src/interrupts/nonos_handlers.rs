//! Primary ISR/exception handlers

#![no_std]

use x86_64::registers::control::Cr2;
use x86_64::structures::idt::InterruptStackFrame;
use x86_64::instructions::port::Port;

use super::{apic, pic, timer};
use super::INTERRUPT_STATS;

// Legacy 8259 PIC lines for IRQ0 (timer), IRQ1 (keyboard)
const TIMER_IRQ_LINE: u8 = 0;
const KEYBOARD_IRQ_LINE: u8 = 1;

// -----------------------------
// Diagnostics
// -----------------------------

#[inline]
fn log_exception(name: &str, frame: &InterruptStackFrame) {
    crate::log::logger::log_critical(
        "{}: rip={:#x} cs={:?} rsp={:#x} rflags={:#x}",
        name,
        frame.instruction_pointer.as_u64(),
        frame.code_segment,
        frame.stack_pointer.as_u64(),
        frame.cpu_flags
    );
}

#[inline]
fn log_page_fault(frame: &InterruptStackFrame, code: u64) {
    let addr = Cr2::read().as_u64();
    crate::log::logger::log_critical(
        "PAGE FAULT: addr={:#x} err={:#x} rip={:#x} rsp={:#x} rflags={:#x}",
        addr,
        code,
        frame.instruction_pointer.as_u64(),
        frame.stack_pointer.as_u64(),
        frame.cpu_flags
    );
}

// -----------------------------
// Exceptions (no error code)
// -----------------------------

pub fn divide_by_zero_handler(frame: InterruptStackFrame) {
    log_exception("DIVIDE ERROR", &frame);
    unsafe { halt_loop() }
}

pub fn debug_handler(_frame: InterruptStackFrame) {
    // Non-fatal trace
}

pub fn nmi_handler(frame: InterruptStackFrame) {
    log_exception("NMI", &frame);
}

pub fn breakpoint_handler(_frame: InterruptStackFrame) {
    crate::log::logger::log_info!("BREAKPOINT");
}

pub fn overflow_handler(frame: InterruptStackFrame) {
    log_exception("OVERFLOW", &frame);
}

pub fn bound_range_exceeded_handler(frame: InterruptStackFrame) {
    log_exception("BOUND RANGE", &frame);
}

pub fn invalid_opcode_handler(frame: InterruptStackFrame) {
    log_exception("INVALID OPCODE", &frame);
    unsafe { halt_loop() }
}

pub fn device_not_available_handler(frame: InterruptStackFrame) {
    log_exception("DEVICE NOT AVAILABLE", &frame);
}

pub fn x87_floating_point_handler(_frame: InterruptStackFrame) {
    // Lazy FPU handling would go here
}

pub fn alignment_check_handler(frame: InterruptStackFrame) {
    log_exception("ALIGNMENT CHECK", &frame);
}

pub fn simd_floating_point_handler(_frame: InterruptStackFrame) {
    // SSE/AVX exception
}

pub fn virtualization_handler(frame: InterruptStackFrame) {
    log_exception("VIRTUALIZATION", &frame);
}

pub fn machine_check_handler(frame: InterruptStackFrame) -> ! {
    log_exception("MACHINE CHECK", &frame);
    unsafe { halt_loop() }
}

// -----------------------------
// Exceptions (with error code)
// -----------------------------

pub fn double_fault_handler(frame: InterruptStackFrame, _code: u64) -> ! {
    log_exception("DOUBLE FAULT", &frame);
    unsafe { halt_loop() }
}

pub fn invalid_tss_handler(frame: InterruptStackFrame, code: u64) {
    log_exception("INVALID TSS", &frame);
    crate::log::logger::log_error!("err={:#x}", code);
}

pub fn segment_not_present_handler(frame: InterruptStackFrame, code: u64) {
    log_exception("SEGMENT NOT PRESENT", &frame);
    crate::log::logger::log_error!("err={:#x}", code);
}

pub fn stack_segment_fault_handler(frame: InterruptStackFrame, code: u64) {
    log_exception("STACK SEGMENT FAULT", &frame);
    crate::log::logger::log_error!("err={:#x}", code);
}

pub fn general_protection_fault_handler(frame: InterruptStackFrame, code: u64) {
    log_exception("GENERAL PROTECTION FAULT", &frame);
    crate::log::logger::log_error!("err={:#x}", code);
    unsafe { halt_loop() }
}

pub fn page_fault_handler(frame: InterruptStackFrame, code: u64) {
    log_page_fault(&frame, code);
    unsafe { halt_loop() }
}

// -----------------------------
// IRQs
// -----------------------------

pub fn timer_interrupt_handler() {
    // Bump counters, run scheduler tick hook, then EOI
    INTERRUPT_STATS
        .timer_ticks
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    timer::on_timer_interrupt();

    if apic::is_enabled() {
        apic::eoi();
    } else {
        pic::eoi(TIMER_IRQ_LINE);
    }
}

pub fn keyboard_interrupt_handler() {
    // Read scancode to ACK controller; ignore value for now
    unsafe {
        let mut data = Port::<u8>::new(0x60);
        let _ = data.read();
    }
    INTERRUPT_STATS
        .keyboard_presses
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    if apic::is_enabled() {
        apic::eoi();
    } else {
        pic::eoi(KEYBOARD_IRQ_LINE);
    }
}

// Syscall gate (INT 0x80) — counts only; dispatch handled by syscall layer.
pub fn syscall_handler() {
    super::INTERRUPT_STATS
        .syscalls
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

// -----------------------------
// Utils
// -----------------------------

#[inline(always)]
unsafe fn halt_loop() -> ! {
    loop {
        x86_64::instructions::interrupts::disable();
        x86_64::instructions::hlt();
    }
}
