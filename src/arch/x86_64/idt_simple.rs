//! Simple IDT setup for NON-OS kernel

use lazy_static::lazy_static;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        // Skip double fault for now - causes type issues
        // TODO: Fix double fault handler
        idt
    };
}

pub fn init() {
    IDT.load();
}

extern "x86-interrupt" fn breakpoint_handler(_stack_frame: InterruptStackFrame) {
    crate::arch::x86_64::vga::print("EXCEPTION: BREAKPOINT\n");
}

extern "x86-interrupt" fn double_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    crate::arch::x86_64::vga::print("EXCEPTION: DOUBLE FAULT\n");
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
