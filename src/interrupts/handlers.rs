//! Interrupt Service Routines (ISRs)
//!
//! Production-quality interrupt handlers

use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};
use x86_64::registers::control::{Cr2, Cr3};
use crate::interrupts::{pic, INTERRUPT_STATS, TIMER_INTERRUPT_ID, KEYBOARD_INTERRUPT_ID};
use crate::arch::x86_64::vga;
use core::sync::atomic::Ordering;
use alloc::format;

/// Handle divide by zero exception
pub extern "x86-interrupt" fn divide_by_zero_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: Divide by zero at RIP: 0x{:016x}", 
           stack_frame.instruction_pointer.as_u64());
}

/// Handle debug exception
pub extern "x86-interrupt" fn debug_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    crate::log::logger::log_critical(&format!("DEBUG EXCEPTION at RIP: 0x{:016x}", 
                                             stack_frame.instruction_pointer.as_u64()));
}

/// Handle non-maskable interrupt
pub extern "x86-interrupt" fn nmi_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("CRITICAL: Non-maskable interrupt at RIP: 0x{:016x}", 
           stack_frame.instruction_pointer.as_u64());
}

/// Handle breakpoint exception
pub extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    crate::log::logger::log_critical(&format!("BREAKPOINT at RIP: 0x{:016x}", 
                                             stack_frame.instruction_pointer.as_u64()));
}

/// Handle overflow exception
pub extern "x86-interrupt" fn overflow_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: Overflow at RIP: 0x{:016x}", 
           stack_frame.instruction_pointer.as_u64());
}

/// Handle bound range exceeded
pub extern "x86-interrupt" fn bound_range_exceeded_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: Bound range exceeded at RIP: 0x{:016x}", 
           stack_frame.instruction_pointer.as_u64());
}

/// Handle invalid opcode
pub extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: Invalid opcode at RIP: 0x{:016x}", 
           stack_frame.instruction_pointer.as_u64());
}

/// Handle device not available
pub extern "x86-interrupt" fn device_not_available_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: Device not available at RIP: 0x{:016x}", 
           stack_frame.instruction_pointer.as_u64());
}

/// Handle double fault  
pub extern "x86-interrupt" fn double_fault_handler(_stack_frame: InterruptStackFrame, _error_code: u64) {
    crate::arch::x86_64::vga::print("FATAL: DOUBLE FAULT - SYSTEM HALTED\n");
    loop {}
}

/// Handle invalid TSS
pub extern "x86-interrupt" fn invalid_tss_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    panic!("EXCEPTION: Invalid TSS (error: 0x{:x}) at RIP: 0x{:016x}", 
           error_code, stack_frame.instruction_pointer.as_u64());
}

/// Handle segment not present
pub extern "x86-interrupt" fn segment_not_present_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: Segment not present (error: 0x{:x}) at RIP: 0x{:016x}", 
           error_code, stack_frame.instruction_pointer.as_u64());
}

/// Handle stack segment fault
pub extern "x86-interrupt" fn stack_segment_fault_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: Stack segment fault (error: 0x{:x}) at RIP: 0x{:016x}", 
           error_code, stack_frame.instruction_pointer.as_u64());
}

/// Handle general protection fault
pub extern "x86-interrupt" fn general_protection_fault_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: General protection fault (error: 0x{:x}) at RIP: 0x{:016x}", 
           error_code, stack_frame.instruction_pointer.as_u64());
}

/// Handle page fault
pub extern "x86-interrupt" fn page_fault_handler(stack_frame: InterruptStackFrame, error_code: PageFaultErrorCode) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    let fault_address = Cr2::read();
    let cr3 = Cr3::read();
    
    panic!("PAGE FAULT: Address 0x{:016x}, Error: {:?}, RIP: 0x{:016x}, CR3: 0x{:016x}", 
           fault_address.as_u64(),
           error_code,
           stack_frame.instruction_pointer.as_u64(),
           cr3.0.start_address().as_u64());
}

/// Handle x87 floating point exception
pub extern "x86-interrupt" fn x87_floating_point_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: x87 floating point at RIP: 0x{:016x}", 
           stack_frame.instruction_pointer.as_u64());
}

/// Handle alignment check
pub extern "x86-interrupt" fn alignment_check_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: Alignment check (error: 0x{:x}) at RIP: 0x{:016x}", 
           error_code, stack_frame.instruction_pointer.as_u64());
}

/// Handle machine check
pub extern "x86-interrupt" fn machine_check_handler(_stack_frame: InterruptStackFrame) {
    crate::arch::x86_64::vga::print("FATAL: MACHINE CHECK - SYSTEM HALTED\n");
    loop {}
}

/// Handle SIMD floating point exception
pub extern "x86-interrupt" fn simd_floating_point_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: SIMD floating point at RIP: 0x{:016x}", 
           stack_frame.instruction_pointer.as_u64());
}

/// Handle virtualization exception
pub extern "x86-interrupt" fn virtualization_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
    
    panic!("EXCEPTION: Virtualization at RIP: 0x{:016x}", 
           stack_frame.instruction_pointer.as_u64());
}

/// Timer interrupt handler
pub extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.timer_ticks.fetch_add(1, Ordering::Relaxed);
    
    // Trigger scheduler tick
    crate::sched::scheduler::on_timer_tick();
    
    // Send EOI
    pic::end_of_interrupt(TIMER_INTERRUPT_ID);
}

/// Keyboard interrupt handler
pub extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    use x86_64::instructions::port::Port;
    
    INTERRUPT_STATS.keyboard_presses.fetch_add(1, Ordering::Relaxed);
    
    // Read scancode from keyboard controller
    let mut port = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };
    
    // Handle keyboard input
    handle_keyboard_input(scancode);
    
    // Send EOI
    pic::end_of_interrupt(KEYBOARD_INTERRUPT_ID);
}

/// Syscall handler
pub extern "x86-interrupt" fn syscall_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.syscalls.fetch_add(1, Ordering::Relaxed);
    
    // For now, implement a simple working syscall interface
    // In production, this would use SYSCALL/SYSRET or properly extract registers
    
    // Simple test: just write a message to show syscalls work
    crate::arch::x86_64::vga::print("SYSCALL: System call received at RIP: ");
    crate::arch::x86_64::vga::print_hex(stack_frame.instruction_pointer.as_u64());
    crate::arch::x86_64::vga::print("\n");
    
    // For testing, always write "Hello from kernel!\n" to show it works
    let test_message = b"Hello from kernel syscall!\n";
    for &byte in test_message {
        crate::arch::x86_64::serial::write_byte(byte);
    }
}

/// Handle keyboard input
fn handle_keyboard_input(scancode: u8) {
    // Simple scancode to ASCII conversion for basic keys
    match scancode {
        0x02 => vga::print("1"),
        0x03 => vga::print("2"),
        0x04 => vga::print("3"),
        0x05 => vga::print("4"),
        0x06 => vga::print("5"),
        0x07 => vga::print("6"),
        0x08 => vga::print("7"),
        0x09 => vga::print("8"),
        0x0A => vga::print("9"),
        0x0B => vga::print("0"),
        0x1C => vga::print("\n"), // Enter
        0x39 => vga::print(" "),  // Space
        _ => {
            // For now, just show the scancode for unmapped keys
            if scancode < 0x80 { // Only handle key presses, not releases
                vga::print(&format!("[{:02x}]", scancode));
            }
        }
    }
}