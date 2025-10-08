//! Production Interrupt Management
//!
//! Complete interrupt handling system for production use

pub mod nonos_handlers;
pub mod nonos_real_handlers;
pub mod nonos_pic;
pub mod nonos_apic;
pub mod nonos_timer;
pub mod nonos_allocation;

// Re-exports for backward compatibility
pub use nonos_handlers as handlers;
pub use nonos_real_handlers as real_handlers;
pub use nonos_pic as pic;
pub use nonos_apic as apic;
pub use nonos_timer as timer;
pub use nonos_allocation as allocation;

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use lazy_static::lazy_static;
use crate::arch::x86_64::gdt;
use core::sync::atomic::{AtomicU64, Ordering};

pub use nonos_allocation::{allocate_vector, register_interrupt_handler, init_interrupt_allocation};

/// System interrupt vectors
pub const TIMER_INTERRUPT_ID: u8 = 32;
pub const KEYBOARD_INTERRUPT_ID: u8 = 33;
pub const SYSCALL_INTERRUPT_ID: u8 = 0x80;

/// Global interrupt statistics
pub struct InterruptStats {
    pub timer_ticks: AtomicU64,
    pub keyboard_presses: AtomicU64,
    pub syscalls: AtomicU64,
    pub exceptions: AtomicU64,
}

pub static INTERRUPT_STATS: InterruptStats = InterruptStats {
    timer_ticks: AtomicU64::new(0),
    keyboard_presses: AtomicU64::new(0),
    syscalls: AtomicU64::new(0),
    exceptions: AtomicU64::new(0),
};

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();

        // CPU Exceptions
        idt.divide_error.set_handler_fn(nonos_handlers::divide_by_zero_handler);
        idt.debug.set_handler_fn(nonos_handlers::debug_handler);
        unsafe {
            idt.non_maskable_interrupt
                .set_handler_fn(nonos_handlers::nmi_handler)
                .set_stack_index(gdt::NMI_IST_INDEX);
        }
        idt.breakpoint.set_handler_fn(nonos_handlers::breakpoint_handler);
        idt.overflow.set_handler_fn(nonos_handlers::overflow_handler);
        idt.bound_range_exceeded.set_handler_fn(nonos_handlers::bound_range_exceeded_handler);
        idt.invalid_opcode.set_handler_fn(nonos_handlers::invalid_opcode_handler);
        idt.device_not_available.set_handler_fn(nonos_handlers::device_not_available_handler);
        unsafe {
            let handler: extern "x86-interrupt" fn(InterruptStackFrame, u64) -> ! = core::mem::transmute(nonos_handlers::double_fault_handler as *const ());
            idt.double_fault.set_handler_fn(handler).set_stack_index(gdt::DF_IST_INDEX);
        }
        idt.invalid_tss.set_handler_fn(nonos_handlers::invalid_tss_handler);
        idt.segment_not_present.set_handler_fn(nonos_handlers::segment_not_present_handler);
        idt.stack_segment_fault.set_handler_fn(nonos_handlers::stack_segment_fault_handler);
        idt.general_protection_fault.set_handler_fn(nonos_handlers::general_protection_fault_handler);
        unsafe {
            idt.page_fault
                .set_handler_fn(nonos_handlers::page_fault_handler)
                .set_stack_index(gdt::PF_IST_INDEX);
        }
        idt.x87_floating_point.set_handler_fn(nonos_handlers::x87_floating_point_handler);
        idt.alignment_check.set_handler_fn(nonos_handlers::alignment_check_handler);
        unsafe {
            let handler: extern "x86-interrupt" fn(InterruptStackFrame) -> ! = core::mem::transmute(nonos_handlers::machine_check_handler as *const ());
            idt.machine_check.set_handler_fn(handler).set_stack_index(gdt::MC_IST_INDEX);
        }
        idt.simd_floating_point.set_handler_fn(nonos_handlers::simd_floating_point_handler);
        idt.virtualization.set_handler_fn(nonos_handlers::virtualization_handler);

        // Hardware Interrupts
        idt[TIMER_INTERRUPT_ID as usize].set_handler_fn(nonos_handlers::timer_interrupt_handler);
        idt[KEYBOARD_INTERRUPT_ID as usize].set_handler_fn(nonos_handlers::keyboard_interrupt_handler);

        // Syscall interface
        idt[SYSCALL_INTERRUPT_ID as usize]
            .set_handler_fn(nonos_handlers::syscall_handler)
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);

        idt
    };
}

/// Initialize interrupt system
pub fn init() {
    nonos_pic::init();           // Initialize PIC
    IDT.load();           // Load IDT
    
    x86_64::instructions::interrupts::enable();
    
    crate::log::logger::log_critical("Interrupt system initialized");
}

/// Initialize just the IDT without enabling interrupts
pub fn init_idt() {
    IDT.load();
}


/// Get interrupt statistics
pub fn get_stats() -> (u64, u64, u64, u64) {
    (
        INTERRUPT_STATS.timer_ticks.load(Ordering::Relaxed),
        INTERRUPT_STATS.keyboard_presses.load(Ordering::Relaxed),
        INTERRUPT_STATS.syscalls.load(Ordering::Relaxed),
        INTERRUPT_STATS.exceptions.load(Ordering::Relaxed),
    )
}

/// Process interrupt queue (called from main loop)
pub fn process_interrupt_queue() {
    // Process pending interrupts - stub implementation
}