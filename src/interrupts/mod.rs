//! Interrupt Management

pub mod nonos_handlers;
pub mod nonos_pic;
pub mod nonos_apic;
pub mod nonos_timer;
pub mod nonos_allocation;

// Re-exports compatibility
pub use nonos_handlers as handlers;
pub use nonos_pic as pic;
pub use nonos_apic as apic;
pub use nonos_timer as timer;
pub use nonos_allocation as allocation;

use core::sync::atomic::{AtomicU64, Ordering};
use lazy_static::lazy_static;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::VirtAddr;
use x86_64::PrivilegeLevel;

use crate::arch::x86_64::gdt;

// Public helpers from allocation
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

// -----------------------------
// x86-interrupt trampolines
// -----------------------------

// Exceptions without error code
extern "x86-interrupt" fn isr_divide_error(frame: InterruptStackFrame) {
    nonos_handlers::divide_by_zero_handler(frame);
    INTERRUPT_STATS.exceptions.fetch_add(1, Ordering::Relaxed);
}
extern "x86-interrupt" fn isr_debug(frame: InterruptStackFrame) {
    nonos_handlers::debug_handler(frame);
}
extern "x86-interrupt" fn isr_nmi(frame: InterruptStackFrame) {
    nonos_handlers::nmi_handler(frame);
}
extern "x86-interrupt" fn isr_breakpoint(frame: InterruptStackFrame) {
    nonos_handlers::breakpoint_handler(frame);
}
extern "x86-interrupt" fn isr_overflow(frame: InterruptStackFrame) {
    nonos_handlers::overflow_handler(frame);
}
extern "x86-interrupt" fn isr_bound_range(frame: InterruptStackFrame) {
    nonos_handlers::bound_range_exceeded_handler(frame);
}
extern "x86-interrupt" fn isr_invalid_opcode(frame: InterruptStackFrame) {
    nonos_handlers::invalid_opcode_handler(frame);
}
extern "x86-interrupt" fn isr_device_na(frame: InterruptStackFrame) {
    nonos_handlers::device_not_available_handler(frame);
}
extern "x86-interrupt" fn isr_x87_fp(frame: InterruptStackFrame) {
    nonos_handlers::x87_floating_point_handler(frame);
}
extern "x86-interrupt" fn isr_alignment_check(frame: InterruptStackFrame, code: u64) {
    nonos_handlers::alignment_check_handler(frame);
}
extern "x86-interrupt" fn isr_simd_fp(frame: InterruptStackFrame) {
    nonos_handlers::simd_floating_point_handler(frame);
}
extern "x86-interrupt" fn isr_virtualization(frame: InterruptStackFrame) {
    nonos_handlers::virtualization_handler(frame);
}
extern "x86-interrupt" fn isr_machine_check(frame: InterruptStackFrame) {
    nonos_handlers::machine_check_handler(frame);
    loop { x86_64::instructions::hlt(); }
}

// Exceptions with error code
extern "x86-interrupt" fn isr_double_fault(frame: InterruptStackFrame, code: u64) {
    let _ = code;
    nonos_handlers::double_fault_handler(frame, code);
    loop { x86_64::instructions::hlt(); }
}
extern "x86-interrupt" fn isr_invalid_tss(frame: InterruptStackFrame, code: u64) {
    nonos_handlers::invalid_tss_handler(frame, code);
}
extern "x86-interrupt" fn isr_segment_not_present(frame: InterruptStackFrame, code: u64) {
    nonos_handlers::segment_not_present_handler(frame, code);
}
extern "x86-interrupt" fn isr_stack_segment_fault(frame: InterruptStackFrame, code: u64) {
    nonos_handlers::stack_segment_fault_handler(frame, code);
}
extern "x86-interrupt" fn isr_gpf(frame: InterruptStackFrame, code: u64) {
    nonos_handlers::general_protection_fault_handler(frame, code);
}
extern "x86-interrupt" fn isr_page_fault(frame: InterruptStackFrame, code: PageFaultErrorCode) {
    nonos_handlers::page_fault_handler(frame, code.bits());
}

// Hardware IRQs
extern "x86-interrupt" fn irq_timer(_frame: InterruptStackFrame) {
    nonos_handlers::timer_interrupt_handler();
}
extern "x86-interrupt" fn irq_keyboard(_frame: InterruptStackFrame) {
    nonos_handlers::keyboard_interrupt_handler();
}

// Syscall gate (INT 0x80 from Ring3)
extern "x86-interrupt" fn irq_syscall(_frame: InterruptStackFrame) {
    nonos_handlers::syscall_handler();
}

// -----------------------------
// IDT construction
// -----------------------------

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();

        // CPU Exceptions
        idt.divide_error.set_handler_fn(isr_divide_error);
        idt.debug.set_handler_fn(isr_debug);
        unsafe {
            idt.non_maskable_interrupt
                .set_handler_fn(isr_nmi)
                .set_stack_index(gdt::NMI_IST_INDEX);
        }
        idt.breakpoint.set_handler_fn(isr_breakpoint);
        idt.overflow.set_handler_fn(isr_overflow);
        idt.bound_range_exceeded.set_handler_fn(isr_bound_range);
        idt.invalid_opcode.set_handler_fn(isr_invalid_opcode);
        idt.device_not_available.set_handler_fn(isr_device_na);
        unsafe {
            idt.double_fault
                .set_handler_addr(VirtAddr::new(isr_double_fault as *const () as u64))
                .set_stack_index(gdt::DF_IST_INDEX);
        }
        idt.invalid_tss.set_handler_fn(isr_invalid_tss);
        idt.segment_not_present.set_handler_fn(isr_segment_not_present);
        idt.stack_segment_fault.set_handler_fn(isr_stack_segment_fault);
        idt.general_protection_fault.set_handler_fn(isr_gpf);
        unsafe {
            idt.page_fault
                .set_handler_fn(isr_page_fault)
                .set_stack_index(gdt::PF_IST_INDEX);
        }
        idt.x87_floating_point.set_handler_fn(isr_x87_fp);
        idt.alignment_check.set_handler_fn(isr_alignment_check);
        unsafe {
            idt.machine_check
                .set_handler_addr(VirtAddr::new(isr_machine_check as *const () as u64))
                .set_stack_index(gdt::MC_IST_INDEX);
        }
        idt.simd_floating_point.set_handler_fn(isr_simd_fp);
        idt.virtualization.set_handler_fn(isr_virtualization);

        // Hardware Interrupts
        idt[TIMER_INTERRUPT_ID as usize].set_handler_fn(irq_timer);
        idt[KEYBOARD_INTERRUPT_ID as usize].set_handler_fn(irq_keyboard);

        // Syscall interface (Ring3)
        idt[SYSCALL_INTERRUPT_ID as usize]
            .set_handler_fn(irq_syscall)
            .set_privilege_level(PrivilegeLevel::Ring3);

        idt
    };
}

/// Initialize interrupt system:
pub fn init() {
    nonos_pic::init();
    nonos_timer::init(); // install tick hook storage
    IDT.load();
    x86_64::instructions::interrupts::enable();
    crate::log::logger::log_critical("Interrupt system initialized");
}

/// Initialize just the IDT without enabling interrupts
pub fn init_idt() {
    IDT.load();
}

/// Snapshot interrupt statistics
pub fn get_stats() -> (u64, u64, u64, u64) {
    (
        INTERRUPT_STATS.timer_ticks.load(Ordering::Relaxed),
        INTERRUPT_STATS.keyboard_presses.load(Ordering::Relaxed),
        INTERRUPT_STATS.syscalls.load(Ordering::Relaxed),
        INTERRUPT_STATS.exceptions.load(Ordering::Relaxed),
    )
}

/// ISRs handle work inline
pub fn process_interrupt_queue() {}
