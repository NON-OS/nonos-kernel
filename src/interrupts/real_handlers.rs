//! Real Hardware Interrupt Handlers
//!
//! Production interrupt service routines with proper hardware interaction

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{
    structures::idt::{InterruptStackFrame, PageFaultErrorCode},
    instructions::port::{Port, PortWriteOnly},
};
use crate::arch::x86_64::vga;
// alloc::vec import removed - not used
// alloc::vec::Vec import removed - not used
use alloc::format;

/// Global interrupt statistics
static INTERRUPT_STATS: InterruptStats = InterruptStats {
    timer_interrupts: AtomicU64::new(0),
    keyboard_interrupts: AtomicU64::new(0),
    page_faults: AtomicU64::new(0),
    general_protection_faults: AtomicU64::new(0),
    double_faults: AtomicU64::new(0),
    spurious_interrupts: AtomicU64::new(0),
};

/// System uptime in milliseconds
static mut SYSTEM_UPTIME_MS: AtomicU64 = AtomicU64::new(0);

/// Timer frequency (1000 Hz = 1ms intervals)
const TIMER_FREQUENCY: u32 = 1000;
const PIT_FREQUENCY: u32 = 1193182;

/// Interrupt statistics structure
#[derive(Debug)]
pub struct InterruptStats {
    pub timer_interrupts: AtomicU64,
    pub keyboard_interrupts: AtomicU64,
    pub page_faults: AtomicU64,
    pub general_protection_faults: AtomicU64,
    pub double_faults: AtomicU64,
    pub spurious_interrupts: AtomicU64,
}

/// Real timer interrupt handler (IRQ 0)
pub extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // Update statistics
    INTERRUPT_STATS.timer_interrupts.fetch_add(1, Ordering::Relaxed);
    
    // Update system uptime
    unsafe {
        SYSTEM_UPTIME_MS.fetch_add(1, Ordering::Relaxed);
    }
    
    // Update VDSO time data if available
    if let Some(vdso_manager) = crate::syscall::vdso::get_vdso_manager() {
        vdso_manager.update_time_data();
    }
    
    // Trigger scheduler if quantum expired
    trigger_scheduler_if_needed();
    
    // Send EOI to PIC
    unsafe {
        let mut pic_command = PortWriteOnly::new(0x20);
        pic_command.write(0x20u8); // EOI command
    }
}

/// Real keyboard interrupt handler (IRQ 1)
pub extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.keyboard_interrupts.fetch_add(1, Ordering::Relaxed);
    
    // Read scancode from keyboard controller
    let mut keyboard_port = Port::new(0x60);
    let scancode: u8 = unsafe { keyboard_port.read() };
    
    // Process scancode
    handle_keyboard_scancode(scancode);
    
    // Send EOI to PIC
    unsafe {
        let mut pic_command = PortWriteOnly::new(0x20);
        pic_command.write(0x20u8);
    }
}

/// Real page fault handler
pub extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    INTERRUPT_STATS.page_faults.fetch_add(1, Ordering::Relaxed);
    
    // Get the faulting address from CR2
    let fault_address = x86_64::registers::control::Cr2::read();
    
    // Analyze the page fault
    let is_present = !error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION);
    let is_write = error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
    let is_user = error_code.contains(PageFaultErrorCode::USER_MODE);
    let is_reserved = error_code.contains(PageFaultErrorCode::MALFORMED_TABLE);
    let is_instruction = error_code.contains(PageFaultErrorCode::INSTRUCTION_FETCH);
    
    // Try to handle the page fault
    let handled = handle_page_fault(fault_address, is_present, is_write, is_user, is_instruction);
    
    if !handled {
        // Unhandled page fault - print debug info and halt
        vga::print(&format!("\nPAGE FAULT at 0x{:016X}\n", fault_address.as_u64()));
        vga::print(&format!("Error Code: {:?}\n", error_code));
        vga::print(&format!("RIP: 0x{:016X}\n", stack_frame.instruction_pointer.as_u64()));
        vga::print(&format!("RSP: 0x{:016X}\n", stack_frame.stack_pointer.as_u64()));
        vga::print(&format!("Present: {}, Write: {}, User: {}, Reserved: {}, Instruction: {}\n",
                   is_present, is_write, is_user, is_reserved, is_instruction));
        
        // In production, would handle more gracefully (kill process, etc.)
        panic!("Unhandled page fault");
    }
}

/// Real general protection fault handler  
pub extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.general_protection_faults.fetch_add(1, Ordering::Relaxed);
    
    vga::print(&format!("\nGENERAL PROTECTION FAULT\n"));
    vga::print(&format!("Error Code: 0x{:016X}\n", error_code));
    vga::print(&format!("RIP: 0x{:016X}\n", stack_frame.instruction_pointer.as_u64()));
    vga::print(&format!("RSP: 0x{:016X}\n", stack_frame.stack_pointer.as_u64()));
    vga::print(&format!("RFLAGS: 0x{:016X}\n", stack_frame.cpu_flags));
    
    // Analyze error code
    if error_code != 0 {
        let is_external = (error_code & 0x01) != 0;
        let table = (error_code >> 1) & 0x03;
        let index = (error_code >> 3) & 0x1FFF;
        
        vga::print(&format!("External: {}, Table: {}, Index: 0x{:X}\n", 
                   is_external, table, index));
    }
    
    // In production, would try to recover or kill offending process
    panic!("General protection fault");
}

/// Real double fault handler
pub extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.double_faults.fetch_add(1, Ordering::Relaxed);
    
    vga::print("\nDOUBLE FAULT - SYSTEM CRITICAL ERROR\n");
    vga::print(&format!("Error Code: 0x{:016X}\n", error_code));
    vga::print(&format!("RIP: 0x{:016X}\n", stack_frame.instruction_pointer.as_u64()));
    vga::print(&format!("RSP: 0x{:016X}\n", stack_frame.stack_pointer.as_u64()));
    
    // Double fault is unrecoverable - halt system
    loop {
        unsafe { 
            core::arch::asm!("cli");
            core::arch::asm!("hlt");
        }
    }
}

/// Real breakpoint handler
pub extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    vga::print(&format!("\nBREAKPOINT at 0x{:016X}\n", 
               stack_frame.instruction_pointer.as_u64()));
    
    // In production, would interface with debugger
    // For now, just continue execution
}

/// Invalid opcode handler
pub extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    vga::print(&format!("\nINVALID OPCODE at 0x{:016X}\n", 
               stack_frame.instruction_pointer.as_u64()));
    
    // Print some context around the invalid instruction
    unsafe {
        let code_ptr = stack_frame.instruction_pointer.as_ptr::<u8>();
        vga::print("Code bytes: ");
        for i in 0..16 {
            let byte = core::ptr::read_volatile(code_ptr.offset(i - 8));
            vga::print(&format!("{:02X} ", byte));
        }
        vga::print("\n");
    }
    
    panic!("Invalid opcode");
}

/// Division by zero handler
pub extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    vga::print(&format!("\nDIVISION BY ZERO at 0x{:016X}\n", 
               stack_frame.instruction_pointer.as_u64()));
    
    // In production, would send SIGFPE to process
    panic!("Division by zero");
}

/// Overflow handler
pub extern "x86-interrupt" fn overflow_handler(stack_frame: InterruptStackFrame) {
    vga::print(&format!("\nOVERFLOW at 0x{:016X}\n", 
               stack_frame.instruction_pointer.as_u64()));
    
    // In production, would send SIGFPE to process  
    panic!("Arithmetic overflow");
}

/// Bound range exceeded handler
pub extern "x86-interrupt" fn bound_range_exceeded_handler(stack_frame: InterruptStackFrame) {
    vga::print(&format!("\nBOUND RANGE EXCEEDED at 0x{:016X}\n", 
               stack_frame.instruction_pointer.as_u64()));
    
    panic!("Bound range exceeded");
}

/// Device not available handler (for FPU)
pub extern "x86-interrupt" fn device_not_available_handler(stack_frame: InterruptStackFrame) {
    vga::print(&format!("\nFPU NOT AVAILABLE at 0x{:016X}\n", 
               stack_frame.instruction_pointer.as_u64()));
    
    // Enable FPU for current task
    enable_fpu();
}

/// Spurious interrupt handler (for PIC)
pub extern "x86-interrupt" fn spurious_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.spurious_interrupts.fetch_add(1, Ordering::Relaxed);
    
    // Check if it's a real spurious interrupt
    let mut pic_command = Port::new(0x20);
    unsafe {
        pic_command.write(0x0B); // Read ISR
        let isr: u8 = pic_command.read();
        
        if (isr & 0x80) == 0 {
            // Real spurious interrupt - don't send EOI
            return;
        }
    }
    
    // False alarm - send EOI
    unsafe {
        let mut pic_command = PortWriteOnly::new(0x20);
        pic_command.write(0x20u8);
    }
}

/// Handle keyboard scancode
fn handle_keyboard_scancode(scancode: u8) {
    // Basic scancode-to-character mapping
    let character = match scancode {
        0x02 => Some('1'),
        0x03 => Some('2'),
        0x04 => Some('3'),
        0x05 => Some('4'),
        0x06 => Some('5'),
        0x07 => Some('6'),
        0x08 => Some('7'),
        0x09 => Some('8'),
        0x0A => Some('9'),
        0x0B => Some('0'),
        
        0x10 => Some('q'),
        0x11 => Some('w'),
        0x12 => Some('e'),
        0x13 => Some('r'),
        0x14 => Some('t'),
        0x15 => Some('y'),
        0x16 => Some('u'),
        0x17 => Some('i'),
        0x18 => Some('o'),
        0x19 => Some('p'),
        
        0x1E => Some('a'),
        0x1F => Some('s'),
        0x20 => Some('d'),
        0x21 => Some('f'),
        0x22 => Some('g'),
        0x23 => Some('h'),
        0x24 => Some('j'),
        0x25 => Some('k'),
        0x26 => Some('l'),
        
        0x2C => Some('z'),
        0x2D => Some('x'),
        0x2E => Some('c'),
        0x2F => Some('v'),
        0x30 => Some('b'),
        0x31 => Some('n'),
        0x32 => Some('m'),
        
        0x39 => Some(' '), // Space
        0x1C => Some('\n'), // Enter
        
        _ => None, // Unrecognized or key release
    };
    
    if let Some(ch) = character {
        // Add to keyboard buffer or send to current process
        handle_keyboard_input(ch);
    }
}

/// Handle keyboard character input
fn handle_keyboard_input(ch: char) {
    // For now, just echo to screen for demonstration
    vga::print(&format!("{}", ch));
    
    // In production, would add to input buffer for current process
    // or handle special keys like Ctrl+C, etc.
}

/// Handle page fault - try to resolve it
fn handle_page_fault(
    fault_addr: x86_64::VirtAddr, 
    is_present: bool,
    is_write: bool, 
    is_user: bool,
    _is_instruction: bool
) -> bool {
    let addr = fault_addr.as_u64();
    
    // Handle heap expansion (brk/sbrk)
    if addr >= 0x400000000 && addr < 0x500000000 {
        return handle_heap_page_fault(fault_addr, is_write);
    }
    
    // Handle stack expansion
    if is_user && addr >= 0x700000000 && addr < 0x800000000 {
        return handle_stack_page_fault(fault_addr);
    }
    
    // Handle memory-mapped I/O
    if !is_user && addr >= 0xFFFF800000000000 {
        return handle_mmio_page_fault(fault_addr);
    }
    
    // Copy-on-write handling
    if is_present && is_write {
        return handle_cow_page_fault(fault_addr);
    }
    
    // Swapped page handling (if swap is implemented)
    if !is_present {
        return handle_swapped_page_fault(fault_addr);
    }
    
    false // Unhandled
}

/// Handle heap page fault (expand heap)
fn handle_heap_page_fault(fault_addr: x86_64::VirtAddr, _is_write: bool) -> bool {
    // Allocate a new page for heap
    if let Some(frame) = crate::memory::page_allocator::allocate_frame() {
        let page_addr = x86_64::VirtAddr::new(fault_addr.as_u64() & !0xFFF);
        
        if crate::memory::virtual_memory::map_memory_range(
            page_addr,
            frame.start_address(),
            4096,
            x86_64::structures::paging::PageTableFlags::PRESENT |
            x86_64::structures::paging::PageTableFlags::WRITABLE |
            x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE
        ).is_ok() {
            // Clear the page
            unsafe {
                core::ptr::write_bytes(page_addr.as_mut_ptr::<u8>(), 0, 4096);
            }
            return true;
        }
    }
    false
}

/// Handle stack page fault (expand stack)
fn handle_stack_page_fault(fault_addr: x86_64::VirtAddr) -> bool {
    // Check if within reasonable stack limits (8MB max)
    const MAX_STACK_SIZE: u64 = 8 * 1024 * 1024;
    const STACK_TOP: u64 = 0x800000000;
    
    if fault_addr.as_u64() < STACK_TOP - MAX_STACK_SIZE {
        return false; // Stack too large
    }
    
    // Allocate page for stack expansion
    if let Some(frame) = crate::memory::page_allocator::allocate_frame() {
        let page_addr = x86_64::VirtAddr::new(fault_addr.as_u64() & !0xFFF);
        
        if crate::memory::virtual_memory::map_memory_range(
            page_addr,
            frame.start_address(),
            4096,
            x86_64::structures::paging::PageTableFlags::PRESENT |
            x86_64::structures::paging::PageTableFlags::WRITABLE |
            x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE |
            x86_64::structures::paging::PageTableFlags::NO_EXECUTE
        ).is_ok() {
            return true;
        }
    }
    false
}

/// Handle MMIO page fault
fn handle_mmio_page_fault(_fault_addr: x86_64::VirtAddr) -> bool {
    // Memory-mapped I/O access - might be valid
    // For now, don't handle
    false
}

/// Handle copy-on-write page fault
fn handle_cow_page_fault(fault_addr: x86_64::VirtAddr) -> bool {
    // Check if this is a valid COW page
    if let Some(page_info) = crate::memory::get_page_info(fault_addr) {
        if page_info.flags.contains(crate::memory::PageFlags::COPY_ON_WRITE) {
            // This is a COW page - allocate new physical frame
            if let Some(new_frame) = crate::memory::allocate_frame() {
                // Copy data from original page
                let original_data = unsafe {
                    core::slice::from_raw_parts(
                        fault_addr.as_u64() as *const u8,
                        4096
                    )
                };
                
                // Map new frame temporarily to copy data
                let temp_vaddr = crate::memory::map_temporary_frame(new_frame);
                unsafe {
                    let dest_slice = core::slice::from_raw_parts_mut(
                        temp_vaddr.as_u64() as *mut u8,
                        4096
                    );
                    dest_slice.copy_from_slice(original_data);
                }
                
                // Update page table to point to new frame with write permissions
                crate::memory::update_page_mapping(
                    fault_addr, 
                    new_frame, 
                    (crate::memory::PageFlags::PRESENT | crate::memory::PageFlags::WRITABLE).bits()
                );
                
                // Unmap temporary mapping
                crate::memory::unmap_temporary_frame(temp_vaddr);
                
                crate::log_dbg!("COW page fault handled for address: {:?}", fault_addr);
                return true;
            }
        }
    }
    
    false
}

/// Handle swapped page fault
fn handle_swapped_page_fault(fault_addr: x86_64::VirtAddr) -> bool {
    // Check if this page was swapped out
    if let Some(swap_info) = crate::memory::get_swap_info(fault_addr) {
        // Allocate new physical frame for the page
        if let Some(new_frame) = crate::memory::allocate_frame() {
            // Read page data from swap storage
            let mut page_data = [0u8; 4096];
            
            let swap_slot = crate::storage::swap::SwapSlot {
                device_id: swap_info.swap_device_id,
                slot: swap_info.swap_slot,
            };
            if crate::storage::swap::read_page(swap_slot, &mut page_data).is_ok() {
                // Map the new frame temporarily to load data
                let temp_vaddr = crate::memory::map_temporary_frame(new_frame);
                
                unsafe {
                    let dest_slice = core::slice::from_raw_parts_mut(
                        temp_vaddr.as_u64() as *mut u8,
                        4096
                    );
                    dest_slice.copy_from_slice(&page_data);
                }
                
                // Update page table to point to new frame with default user flags
                let page_flags = 0x7; // Present + Writable + User accessible
                crate::memory::update_page_mapping(
                    fault_addr,
                    new_frame,
                    page_flags
                );
                
                // Free the swap slot
                let swap_slot_to_free = crate::storage::swap::SwapSlot {
                    device_id: swap_info.swap_device_id,
                    slot: swap_info.swap_slot,
                };
                crate::storage::swap::free_swap_slot(swap_slot_to_free);
                
                // Remove from swap tracking
                crate::memory::remove_swap_info(fault_addr);
                
                // Unmap temporary mapping
                crate::memory::unmap_temporary_frame(temp_vaddr);
                
                crate::log_dbg!("Swapped page loaded for address: {:?}", fault_addr);
                return true;
            }
        }
    }
    
    false
}

/// Enable FPU for current task
fn enable_fpu() {
    unsafe {
        // Clear TS bit in CR0
        let mut cr0 = x86_64::registers::control::Cr0::read();
        cr0.remove(x86_64::registers::control::Cr0Flags::TASK_SWITCHED);
        x86_64::registers::control::Cr0::write(cr0);
        
        // Initialize FPU
        core::arch::asm!("fninit");
    }
}

/// Trigger scheduler if time quantum expired
fn trigger_scheduler_if_needed() {
    // Check if current process time slice expired
    const TIME_SLICE_MS: u64 = 10; // 10ms time slices
    
    static mut LAST_SCHEDULE_TIME: AtomicU64 = AtomicU64::new(0);
    
    unsafe {
        let current_time = SYSTEM_UPTIME_MS.load(Ordering::Relaxed);
        let last_schedule = LAST_SCHEDULE_TIME.load(Ordering::Relaxed);
        
        if current_time - last_schedule >= TIME_SLICE_MS {
            LAST_SCHEDULE_TIME.store(current_time, Ordering::Relaxed);
            
            // Trigger scheduler
            crate::sched::executor::yield_to_scheduler();
        }
    }
}

/// Initialize PIT (Programmable Interval Timer) for precise timing
pub fn init_pit_timer() -> Result<(), &'static str> {
    let divisor = PIT_FREQUENCY / TIMER_FREQUENCY;
    
    if divisor > 65535 {
        return Err("Timer frequency too low");
    }
    
    unsafe {
        // Set PIT to mode 3 (square wave generator)
        let mut command_port = PortWriteOnly::new(0x43);
        command_port.write(0x36u8); // Channel 0, lobyte/hibyte, mode 3
        
        // Set divisor
        let mut data_port = PortWriteOnly::new(0x40);
        data_port.write((divisor & 0xFF) as u8); // Low byte
        data_port.write((divisor >> 8) as u8);   // High byte
    }
    
    Ok(())
}

/// Get system uptime in milliseconds
pub fn get_uptime_ms() -> u64 {
    unsafe { SYSTEM_UPTIME_MS.load(Ordering::Relaxed) }
}

/// Get interrupt statistics
pub fn get_interrupt_stats() -> &'static InterruptStats {
    &INTERRUPT_STATS
}