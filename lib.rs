// This file is part of the NONOS Operating Systems Kernel.
// 
//  Copyright (C) [2025] [NONOS]
//  
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//! NØNOS Kernel Library - Main Entry Point
//!
//! This connects the boot module with the rest of the kernel subsystems.

#![no_std]
#![no_main]
#![feature(
    alloc_error_handler,
    panic_info_message,
    lang_items,
    abi_x86_interrupt,
    naked_functions,
    const_mut_refs,
    async_fn_in_trait
)]

extern crate alloc;

// Subsystem modules
pub mod arch;
pub mod boot;  // The boot module you just added
pub mod crypto;
pub mod ipc;
pub mod log;
pub mod memory;
pub mod modules;
pub mod runtime;
pub mod sched;
pub mod syscall;
pub mod ui;

// Re-export the boot entry point
pub use boot::_start;

use core::panic::PanicInfo;

/// Global allocator error handler
#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    panic!("Allocation error: {:?}", layout);
}

/// Language item for stack unwinding (we don't support it)
#[lang = "eh_personality"]
fn eh_personality() {}

/// Panic handler - called on kernel panic
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Disable interrupts
    x86_64::instructions::interrupts::disable();
    
    // Try to print to serial
    if let Some(serial) = unsafe { arch::x86_64::serial::get_serial() } {
        use core::fmt::Write;
        let _ = writeln!(serial, "\n!!! KERNEL PANIC !!!");
        if let Some(location) = info.location() {
            let _ = writeln!(serial, "Location: {}:{}", location.file(), location.line());
        }
        if let Some(msg) = info.message() {
            let _ = writeln!(serial, "Message: {}", msg);
        }
    }
    
    // Try to print to VGA
    unsafe {
        arch::x86_64::vga::print_panic(info);
    }
    
    // Halt the CPU
    loop {
        x86_64::instructions::hlt();
    }
}
