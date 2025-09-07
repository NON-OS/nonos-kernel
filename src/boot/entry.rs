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
// NONOS boot - entry
#![no_std]
#![no_main]

use bootloader_api::{BootInfo, BootloaderConfig, entry_point};

/// Early interrupt stack allocator for BSP initialization
pub static EARLY_IST_ALLOC: [u8; 4096] = [0; 4096];

// Use the simplest possible configuration  
pub const BOOTLOADER_CONFIG: bootloader_api::BootloaderConfig = bootloader_api::BootloaderConfig::new_default();

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // Initialize core subsystems in correct order
    unsafe {
        // 1. Early serial for debugging
        crate::arch::x86_64::serial::init();
        
        // 2. Memory subsystem
        crate::memory::init_from_bootinfo(boot_info);
        
        // 3. GDT/IDT
        let early_alloc = crate::boot::EarlyAllocator::new();
        crate::arch::x86_64::gdt::init_bsp(0, &early_alloc);
        crate::arch::x86_64::idt::init();
        
        // 4. APIC/Timer
        crate::arch::interrupt::apic::init();
        crate::arch::time::timer::init_with_freq(1000); // 1kHz tick
        
        // 5. Scheduler
        crate::sched::init();
        
        // 6. Enable interrupts
        x86_64::instructions::interrupts::enable();
        
        // 7. Start scheduler
        crate::sched::enter();
    }
}
