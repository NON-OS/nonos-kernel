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
pub mod scheduler;
pub mod task;
pub mod executor;
pub mod nonos_scheduler;
pub mod advanced_scheduler;
pub mod runqueue;

// Re-export main scheduler functions
pub use executor::run_scheduler;
pub use task::{kspawn, Priority, Affinity};

/// Get current CPU ID (stub implementation)
pub fn current_cpu_id() -> u32 {
    // In a real implementation, this would read the APIC ID or use per-CPU data
    // For now, we return CPU 0 as we're single-core
    0
}

/// Enter the main scheduler loop
pub fn enter() -> ! {
    crate::log::logger::log_info!("Entering main scheduler loop");
    run_scheduler()
}

/// Initialize the scheduler subsystem
pub fn init() {
    crate::log::logger::log_info!("Initializing scheduler subsystem");
    
    // Initialize the task executor
    executor::init();
    
    // Initialize the runqueue
    scheduler::init();
    
    crate::log::logger::log_info!("Scheduler subsystem initialized");
}

/// Schedule immediately (yield current task)
pub fn schedule_now() {
    // Simple yield implementation
    unsafe {
        x86_64::instructions::hlt();
    }
}
