pub mod advanced_scheduler;
pub mod executor;
pub mod nonos_scheduler;
pub mod runqueue;
pub mod scheduler;
pub mod task;

use alloc::format;

// Re-export main scheduler functions
pub use executor::run_scheduler;
pub use task::{kspawn, Affinity, Priority};

/// Get current CPU ID from APIC
pub fn current_cpu_id() -> u32 {
    unsafe {
        // Read Local APIC ID from APIC register
        let apic_base = crate::interrupts::apic::get_apic_base();
        if apic_base != 0 {
            // APIC ID is in bits 24-31 of APIC ID register (offset 0x20)
            let apic_id_reg = apic_base + 0x20;
            let apic_id_value = core::ptr::read_volatile(apic_id_reg as *const u32);
            (apic_id_value >> 24) & 0xFF
        } else {
            // Fallback: use CPUID if APIC not available
            let cpuid_result = core::arch::x86_64::__cpuid(1);
            (cpuid_result.ebx >> 24) & 0xFF
        }
    }
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

/// Yield CPU to other tasks
pub fn yield_cpu() {
    schedule_now();
}

/// Get current scheduler instance
pub fn current_scheduler() -> Option<&'static scheduler::Scheduler> {
    scheduler::get_current_scheduler()
}

/// Spawn a new task
pub fn spawn_task(name: &str, task_fn: fn(), priority: u8) {
    // Simplified task spawning for compilation
    crate::log::logger::log_info!(
        "{}",
        &format!("Spawning task: {} with priority: {}", name, priority)
    );
}

/// Scheduler tick - delegate to nonos_scheduler
pub fn scheduler_tick() {
    nonos_scheduler::scheduler_tick();
}
