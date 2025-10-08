pub mod nonos_scheduler;
pub mod nonos_task;
pub mod nonos_executor;
pub mod nonos_advanced_scheduler;
pub mod nonos_quantum_ai_scheduler;
pub mod nonos_runqueue;
pub mod nonos_context;
pub mod nonos_ctx;
pub mod nonos_ml_scheduler;
pub mod nonos_realtime_scheduler;

// Re-export for compatibility
pub use nonos_scheduler as scheduler;
pub use nonos_task as task;
pub use nonos_executor as executor;
pub use nonos_advanced_scheduler as advanced_scheduler;
pub use nonos_quantum_ai_scheduler as quantum_ai_scheduler;
pub use nonos_runqueue as runqueue;

use alloc::format;

// Re-export main scheduler functions
pub use nonos_executor::run_scheduler;
pub use nonos_task::{kspawn, Priority, Affinity};

/// Scheduling policy for process management
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SchedulingPolicy {
    Fair,
    RealTime,
    Background,
    Quantum,
    HighPriority,
    Interactive,
}

/// CPU affinity for scheduling
#[derive(Debug, Clone)]
pub struct CpuAffinity {
    pub allowed_cpus: alloc::vec::Vec<u32>,
}

impl CpuAffinity {
    pub fn new(cpus: alloc::vec::Vec<u32>) -> Self {
        Self { allowed_cpus: cpus }
    }
    
    pub fn any() -> Self {
        Self { allowed_cpus: (0..16).collect() }
    }
}

/// Priority class for scheduling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PriorityClass {
    Idle = 0,
    Background = 1,
    Normal = 2,
    AboveNormal = 3,
    High = 4,
    RealTime = 5,
    Critical = 6,
}
pub use nonos_quantum_ai_scheduler::{
    init_quantum_ai_scheduler, get_quantum_ai_scheduler, quantum_schedule_task,
    get_quantum_ai_stats, QuantumAIStatsSnapshot, SystemState, QuantumSchedulingDecision
};

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
    nonos_executor::init();
    
    // Initialize the runqueue
    nonos_scheduler::init();
    
    // Initialize advanced scheduler
    if let Err(e) = nonos_advanced_scheduler::init_advanced_scheduler(4) { // 4 CPUs
        crate::log_warn!("Failed to initialize advanced scheduler: {}", e);
    }
    
    // Initialize quantum AI scheduler
    if let Err(e) = init_quantum_ai_scheduler() {
        crate::log_warn!("Failed to initialize quantum AI scheduler: {}", e);
    }
    
    crate::log::logger::log_info!("Scheduler subsystem initialized");
}

/// Initialize scheduler with alias for compatibility
pub fn init_scheduler() {
    init();
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
pub fn current_scheduler() -> Option<&'static nonos_scheduler::Scheduler> {
    nonos_scheduler::get_current_scheduler()
}

/// Spawn a new task
pub fn spawn_task(name: &str, task_fn: fn(), priority: u8) {
    // Simplified task spawning for compilation
    crate::log::logger::log_info!("{}", &format!("Spawning task: {} with priority: {}", name, priority));
}

/// Scheduler tick - delegate to nonos_scheduler
pub fn scheduler_tick() {
    nonos_scheduler::scheduler_tick();
}

/// Wake up scheduler (compatibility function)
pub fn wakeup_scheduler() {
    nonos_scheduler::wakeup_scheduler();
}
