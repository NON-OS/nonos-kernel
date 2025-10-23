//! NØNOS Scheduler Subsystem 

pub mod task;
pub mod runqueue;
pub mod context;
pub mod executor;
pub mod realtime;
pub mod nonos_scheduler;

// Re-export primary scheduler APIs
pub use nonos_scheduler::{
    init,
    get,
    spawn,
    run,
    tick,
    wakeup,
    enter,
};

pub fn current_scheduler() -> Option<&'static nonos_scheduler::Scheduler> {
    get()
}

pub fn yield_cpu() {
    // Yield CPU to next task
    tick();
}

pub fn current_cpu_id() -> u32 {
    // Get current CPU ID from architecture-specific code
    crate::arch::x86_64::cpu::current_cpu_id() as u32
}

pub use task::{Task, Priority, CpuAffinity};
pub use runqueue::RunQueue;
pub use context::Context;
pub use executor::{spawn_async, poll_async_tasks, pending_async_tasks};
pub use realtime::{
    init as realtime_init,
    spawn_realtime,
    run_realtime_tasks,
    pending_realtime_tasks,
    has_realtime_tasks,
};
