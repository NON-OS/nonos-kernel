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
