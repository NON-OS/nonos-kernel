//! NØNOS Kernel Scheduler

use alloc::collections::VecDeque;
use spin::Mutex;
use crate::sched::task::Task;
use crate::sched::runqueue::RunQueue;
use crate::sched::realtime;

/// The global run queue for normal tasks.
static RUNQUEUE: Mutex<RunQueue> = Mutex::new(RunQueue::new());

/// The main scheduler structure.
pub struct Scheduler {
    pub running_tasks: usize,
}

static mut GLOBAL_SCHEDULER: Option<Scheduler> = None;

/// Initialize the scheduler subsystem.
pub fn init() {
    unsafe { GLOBAL_SCHEDULER = Some(Scheduler { running_tasks: 0 }); }
    RUNQUEUE.lock().clear();
    realtime::init();
}

/// Get the current scheduler instance.
pub fn get() -> Option<&'static Scheduler> {
    unsafe { GLOBAL_SCHEDULER.as_ref() }
}

/// Spawn a new normal-priority kernel task into the global runqueue.
pub fn spawn(task: Task) {
    if task.priority == crate::sched::task::Priority::RealTime {
        realtime::spawn_realtime(task);
    } else {
        RUNQUEUE.lock().push(task);
    }
}

/// Run all normal and real-time tasks (entry point for kernel scheduling).
pub fn run() -> ! {
    loop {
        // Run any pending real-time tasks first (minimal latency)
        realtime::run_realtime_tasks();

        // Then run normal tasks
        let mut rq = RUNQUEUE.lock();
        if let Some(mut task) = rq.pop() {
            task.run();
            if !task.is_complete() {
                rq.push(task);
            }
        } else {
            // No tasks—idle CPU until interrupt
            crate::arch::idle_cpu();
        }
    }
}

/// Called by timer interrupt for preemption (integration point).
pub fn tick() {
    // Preemptive scheduling logic can be added here.
    // For now, this function is an integration point for timer interrupts.
}

/// Wake up the scheduler from external event (IPI, etc).
pub fn wakeup() {
    // Integration point for IPI, device, or external wakeup.
}

/// Entry point to start the scheduler loop (used by kernel).
pub fn enter() -> ! {
    run()
}
