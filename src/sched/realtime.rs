//! NØNOS Real-Time Scheduler 

use crate::sched::task::{Task, Priority};
use crate::sched::runqueue::RunQueue;
use spin::{Mutex, Once};

/// Dedicated run queue for real-time tasks (RAM-only)
static REALTIME_RUNQUEUE: Once<Mutex<RunQueue>> = Once::new();

fn get_rt_queue() -> &'static Mutex<RunQueue> {
    REALTIME_RUNQUEUE.call_once(|| Mutex::new(RunQueue::new()))
}

/// Initialize the real-time scheduler subsystem.
pub fn init() {
    get_rt_queue().lock().clear();
}

/// Spawn a real-time task.
/// Only tasks with Priority::RealTime are accepted.
pub fn spawn_realtime(task: Task) {
    if task.priority == Priority::RealTime {
        get_rt_queue().lock().push(task);
    }
}

/// Run all real-time tasks.
pub fn run_realtime_tasks() {
    let mut rq = get_rt_queue().lock();
    while let Some(mut task) = rq.pop() {
        task.run();
        // If not complete, requeue for next cycle
        if !task.is_complete() {
            rq.push(task);
        }
    }
}

/// Returns the count of pending real-time tasks.
pub fn pending_realtime_tasks() -> usize {
    get_rt_queue().lock().len()
}

/// Check if there are real-time tasks to run.
pub fn has_realtime_tasks() -> bool {
    !get_rt_queue().lock().is_empty()
}
