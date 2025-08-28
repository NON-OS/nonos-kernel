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
//! NØNOS Capability-Aware Kernel Scheduler
//!
//! This scheduler provides a secure cooperative multitasking environment
//! for async-capable kernel tasks. It supports:
//! - Capability-tagged task registration (planned)
//! - Priority boot queues and core-task separation (in roadmap)
//! - Preemption placeholder via tick scheduling (planned)
//! - Secure `.mod` future-scoped sandbox execution

use alloc::{collections::VecDeque, format, boxed::Box};
use core::task::{Context, Poll, Waker, RawWaker, RawWakerVTable};
use core::future::Future;
use core::pin::Pin;
use core::ptr::null;
use spin::Mutex;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Represents a single schedulable kernel task
pub struct Task {
    pub name: &'static str,
    pub future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    pub waker: Option<Waker>,
    pub priority: u8,
    pub ticks: u64,
}

impl Task {
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.future.as_mut().poll(cx)
    }
}

/// Global scheduler queue (FIFO, upgrade to priority queue later)
static SCHED_QUEUE: Mutex<VecDeque<Task>> = Mutex::new(VecDeque::new());

/// Preemption flag for scheduler
static NEED_RESCHEDULE: AtomicBool = AtomicBool::new(false);

/// Scheduler statistics
static SCHEDULER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Spawns a new async kernel task into the global queue
pub fn spawn_task(name: &'static str, fut: impl Future<Output = ()> + Send + 'static, priority: u8) {
    let task = Task {
        name,
        future: Box::pin(fut),
        waker: None,
        priority,
        ticks: 0,
    };
    SCHED_QUEUE.lock().push_back(task);
}

/// Initialize scheduler state
pub fn init_scheduler() {
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log("[SCHED] Kernel scheduler initialized");
    }
}

/// Polls the entire scheduler queue cooperatively
pub fn run_scheduler() -> ! {
    let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    
    let mut task_failures = 0u64;
    const MAX_TASK_FAILURES: u64 = 100;

    loop {
        let mut queue = SCHED_QUEUE.lock();
        if queue.is_empty() {
            drop(queue);
            // No tasks - idle with interrupts enabled
            unsafe {
                x86_64::instructions::interrupts::enable();
                x86_64::instructions::hlt();
                x86_64::instructions::interrupts::disable();
            }
            continue;
        }

        let mut new_queue = VecDeque::new();

        while let Some(mut task) = queue.pop_front() {
            // Check always system health before running tasks
            if !crate::system_monitor::is_system_stable() {
                log_task_error(task.name, "System unstable - task skipped");
                task_failures += 1;
                if task_failures > MAX_TASK_FAILURES {
                    log_task_error("scheduler", "Too many task failures - halting");
                    break;
                }
                continue;
            }
            
            match task.poll(&mut cx) {
                Poll::Ready(()) => {
                    log_task_exit(task.name);
                },
                Poll::Pending => {
                    task.ticks += 1;
                    // Prevent runaway tasks
                    if task.ticks > 1000000 {
                        log_task_error(task.name, "Task timeout - terminating");
                        task_failures += 1;
                    } else {
                        new_queue.push_back(task);
                    }
                },
            }
        }

        *queue = new_queue;
        
        if task_failures > MAX_TASK_FAILURES {
            crate::system_monitor::mark_system_unstable();
            break;
        }
    }
    
    // If we exit the loop, might be something went wrong
    loop {
        unsafe { x86_64::instructions::hlt(); }
    }
}


/// RawWaker for pre-init environments
fn dummy_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker { dummy_raw_waker() }

    let vtable = &RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(null(), vtable)
}

/// Simple scheduler-level logging
fn log_task_exit(task: &str) {
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log(&format!("[SCHED] Task '{}' completed.", task));
    }
}

fn log_task_error(task: &str, error: &str) {
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log(&format!("[SCHED] Task '{}' error: {}", task, error));
    }
}

/// Called by timer interrupt for preemptive scheduling
pub fn on_timer_tick() {
    SCHEDULER_TICKS.fetch_add(1, Ordering::Relaxed);
    
    // Mark that we need to reschedule
    NEED_RESCHEDULE.store(true, Ordering::Relaxed);
    
    // Update timer module
    crate::interrupts::timer::tick();
}

/// Check if reschedule is needed
pub fn should_reschedule() -> bool {
    NEED_RESCHEDULE.compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed).is_ok()
}

/// Get scheduler statistics
pub fn get_stats() -> (u64, usize) {
    let queue_len = SCHED_QUEUE.lock().len();
    (SCHEDULER_TICKS.load(Ordering::Relaxed), queue_len)
}

/// Yield current task (trigger reschedule)
pub fn yield_current_task() {
    NEED_RESCHEDULE.store(true, Ordering::Release);
    
    // In a real implementation, we need to save current task state and switch to the next ready task. For now, we just mark for reschedule.
    unsafe {
        x86_64::instructions::hlt(); // Give CPU time to other tasks
    }
}

/// Initialize the scheduler subsystem
pub fn init() {
    // Clear any existing tasks
    SCHED_QUEUE.lock().clear();
    
    // Reset scheduler state
    NEED_RESCHEDULE.store(false, Ordering::Relaxed);
    SCHEDULER_TICKS.store(0, Ordering::Relaxed);
    
    // Call the init_scheduler function
    init_scheduler();
}
