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

//! Async Executor for NONOS
//! 
//! High-performance async executor with capability-aware scheduling

use crate::sched::scheduler;
use spin::Mutex;
use alloc::{vec::Vec, boxed::Box};

/// Task execution state
static EXECUTOR_STATE: Mutex<ExecutorState> = Mutex::new(ExecutorState::new());

struct ExecutorState {
    ready_queue: Vec<TaskHandle>,
    current_task: Option<TaskHandle>,
}

impl ExecutorState {
    const fn new() -> Self {
        Self {
            ready_queue: Vec::new(),
            current_task: None,
        }
    }
}

struct TaskHandle {
    id: u64,
    name: &'static str,
    entry: fn(),
}

/// Initialize the executor subsystem
pub fn init() {
    let mut state = EXECUTOR_STATE.lock();
    state.ready_queue.clear();
    state.current_task = None;
    
    // Create idle task
    state.ready_queue.push(TaskHandle {
        id: 0,
        name: "idle",
        entry: idle_task,
    });
}

fn idle_task() {
    loop {
        unsafe {
            x86_64::instructions::hlt();
        }
    }
}

/// Yield current task to scheduler
pub fn yield_to_scheduler() {
    scheduler::yield_current_task();
}

/// Main scheduler entry point
pub fn run_scheduler() -> ! {
    // Initialize scheduler
    scheduler::init_scheduler();
    
    // Create initial system tasks
    create_system_tasks();
    
    // Run main scheduler loop
    scheduler::run_scheduler();
    
    // If we get here, all tasks completed - enter idle loop
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

fn create_system_tasks() {
    use crate::sched::scheduler::spawn_task;
    
    // Spawn system monitoring task
    spawn_task("system.monitor", async {
        loop {
            // Perform actual health check
            crate::system_monitor::periodic_health_check();
            
            // Sleep for 5 seconds between checks
            simple_delay(5000).await;
        }
    }, 1);
    
    // Spawn memory management task  
    spawn_task("memory.maintenance", async {
        loop {
            // Check heap health
            let heap_stats = crate::memory::heap::get_heap_stats();
            if !crate::memory::heap::check_heap_health() {
                crate::log::logger::log_critical("Heap health degraded");
            }
            
            // Sleep for 30 seconds between maintenance
            simple_delay(30000).await;
        }
    }, 0);
}

// Simple delay implementation
async fn simple_delay(ms: u64) {
    let start = crate::time::timestamp_millis();
    let target = start + ms;
    
    while crate::time::timestamp_millis() < target {
        // Yield to scheduler by checking should continue
        core::hint::spin_loop();
    }
}
