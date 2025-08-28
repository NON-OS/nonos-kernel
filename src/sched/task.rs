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
//! Task Management System
//! Provides capability-aware task spawning with priority and affinity control

use alloc::boxed::Box;
use core::future::Future;

/// Task identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub u64);

/// Task priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Idle = 0,
    Low = 1,
    Normal = 2, 
    High = 3,
    Realtime = 4,
    Critical = 5,
}

/// CPU affinity specification
#[derive(Debug, Clone, Copy)]
pub enum Affinity {
    ANY,
    Core(u32),
    Package(u32),
}

/// Spawn a new kernel task with advanced scheduling parameters
pub fn kspawn(
    name: &'static str,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
    priority: Priority,
    affinity: Affinity,
) {
    // Convert C function to async future
    let future = KernelTaskFuture::new(name, entry, arg);
    let priority_num = match priority {
        Priority::Idle => 0,
        Priority::Low => 1,
        Priority::Normal => 2,
        Priority::High => 3,
        Priority::Realtime => 4,
        Priority::Critical => 5,
    };
    
    crate::sched::scheduler::spawn_task(name, future, priority_num);
}

/// Wrapper to convert kernel thread to async future
struct KernelTaskFuture {
    name: &'static str,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
    started: bool,
}

impl KernelTaskFuture {
    fn new(name: &'static str, entry: extern "C" fn(usize) -> !, arg: usize) -> Self {
        Self {
            name,
            entry,
            arg,
            started: false,
        }
    }
}

impl Future for KernelTaskFuture {
    type Output = ();
    
    fn poll(mut self: core::pin::Pin<&mut Self>, _cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.started {
            self.started = true;
            // uture wwould create a new stack and jump to entry
            // For now, we just mark as completed
            return core::task::Poll::Ready(());
        }
        core::task::Poll::Pending
    }
}

/// Get current task ID
pub fn current() -> TaskId {
    // Simple implementation - we return a fixed ID for now
    TaskId(1)
}
