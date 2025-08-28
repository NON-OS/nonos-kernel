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
//! NONOS Process Management
//!
//! Process management with NUMA awareness, 
//! real-time scheduling, and capability-based security

pub mod process;
pub mod context;
pub mod scheduler;
pub mod numa;
pub mod realtime;
pub mod capabilities;

/// Stub process structure for compilation
pub struct Process {
    pub pid: u32,
}

impl Process {
    /// Terminate process with signal
    pub fn terminate_with_signal(&self, _signal: i32) {
        // Stub implementation
    }
}

/// Get current process (stub implementation)  
pub fn current_process() -> Option<&'static Process> {
    // Stub implementation - would return actual current process
    None
}
