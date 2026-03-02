// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicU64, Ordering};
use super::constants::*;
use super::types::{ExecutionState, FaultInfo, FaultPolicy};

static CONTEXT_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub stack_size: usize,
    pub heap_size: usize,
    pub startup_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
    pub fault_policy: FaultPolicy,
    pub max_fault_count: u32,
    pub watchdog_enabled: bool,
    pub watchdog_timeout_ms: u64,
    pub priority: u8,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            stack_size: MODULE_STACK_SIZE,
            heap_size: MODULE_HEAP_SIZE,
            startup_timeout_ms: STARTUP_TIMEOUT_MS,
            shutdown_timeout_ms: SHUTDOWN_TIMEOUT_MS,
            fault_policy: FaultPolicy::default(),
            max_fault_count: FAULT_RETRY_COUNT,
            watchdog_enabled: true,
            watchdog_timeout_ms: WATCHDOG_TIMEOUT_MS,
            priority: 128,
        }
    }
}

impl RunnerConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_stack_size(mut self, size: usize) -> Self {
        self.stack_size = size;
        self
    }

    pub fn with_heap_size(mut self, size: usize) -> Self {
        self.heap_size = size;
        self
    }

    pub fn with_fault_policy(mut self, policy: FaultPolicy) -> Self {
        self.fault_policy = policy;
        self
    }

    pub fn with_watchdog(mut self, enabled: bool, timeout_ms: u64) -> Self {
        self.watchdog_enabled = enabled;
        self.watchdog_timeout_ms = timeout_ms;
        self
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }
}

#[derive(Debug)]
pub struct ExecutionContext {
    pub id: u64,
    pub module_id: u64,
    pub state: ExecutionState,
    pub config: RunnerConfig,
    pub stack_base: u64,
    pub stack_pointer: u64,
    pub heap_base: u64,
    pub heap_used: usize,
    pub entry_point: u64,
    pub fault_info: Option<FaultInfo>,
    pub start_time: u64,
    pub cpu_time: u64,
    pub last_heartbeat: u64,
}

impl ExecutionContext {
    pub fn new(module_id: u64, config: RunnerConfig) -> Self {
        Self {
            id: CONTEXT_ID_COUNTER.fetch_add(1, Ordering::SeqCst),
            module_id,
            state: ExecutionState::Pending,
            config,
            stack_base: 0,
            stack_pointer: 0,
            heap_base: 0,
            heap_used: 0,
            entry_point: 0,
            fault_info: None,
            start_time: 0,
            cpu_time: 0,
            last_heartbeat: 0,
        }
    }

    pub fn set_memory_regions(&mut self, stack_base: u64, heap_base: u64, entry: u64) {
        self.stack_base = stack_base;
        self.stack_pointer = stack_base + self.config.stack_size as u64;
        self.heap_base = heap_base;
        self.entry_point = entry;
    }

    pub fn transition_to(&mut self, new_state: ExecutionState) -> bool {
        let valid = match (self.state, new_state) {
            (ExecutionState::Pending, ExecutionState::Starting) => true,
            (ExecutionState::Starting, ExecutionState::Running) => true,
            (ExecutionState::Starting, ExecutionState::Faulted) => true,
            (ExecutionState::Running, ExecutionState::Paused) => true,
            (ExecutionState::Running, ExecutionState::Stopping) => true,
            (ExecutionState::Running, ExecutionState::Faulted) => true,
            (ExecutionState::Paused, ExecutionState::Running) => true,
            (ExecutionState::Paused, ExecutionState::Stopping) => true,
            (ExecutionState::Stopping, ExecutionState::Stopped) => true,
            (ExecutionState::Stopping, ExecutionState::Faulted) => true,
            (ExecutionState::Faulted, ExecutionState::Starting) => true,
            (ExecutionState::Faulted, ExecutionState::Terminated) => true,
            (ExecutionState::Stopped, ExecutionState::Starting) => true,
            _ => false,
        };

        if valid {
            self.state = new_state;
        }
        valid
    }

    pub fn record_fault(&mut self, fault: FaultInfo) {
        if let Some(ref mut existing) = self.fault_info {
            existing.increment_count();
            existing.fault_type = fault.fault_type;
            existing.instruction_pointer = fault.instruction_pointer;
            existing.address = fault.address;
        } else {
            self.fault_info = Some(fault);
        }
        self.state = ExecutionState::Faulted;
    }

    pub fn should_restart(&self) -> bool {
        if let Some(ref fault) = self.fault_info {
            match self.config.fault_policy {
                FaultPolicy::Ignore => false,
                FaultPolicy::Restart => true,
                FaultPolicy::RestartWithBackoff => fault.fault_count < self.config.max_fault_count,
                FaultPolicy::Terminate | FaultPolicy::Panic => false,
            }
        } else {
            false
        }
    }

    pub fn clear_fault(&mut self) {
        self.fault_info = None;
    }

    pub fn update_heartbeat(&mut self, timestamp: u64) {
        self.last_heartbeat = timestamp;
    }

    pub fn check_watchdog(&self, current_time: u64) -> bool {
        if !self.config.watchdog_enabled {
            return true;
        }
        if self.last_heartbeat == 0 {
            return true;
        }
        current_time.saturating_sub(self.last_heartbeat) < self.config.watchdog_timeout_ms
    }

    pub fn erase(&mut self) {
        // SAFETY: Secure erasure of execution context for ZeroState compliance.
        unsafe {
            let ptr = self as *mut Self as *mut u8;
            let size = core::mem::size_of::<Self>();
            core::ptr::write_bytes(ptr, 0, size);
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
        }
    }
}

impl Drop for ExecutionContext {
    fn drop(&mut self) {
        self.erase();
    }
}
