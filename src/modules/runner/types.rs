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

pub use super::context::{ExecutionContext, RunnerConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionState {
    Pending,
    Starting,
    Running,
    Paused,
    Stopping,
    Stopped,
    Faulted,
    Terminated,
}

impl ExecutionState {
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Starting | Self::Running | Self::Paused)
    }

    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Stopped | Self::Faulted | Self::Terminated)
    }

    pub const fn can_start(&self) -> bool {
        matches!(self, Self::Pending | Self::Stopped)
    }

    pub const fn can_stop(&self) -> bool {
        matches!(self, Self::Running | Self::Paused | Self::Faulted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPolicy {
    Ignore,
    Restart,
    RestartWithBackoff,
    Terminate,
    Panic,
}

impl Default for FaultPolicy {
    fn default() -> Self {
        Self::RestartWithBackoff
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultType {
    MemoryViolation,
    InvalidInstruction,
    DivisionByZero,
    StackOverflow,
    HeapExhaustion,
    Timeout,
    SecurityBreach,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct FaultInfo {
    pub fault_type: FaultType,
    pub address: Option<u64>,
    pub instruction_pointer: u64,
    pub timestamp: u64,
    pub fault_count: u32,
}

impl FaultInfo {
    pub fn new(fault_type: FaultType, ip: u64) -> Self {
        Self {
            fault_type,
            address: None,
            instruction_pointer: ip,
            timestamp: 0,
            fault_count: 1,
        }
    }

    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    pub fn increment_count(&mut self) {
        self.fault_count = self.fault_count.saturating_add(1);
    }
}
