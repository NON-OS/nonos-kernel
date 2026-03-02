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


use crate::process::capabilities::CapabilitySet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPolicy {
    Restart,
    Terminate,
    Isolate,
    Notify,
}

impl Default for FaultPolicy {
    fn default() -> Self {
        Self::Terminate
    }
}

#[derive(Debug, Clone)]
pub struct RunnerContext {
    pub module_id: u64,
    pub capabilities: CapabilitySet,
    pub fault_policy: FaultPolicy,
    pub is_running: bool,
    pub memory_base: Option<u64>,
    pub memory_size: usize,
}

impl RunnerContext {
    pub fn new(module_id: u64, capabilities: CapabilitySet) -> Self {
        Self {
            module_id,
            capabilities,
            fault_policy: FaultPolicy::default(),
            is_running: false,
            memory_base: None,
            memory_size: 0,
        }
    }

    pub fn with_fault_policy(mut self, policy: FaultPolicy) -> Self {
        self.fault_policy = policy;
        self
    }

    pub fn with_memory(mut self, base: u64, size: usize) -> Self {
        self.memory_base = Some(base);
        self.memory_size = size;
        self
    }
}
