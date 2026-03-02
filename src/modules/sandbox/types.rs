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

extern crate alloc;

use alloc::vec::Vec;
use super::constants::*;

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub memory_limit: usize,
    pub allowed_capabilities: Vec<u64>,
    pub audit_enabled: bool,
    pub quantum_isolation: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit: DEFAULT_MEMORY_LIMIT,
            allowed_capabilities: Vec::new(),
            audit_enabled: false,
            quantum_isolation: false,
        }
    }
}

impl SandboxConfig {
    pub fn new(memory_limit: usize) -> Self {
        Self {
            memory_limit,
            ..Default::default()
        }
    }

    pub fn with_capability(mut self, cap: u64) -> Self {
        if !self.allowed_capabilities.contains(&cap) {
            self.allowed_capabilities.push(cap);
        }
        self
    }

    pub fn with_audit(mut self) -> Self {
        self.audit_enabled = true;
        self
    }

    pub fn with_quantum_isolation(mut self) -> Self {
        self.quantum_isolation = true;
        self
    }

    pub fn page_count(&self) -> usize {
        (self.memory_limit + PAGE_SIZE - 1) / PAGE_SIZE
    }
}

#[derive(Debug)]
pub struct SandboxState {
    pub module_id: u64,
    pub base_addr: usize,
    pub size: usize,
    pub capabilities: Vec<u64>,
    pub active: bool,
}

impl SandboxState {
    pub fn new(module_id: u64, base_addr: usize, size: usize, capabilities: Vec<u64>) -> Self {
        Self {
            module_id,
            base_addr,
            size,
            capabilities,
            active: true,
        }
    }

    pub fn has_capability(&self, cap: u64) -> bool {
        self.capabilities.contains(&cap)
    }

    pub fn page_count(&self) -> usize {
        (self.size + PAGE_SIZE - 1) / PAGE_SIZE
    }
}
