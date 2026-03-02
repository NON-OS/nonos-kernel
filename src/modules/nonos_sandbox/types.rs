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


use crate::process::capabilities::{Capability, CapabilitySet};
use crate::crypto::{
    kyber::KyberKeyPair,
    dilithium::DilithiumKeyPair,
};

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub memory_limit: usize,
    pub allowed_capabilities: CapabilitySet,
    pub audit: bool,
    pub quantum_isolation: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit: 4096,
            allowed_capabilities: CapabilitySet::new(),
            audit: false,
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

    pub fn with_capability(mut self, cap: Capability) -> Self {
        self.allowed_capabilities.insert(cap.bit());
        self
    }

    pub fn with_audit(mut self) -> Self {
        self.audit = true;
        self
    }

    pub fn with_quantum_isolation(mut self) -> Self {
        self.quantum_isolation = true;
        self
    }

    pub fn with_capability_set(mut self, caps: CapabilitySet) -> Self {
        self.allowed_capabilities = caps;
        self
    }
}

#[derive(Debug)]
pub struct SandboxState {
    pub module_id: u64,
    pub base_addr: usize,
    pub size: usize,
    pub capabilities: CapabilitySet,
    pub quantum_keys: Option<(KyberKeyPair, DilithiumKeyPair)>,
}

impl SandboxState {
    #[inline]
    pub fn has_capability(&self, cap: Capability) -> bool {
        self.capabilities.bits() & (1u64 << cap.bit()) != 0
    }

    pub fn has_all_capabilities(&self, required: &[Capability]) -> bool {
        required.iter().all(|cap| self.has_capability(*cap))
    }
}
