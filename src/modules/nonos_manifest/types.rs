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


use alloc::{string::String, vec::Vec};
use crate::crypto::blake3::blake3_hash;
use crate::security::trusted_keys::TrustedKey;
use crate::process::capabilities::Capability;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyPolicy {
    ZeroStateOnly,
    Ephemeral,
    EncryptedPersistent,
    None,
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        Self::ZeroStateOnly
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    VaultSignature,
    Ed25519Signature,
    TrustedKeys,
    None,
}

impl Default for AuthMethod {
    fn default() -> Self {
        Self::Ed25519Signature
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleType {
    System,
    User,
    Driver,
    Service,
    Library,
}

impl Default for ModuleType {
    fn default() -> Self {
        Self::User
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRequirements {
    pub min_heap: usize,
    pub max_heap: usize,
    pub stack_size: usize,
    pub needs_dma: bool,
}

impl Default for MemoryRequirements {
    fn default() -> Self {
        Self {
            min_heap: 4096,
            max_heap: 1024 * 1024, // 1 MB
            stack_size: 8192,
            needs_dma: false,
        }
    }
}

impl MemoryRequirements {
    pub fn new(min_heap: usize, max_heap: usize, stack_size: usize) -> Self {
        Self {
            min_heap,
            max_heap,
            stack_size,
            needs_dma: false,
        }
    }

    pub fn with_dma(mut self) -> Self {
        self.needs_dma = true;
        self
    }

    pub fn validate(&self) -> bool {
        self.min_heap <= self.max_heap && self.stack_size > 0
    }
}

#[derive(Debug, Clone)]
pub struct ModuleManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub capabilities: Vec<Capability>,
    pub privacy_policy: PrivacyPolicy,
    pub attestation_chain: Vec<TrustedKey>,
    pub hash: [u8; 32],
    pub module_type: ModuleType,
    pub memory_requirements: MemoryRequirements,
    pub auth_method: AuthMethod,
}

impl ModuleManifest {
    pub fn new(
        name: String,
        version: String,
        author: String,
        description: String,
        capabilities: Vec<Capability>,
        privacy_policy: PrivacyPolicy,
        attestation_chain: Vec<TrustedKey>,
        module_code: &[u8],
    ) -> Self {
        let hash = blake3_hash(module_code);
        Self {
            name,
            version,
            author,
            description,
            capabilities,
            privacy_policy,
            attestation_chain,
            hash,
            module_type: ModuleType::default(),
            memory_requirements: MemoryRequirements::default(),
            auth_method: AuthMethod::default(),
        }
    }

    pub fn with_type(mut self, module_type: ModuleType) -> Self {
        self.module_type = module_type;
        self
    }

    pub fn with_memory_requirements(mut self, requirements: MemoryRequirements) -> Self {
        self.memory_requirements = requirements;
        self
    }

    pub fn with_auth_method(mut self, method: AuthMethod) -> Self {
        self.auth_method = method;
        self
    }
}
