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

use alloc::string::String;
use alloc::vec::Vec;
use super::constants::*;
use super::error::{ManifestError, ManifestResult};
use super::types::{ModuleManifest, ModuleType, PrivacyPolicy, MemoryRequirements, AttestationEntry};

pub struct ManifestBuilder {
    name: String,
    version: String,
    author: String,
    description: String,
    module_type: ModuleType,
    privacy_policy: PrivacyPolicy,
    memory: MemoryRequirements,
    capabilities: Vec<crate::process::capabilities::Capability>,
    attestation_chain: Vec<AttestationEntry>,
    code: Vec<u8>,
}

impl ManifestBuilder {
    pub fn new(name: &str, code: &[u8]) -> Self {
        Self {
            name: String::from(name),
            version: String::from("1.0.0"),
            author: String::new(),
            description: String::new(),
            module_type: ModuleType::default(),
            privacy_policy: PrivacyPolicy::default(),
            memory: MemoryRequirements::default(),
            capabilities: Vec::new(),
            attestation_chain: Vec::new(),
            code: Vec::from(code),
        }
    }

    pub fn version(mut self, version: &str) -> Self {
        self.version = String::from(version);
        self
    }

    pub fn author(mut self, author: &str) -> Self {
        self.author = String::from(author);
        self
    }

    pub fn description(mut self, description: &str) -> Self {
        self.description = String::from(description);
        self
    }

    pub fn module_type(mut self, module_type: ModuleType) -> Self {
        self.module_type = module_type;
        self
    }

    pub fn privacy_policy(mut self, policy: PrivacyPolicy) -> Self {
        self.privacy_policy = policy;
        self
    }

    pub fn memory_requirements(mut self, memory: MemoryRequirements) -> Self {
        self.memory = memory;
        self
    }

    pub fn capability(mut self, cap: crate::process::capabilities::Capability) -> Self {
        if !self.capabilities.contains(&cap) {
            self.capabilities.push(cap);
        }
        self
    }

    pub fn capabilities(mut self, caps: &[crate::process::capabilities::Capability]) -> Self {
        for cap in caps {
            if !self.capabilities.contains(cap) {
                self.capabilities.push(*cap);
            }
        }
        self
    }

    pub fn attestation(mut self, entry: AttestationEntry) -> Self {
        self.attestation_chain.push(entry);
        self
    }

    pub fn build(self) -> ManifestResult<ModuleManifest> {
        if self.name.is_empty() {
            return Err(ManifestError::EmptyName);
        }
        if self.name.len() > MAX_MODULE_NAME_LEN {
            return Err(ManifestError::NameTooLong);
        }
        if self.version.len() > MAX_VERSION_LEN {
            return Err(ManifestError::VersionTooLong);
        }
        if self.author.len() > MAX_AUTHOR_LEN {
            return Err(ManifestError::AuthorTooLong);
        }
        if self.description.len() > MAX_DESCRIPTION_LEN {
            return Err(ManifestError::DescriptionTooLong);
        }
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(ManifestError::TooManyCapabilities);
        }

        let hash = crate::crypto::hash_blake3_hash(&self.code);

        Ok(ModuleManifest {
            name: self.name,
            version: self.version,
            author: self.author,
            description: self.description,
            module_type: self.module_type,
            privacy_policy: self.privacy_policy,
            memory: self.memory,
            capabilities: self.capabilities,
            attestation_chain: self.attestation_chain,
            hash,
        })
    }
}
