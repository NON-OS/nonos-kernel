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
use core::sync::atomic::{compiler_fence, Ordering};
use super::constants::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl ModuleType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::System => "System",
            Self::User => "User",
            Self::Driver => "Driver",
            Self::Service => "Service",
            Self::Library => "Library",
        }
    }

    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::System => 0,
            Self::User => 1,
            Self::Driver => 2,
            Self::Service => 3,
            Self::Library => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl PrivacyPolicy {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ZeroStateOnly => "ZeroStateOnly",
            Self::Ephemeral => "Ephemeral",
            Self::EncryptedPersistent => "EncryptedPersistent",
            Self::None => "None",
        }
    }

    pub const fn allows_persistence(&self) -> bool {
        matches!(self, Self::EncryptedPersistent)
    }

    pub const fn is_ram_only(&self) -> bool {
        matches!(self, Self::ZeroStateOnly | Self::Ephemeral)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRequirements {
    pub min_heap: usize,
    pub max_heap: usize,
    pub stack_size: usize,
    pub needs_dma: bool,
}

impl Default for MemoryRequirements {
    fn default() -> Self {
        Self {
            min_heap: DEFAULT_MIN_HEAP,
            max_heap: DEFAULT_MAX_HEAP,
            stack_size: DEFAULT_STACK_SIZE,
            needs_dma: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AttestationEntry {
    pub signer: [u8; 32],
    pub signature: [u8; 64],
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct ModuleManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub module_type: ModuleType,
    pub privacy_policy: PrivacyPolicy,
    pub memory: MemoryRequirements,
    pub capabilities: Vec<crate::process::capabilities::Capability>,
    pub attestation_chain: Vec<AttestationEntry>,
    pub hash: [u8; HASH_SIZE],
}

impl ModuleManifest {
    pub fn new(name: &str, code: &[u8]) -> Self {
        let hash = crate::crypto::hash_blake3_hash(code);
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
            hash,
        }
    }

    pub fn verify_hash(&self, code: &[u8]) -> bool {
        let computed = crate::crypto::hash_blake3_hash(code);
        self.hash == computed
    }

    pub fn has_capability(&self, cap: crate::process::capabilities::Capability) -> bool {
        self.capabilities.contains(&cap)
    }

    pub fn verify_attestation_chain(&self) -> bool {
        if self.attestation_chain.is_empty() {
            return true;
        }

        for entry in &self.attestation_chain {
            let mut msg = [0u8; 40];
            msg[..32].copy_from_slice(&entry.signer);
            msg[32..40].copy_from_slice(&entry.timestamp.to_le_bytes());

            let sig = crate::crypto::Signature::from_bytes(&entry.signature);
            let verified = crate::crypto::verify_ed25519(&entry.signer, &msg, &sig);

            if !verified {
                return false;
            }
        }

        true
    }

    pub fn secure_erase(&mut self) {
        // # SAFETY: Volatile writes ensure data is actually erased
        secure_erase_string(&mut self.name);
        secure_erase_string(&mut self.version);
        secure_erase_string(&mut self.author);
        secure_erase_string(&mut self.description);
        self.capabilities.clear();
        self.attestation_chain.clear();
        for b in self.hash.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

fn secure_erase_string(s: &mut String) {
    // # SAFETY: Volatile writes prevent optimization
    let bytes = unsafe { s.as_bytes_mut() };
    for b in bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    s.clear();
}
