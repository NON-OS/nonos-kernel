//! Module Manifest System
//! 
//! Advanced manifest parsing and validation for cryptographically signed modules

use alloc::vec::Vec;
use crate::syscall::capabilities::Capability;

/// Module manifest with cryptographic binding
pub struct ModuleManifest {
    pub name: &'static str,
    pub version: &'static str,
    pub hash: [u8; 32],
    pub required_caps: Vec<Capability>,
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
    pub module_type: ModuleType,
    pub memory_requirements: MemoryRequirements,
    // Extended fields for advanced module management
    pub entry_point_addr: Option<u64>,
    pub signer: crate::crypto::vault::VaultPublicKey,
    pub auth_chain_id: Option<u32>,
    pub auth_method: AuthMethod,
    pub zk_attestation: Option<[u8; 32]>,
    pub fault_policy: Option<crate::modules::runtime::FaultPolicy>,
    pub memory_bytes: usize,
    pub timestamp: u64,
    pub expiry_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub enum ModuleType {
    System,
    User,
    Driver,
    Service,
}

#[derive(Debug, Clone, Copy)]
pub enum AuthMethod {
    VaultSignature,
    PublicKeySignature,
    TrustedPlatformModule,
    HardwareAttestation,
}

#[derive(Debug, Clone)]
pub struct MemoryRequirements {
    pub min_heap: usize,
    pub max_heap: usize,
    pub stack_size: usize,
}

impl ModuleManifest {
    pub fn module_id(&self) -> u64 {
        // Generate unique ID from hash
        u64::from_le_bytes([
            self.hash[0], self.hash[1], self.hash[2], self.hash[3],
            self.hash[4], self.hash[5], self.hash[6], self.hash[7],
        ])
    }
}
