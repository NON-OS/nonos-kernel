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

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use alloc::boxed::Box;

pub type CapabilityType = Capability;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Capability {
    ProcessCreate = 1 << 0,
    ProcessKill = 1 << 1,
    MemoryMap = 1 << 2,
    MemoryUnmap = 1 << 3,
    FileRead = 1 << 4,
    FileWrite = 1 << 5,
    FileCreate = 1 << 6,
    FileDelete = 1 << 7,
    NetworkBind = 1 << 8,
    NetworkConnect = 1 << 9,
    DeviceAccess = 1 << 10,
    SystemCall = 1 << 11,
    InterruptHandler = 1 << 12,
    ModuleLoad = 1 << 13,
    ModuleUnload = 1 << 14,
    CryptoKeys = 1 << 15,
    VaultAccess = 1 << 16,
    EphemeralMemory = 1 << 17,
    IsolationChamber = 1 << 18,
    ZeroStateRuntime = 1 << 19,
    CapabilityGrant = 1 << 20,
    CapabilityRevoke = 1 << 21,
    AttestationCreate = 1 << 22,
    AttestationVerify = 1 << 23,
    SecureBootChain = 1 << 24,
    CryptoFsVault = 1 << 25,
    QuantumSignatures = 1 << 26,
    HardwareAbstraction = 1 << 27,
    DebugFramework = 1 << 28,
    AuditTrails = 1 << 29,
    IPCTokens = 1 << 30,
}

#[derive(Debug)]
pub struct CapabilitySet {
    pub capabilities: AtomicU64,
    pub delegation_depth: AtomicU32,
    pub origin_signature: Option<Box<[u8; 64]>>,
    pub issuer_pubkey: Option<Box<[u8; 32]>>,
    pub expiration: AtomicU64,
    pub usage_count: AtomicU64,
    pub max_delegations: AtomicU32,
    pub quantum_proof: Option<Box<[u8; 128]>>,
}

impl CapabilitySet {
    pub fn new() -> Self {
        Self {
            capabilities: AtomicU64::new(0),
            delegation_depth: AtomicU32::new(0),
            origin_signature: None,
            issuer_pubkey: None,
            expiration: AtomicU64::new(u64::MAX),
            usage_count: AtomicU64::new(0),
            max_delegations: AtomicU32::new(0),
            quantum_proof: None,
        }
    }

    pub fn has_capability(&self, cap: Capability) -> bool {
        if self.is_expired() {
            return false;
        }
        (self.capabilities.load(Ordering::Acquire) & (cap as u64)) != 0
    }

    pub fn grant_capability(&self, cap: Capability) {
        self.capabilities.fetch_or(cap as u64, Ordering::Release);
    }

    pub fn revoke_capability(&self, cap: Capability) {
        self.capabilities.fetch_and(!(cap as u64), Ordering::Release);
    }

    pub fn is_expired(&self) -> bool {
        let current_time = crate::time::get_kernel_time_ns();
        current_time > self.expiration.load(Ordering::Acquire)
    }

    pub fn use_capability(&self) -> bool {
        if self.is_expired() {
            return false;
        }
        self.usage_count.fetch_add(1, Ordering::Release);
        true
    }

    pub fn can_delegate(&self) -> bool {
        self.delegation_depth.load(Ordering::Acquire) < self.max_delegations.load(Ordering::Acquire)
    }
}
