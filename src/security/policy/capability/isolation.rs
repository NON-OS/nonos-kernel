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

use core::sync::atomic::{AtomicU64, AtomicU32};
use spin::{RwLock, Mutex};
use alloc::{vec::Vec, collections::BTreeMap};

use super::types::CapabilitySet;
use super::attestation::AttestationLink;
use super::quantum::QuantumState;

#[derive(Debug, Clone, Copy)]
pub enum IsolationLevel {
    None,
    Basic,
    Cryptographic,
    Ephemeral,
    ZeroState,
    QuantumSecure,
}

#[derive(Debug)]
pub struct IsolationChamber {
    pub id: u64,
    pub level: IsolationLevel,
    pub memory_encryption_key: [u8; 32],
    pub sealed_memory_regions: RwLock<Vec<SealedMemoryRegion>>,
    pub capability_whitelist: CapabilitySet,
    pub execution_context: RwLock<ExecutionContext>,
    pub attestation_chain: RwLock<Vec<AttestationLink>>,
    pub quantum_entanglement: Option<QuantumState>,
    pub ephemeral_keys: RwLock<BTreeMap<u64, [u8; 32]>>,
    pub secure_rng_state: Mutex<[u8; 32]>,
    pub chamber_signature: [u8; 64],
    pub creation_timestamp: u64,
    pub last_access_timestamp: AtomicU64,
    pub access_count: AtomicU64,
    pub violation_count: AtomicU32,
    pub auto_destruct_timer: AtomicU64,
}

#[derive(Debug)]
pub struct SealedMemoryRegion {
    pub start_addr: u64,
    pub size: u64,
    pub protection: u32,
    pub encryption_key: [u8; 32],
    pub integrity_hash: [u8; 32],
    pub access_pattern_hash: [u8; 32],
    pub sealed: bool,
    pub ephemeral: bool,
    pub quantum_locked: bool,
}

#[derive(Debug)]
pub struct ExecutionContext {
    pub process_id: u64,
    pub thread_count: u32,
    pub cpu_quota: u64,
    pub memory_limit: u64,
    pub io_bandwidth_limit: u64,
    pub syscall_budget: u32,
    pub crypto_operations_budget: u32,
    pub network_connections_limit: u16,
    pub file_handles_limit: u16,
    pub execution_time_limit: u64,
    pub quantum_operations_budget: u16,
}
