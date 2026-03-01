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
use alloc::{vec::Vec, string::String};
use core::sync::atomic::AtomicU64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QuantumAlgorithm {
    Kyber1024,
    Kyber768,
    Dilithium3,
    SphincsPlus128s,
    NtruHps4096821,
    McEliece348864,
    Lattice,
}

#[derive(Debug)]
pub struct QuantumKey {
    pub algo: QuantumAlgorithm,
    pub key_id: [u8; 32],
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub usage_count: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct QuantumKeyRotation {
    pub old_key_id: [u8; 32],
    pub new_key_id: [u8; 32],
    pub rotated_at: u64,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct QuantumKeyRotationPolicy {
    pub rotation_interval_secs: u64,
    pub max_usage: u64,
    pub enforce_expiry: bool,
}

impl Default for QuantumKeyRotationPolicy {
    fn default() -> Self {
        Self {
            rotation_interval_secs: 86400,
            max_usage: 10000,
            enforce_expiry: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuantumAuditEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub details: String,
    pub key_id: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct QuantumSecurityStats {
    pub key_count: u64,
    pub compliance_events: u64,
    pub qkd_count: u64,
    pub entropy_bits: f64,
    pub threat_detections: u64,
    pub trust_verifications: u64,
}

pub trait ThreatDetectionEngine {
    fn detect_threat(&self, input: &[u8]) -> Option<String>;
    fn report(&self) -> u64;
}
