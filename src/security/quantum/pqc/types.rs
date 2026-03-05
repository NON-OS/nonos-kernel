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

impl QuantumKey {
    /// Get the algorithm type
    pub fn algorithm(&self) -> &QuantumAlgorithm {
        &self.algo
    }

    /// Get the key ID
    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    /// Get the public key
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Get the secret key (use with caution)
    pub fn secret_key(&self) -> &[u8] {
        &self.secret
    }

    /// Get creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get expiration timestamp
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Get usage count
    pub fn get_usage_count(&self) -> u64 {
        self.usage_count.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Increment usage count
    pub fn increment_usage(&self) {
        self.usage_count.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    /// Check if key is expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires_at
    }
}

#[derive(Debug, Clone)]
pub struct QuantumKeyRotation {
    pub old_key_id: [u8; 32],
    pub new_key_id: [u8; 32],
    pub rotated_at: u64,
    pub reason: String,
}

impl QuantumKeyRotation {
    /// Get the old key ID
    pub fn old_key_id(&self) -> &[u8; 32] {
        &self.old_key_id
    }

    /// Get the new key ID
    pub fn new_key_id(&self) -> &[u8; 32] {
        &self.new_key_id
    }

    /// Get rotation timestamp
    pub fn rotated_at(&self) -> u64 {
        self.rotated_at
    }

    /// Get rotation reason
    pub fn reason(&self) -> &str {
        &self.reason
    }
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

impl QuantumKeyRotationPolicy {
    /// Get rotation interval in seconds
    pub fn rotation_interval(&self) -> u64 {
        self.rotation_interval_secs
    }

    /// Get max usage before rotation
    pub fn max_usage(&self) -> u64 {
        self.max_usage
    }

    /// Check if expiry enforcement is enabled
    pub fn enforces_expiry(&self) -> bool {
        self.enforce_expiry
    }

    /// Check if key needs rotation based on age
    pub fn needs_rotation_by_age(&self, created_at: u64, current_time: u64) -> bool {
        current_time.saturating_sub(created_at) >= self.rotation_interval_secs
    }

    /// Check if key needs rotation based on usage
    pub fn needs_rotation_by_usage(&self, usage_count: u64) -> bool {
        usage_count >= self.max_usage
    }
}

#[derive(Debug, Clone)]
pub struct QuantumAuditEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub details: String,
    pub key_id: Option<[u8; 32]>,
}

impl QuantumAuditEvent {
    /// Get event timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get event type
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Get event details
    pub fn details(&self) -> &str {
        &self.details
    }

    /// Get associated key ID if any
    pub fn key_id(&self) -> Option<&[u8; 32]> {
        self.key_id.as_ref()
    }
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

impl QuantumSecurityStats {
    /// Get key count
    pub fn key_count(&self) -> u64 {
        self.key_count
    }

    /// Get compliance events count
    pub fn compliance_events(&self) -> u64 {
        self.compliance_events
    }

    /// Get QKD count
    pub fn qkd_count(&self) -> u64 {
        self.qkd_count
    }

    /// Get entropy bits
    pub fn entropy_bits(&self) -> f64 {
        self.entropy_bits
    }

    /// Get threat detections count
    pub fn threat_detections(&self) -> u64 {
        self.threat_detections
    }

    /// Get trust verifications count
    pub fn trust_verifications(&self) -> u64 {
        self.trust_verifications
    }
}

pub trait ThreatDetectionEngine {
    fn detect_threat(&self, input: &[u8]) -> Option<String>;
    fn report(&self) -> u64;
}
