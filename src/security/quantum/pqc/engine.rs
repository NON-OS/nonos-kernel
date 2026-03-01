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
use alloc::{vec::Vec, sync::Arc, format};
use super::types::{QuantumAlgorithm, QuantumKey, QuantumAuditEvent, ThreatDetectionEngine};
use super::vault::QuantumKeyVault;
use super::rng::QuantumRng;
use super::threat::KernelThreatAI;
use super::zerotrust::QuantumZeroTrust;
use super::audit::QuantumAuditLog;
use super::pq_ops::{pq_sign, pq_verify, pq_encapsulate, pq_decapsulate};

pub struct QuantumSecurityEngine {
    pub vault: Arc<QuantumKeyVault>,
    pub rng: Arc<QuantumRng>,
    pub threat_ai: Arc<KernelThreatAI>,
    pub zero_trust: Arc<QuantumZeroTrust>,
    pub audit: Arc<QuantumAuditLog>,
}

impl QuantumSecurityEngine {
    pub fn new() -> Self {
        Self {
            vault: Arc::new(QuantumKeyVault::new()),
            rng: Arc::new(QuantumRng::new()),
            threat_ai: Arc::new(KernelThreatAI::new()),
            zero_trust: Arc::new(QuantumZeroTrust::new()),
            audit: Arc::new(QuantumAuditLog::new()),
        }
    }

    pub fn generate_pq_key(&self, algo: QuantumAlgorithm, lifetime_secs: u64) -> Option<Arc<QuantumKey>> {
        let key = self.vault.generate_key(algo, lifetime_secs)?;
        self.audit.log_event("key_generated", "Post-quantum key generated", Some(key.key_id));
        Some(key)
    }

    pub fn rotate_pq_key(&self, key_id: &[u8; 32], reason: &str) -> Option<Arc<QuantumKey>> {
        let new_key = self.vault.rotate_key(key_id, reason);
        if let Some(ref k) = new_key {
            self.audit.log_event("key_rotated", reason, Some(k.key_id));
        }
        new_key
    }

    pub fn sign(&self, algo: QuantumAlgorithm, message: &[u8], sk: &[u8]) -> Result<Vec<u8>, &'static str> {
        pq_sign(&algo, message, sk)
    }

    pub fn verify(&self, algo: QuantumAlgorithm, message: &[u8], sig: &[u8], pk: &[u8]) -> Result<bool, &'static str> {
        pq_verify(&algo, message, sig, pk)
    }

    pub fn encapsulate(&self, algo: QuantumAlgorithm, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        pq_encapsulate(&algo, pk)
    }

    pub fn decapsulate(&self, algo: QuantumAlgorithm, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>, &'static str> {
        pq_decapsulate(&algo, ct, sk)
    }

    pub fn check_rng_health(&self) -> bool {
        self.rng.health_check()
    }

    pub fn detect_threat(&self, input: &[u8]) -> Option<alloc::string::String> {
        let res = self.threat_ai.detect_threat(input);
        if let Some(ref threat) = res {
            self.audit.log_event("threat_detected", threat, None);
        }
        res
    }

    pub fn set_trust_score(&self, key_id: [u8; 32], score: u8) {
        self.zero_trust.set_trust(key_id, score);
        self.audit.log_event("trust_score_set", &format!("Score: {}", score), Some(key_id));
    }

    pub fn verify_trust(&self, key_id: [u8; 32], min_score: u8) -> bool {
        self.zero_trust.verify(key_id, min_score)
    }

    pub fn recent_audit(&self, n: usize) -> Vec<QuantumAuditEvent> {
        self.audit.recent(n)
    }
}
