// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

/*
 * Tamper-Evident Audit Log.
 *
 * Cryptographically chained boot audit trail. Each entry commits
 * to all previous entries via rolling hash. Detects log tampering.
 *
 * Passed to kernel for post-boot forensics and attestation.
 */

use spin::Mutex;

pub use super::types::{AuditEntry, AuditEvent, AUDIT_MSG_LEN};

const DS_AUDIT: &str = "NONOS:AUDIT:LOG:v1";
const MAX_AUDIT_ENTRIES: usize = 64;

pub struct AuditLog {
    entries: [AuditEntry; MAX_AUDIT_ENTRIES],
    count: usize,
    running_hash: [u8; 32],
    sealed: bool,
}

impl AuditLog {
    pub const fn new() -> Self {
        Self {
            entries: [AuditEntry::empty(); MAX_AUDIT_ENTRIES],
            count: 0,
            running_hash: [0u8; 32],
            sealed: false,
        }
    }

    pub fn record(&mut self, event: AuditEvent, timestamp: u64, message: &[u8]) {
        if self.sealed || self.count >= MAX_AUDIT_ENTRIES {
            return;
        }

        let mut entry = AuditEntry::empty();
        entry.event = event;
        entry.timestamp = timestamp;
        entry.msg_len = message.len().min(AUDIT_MSG_LEN);
        entry.message[..entry.msg_len].copy_from_slice(&message[..entry.msg_len]);

        let entry_hash = self.compute_entry_hash(&entry);
        entry.chain_hash = entry_hash;
        self.running_hash = entry_hash;

        self.entries[self.count] = entry;
        self.count += 1;
    }

    fn compute_entry_hash(&self, entry: &AuditEntry) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DS_AUDIT);
        hasher.update(&self.running_hash);
        hasher.update(&entry.to_bytes());
        *hasher.finalize().as_bytes()
    }

    pub fn seal(&mut self) {
        self.sealed = true;
    }

    pub fn verify_integrity(&self) -> bool {
        if self.count == 0 {
            return true;
        }

        let mut prev_hash = [0u8; 32];

        for i in 0..self.count {
            let entry = &self.entries[i];

            let mut hasher = blake3::Hasher::new_derive_key(DS_AUDIT);
            hasher.update(&prev_hash);
            hasher.update(&entry.to_bytes());
            let expected = *hasher.finalize().as_bytes();

            if !constant_time_eq_32(&expected, &entry.chain_hash) {
                return false;
            }

            prev_hash = entry.chain_hash;
        }

        true
    }

    pub fn get_final_hash(&self) -> [u8; 32] {
        self.running_hash
    }

    pub fn get_count(&self) -> usize {
        self.count
    }

    pub fn get_entry(&self, idx: usize) -> Option<&AuditEntry> {
        if idx < self.count {
            Some(&self.entries[idx])
        } else {
            None
        }
    }
}

#[inline(never)]
fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub static AUDIT_LOG: Mutex<AuditLog> = Mutex::new(AuditLog::new());

pub fn audit(event: AuditEvent, timestamp: u64, message: &[u8]) {
    let mut log = AUDIT_LOG.lock();
    log.record(event, timestamp, message);
}

pub fn audit_alert(timestamp: u64, message: &[u8]) {
    audit(AuditEvent::SecurityAlert, timestamp, message);
}

pub fn seal_audit_log() {
    let mut log = AUDIT_LOG.lock();
    log.seal();
}

pub fn verify_audit_integrity() -> bool {
    let log = AUDIT_LOG.lock();
    log.verify_integrity()
}

pub fn get_audit_hash() -> [u8; 32] {
    let log = AUDIT_LOG.lock();
    log.get_final_hash()
}
