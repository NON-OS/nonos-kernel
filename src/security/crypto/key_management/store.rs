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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;
use super::entry::KeyEntry;
use super::audit::{KeyAuditEntry, KeyOperation};
use super::errors::{KeyError, KeyResult};
use crate::crypto::constant_time::secure_erase;

pub static KEY_STORE: RwLock<KeyStore> = RwLock::new(KeyStore::new());
pub static KEY_STORE_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub struct KeyStore {
    pub(super) keys: BTreeMap<u64, KeyEntry>,
    pub(super) next_id: u64,
    pub(super) master_key: Option<[u8; 32]>,
    pub(super) audit_log: Vec<KeyAuditEntry>,
    pub(super) max_audit_entries: usize,
}

impl KeyStore {
    pub const fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            next_id: 1,
            master_key: None,
            audit_log: Vec::new(),
            max_audit_entries: 1000,
        }
    }

    pub fn log_operation(
        &mut self,
        operation: KeyOperation,
        key_id: u64,
        fingerprint: [u8; 32],
        caller: u64,
        success: bool,
    ) {
        if self.audit_log.len() >= self.max_audit_entries {
            self.audit_log.remove(0);
        }
        self.audit_log.push(KeyAuditEntry::new(operation, key_id, fingerprint, caller, success));
    }

    pub fn clear_all(&mut self) {
        for (_, entry) in self.keys.iter_mut() {
            entry.secure_clear();
        }
        self.keys.clear();

        if let Some(ref mut master) = self.master_key {
            secure_erase(master);
        }
        self.master_key = None;
    }
}

pub fn init() -> KeyResult<()> {
    if KEY_STORE_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut store = KEY_STORE.write();
    let mut master = [0u8; 32];
    crate::crypto::rng::fill_bytes(&mut master);

    if master.iter().all(|&b| b == 0) {
        return Err(KeyError::CryptoError);
    }

    store.master_key = Some(master);
    KEY_STORE_INITIALIZED.store(true, Ordering::SeqCst);

    crate::log::info!("[KEY_MGMT] Key management system initialized");
    Ok(())
}
