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
use super::store::VaultSealStore;
use super::types::{SealPolicy, SealedSecret};
use crate::arch::x86_64::uefi::{get_variable as uefi_get_variable, Guid};
use crate::crypto::aes256_gcm_decrypt;
use crate::crypto::hash::blake3_hash;
use crate::fs::nonos_filesystem::NonosFilesystem;
use crate::vault::nonos_vault::{VaultAuditEvent, NONOS_VAULT};
use alloc::{format, string::String, vec::Vec};

fn hexify(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

impl VaultSealStore {
    pub fn unseal_secret(&self, sealed: &SealedSecret) -> Result<Vec<u8>, &'static str> {
        if !NONOS_VAULT.is_initialized() {
            return Err("Vault not initialized");
        }
        let pt = unseal_from_policy(sealed)?;
        let audit = VaultAuditEvent {
            timestamp: crate::time::timestamp_millis(),
            event: "unseal_secret".into(),
            context: Some(hexify(&blake3_hash(&pt))),
            status: Some(format!("{:?}", sealed.policy)),
        };
        NONOS_VAULT.audit_log().lock().push(audit);
        Ok(pt)
    }
}

fn unseal_from_policy(sealed: &SealedSecret) -> Result<Vec<u8>, &'static str> {
    let sealed_buf = match &sealed.policy {
        SealPolicy::RAMOnly => sealed.sealed_data.clone(),
        SealPolicy::UEFI => {
            let var = uefi_get_variable("NONOS_VAULT_SECRET", &Guid::GLOBAL_VARIABLE)
                .ok_or("UEFI variable not found")?;
            var.data
        }
        SealPolicy::Disk => NonosFilesystem::new().read_file("nonos_vault.sealed")?,
        SealPolicy::Custom(backend) => {
            NonosFilesystem::new().read_file(&format!("/vault/{}/sealed", backend))?
        }
    };
    let master_key_guard = NONOS_VAULT.master_key().read();
    let master_key = master_key_guard.as_ref().ok_or("No master key")?;
    if master_key.len() < 32 {
        return Err("Master key too short");
    }
    if sealed_buf.len() < 12 + 16 {
        return Err("Sealed data too short");
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sealed_buf[..12]);
    let ct_and_tag = &sealed_buf[12..];
    let key32: &[u8; 32] = master_key[..32].try_into().map_err(|_| "Key conversion failed")?;
    aes256_gcm_decrypt(key32, &nonce, &sealed.aad, ct_and_tag)
}
