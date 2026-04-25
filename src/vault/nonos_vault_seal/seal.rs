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
use crate::arch::x86_64::uefi::{set_variable as uefi_set_variable, Guid, VariableAttributes};
use crate::crypto::hash::blake3_hash;
use crate::crypto::{aes256_gcm_encrypt, get_random_bytes};
use crate::fs::nonos_filesystem::NonosFilesystem;
use crate::vault::nonos_vault::{VaultAuditEvent, NONOS_VAULT};
use alloc::{format, string::String, vec::Vec};

fn hexify(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

impl VaultSealStore {
    pub fn seal_secret(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        policy: SealPolicy,
    ) -> Result<SealedSecret, &'static str> {
        if !NONOS_VAULT.is_initialized() {
            return Err("Vault not initialized");
        }
        let ts = crate::time::timestamp_millis();
        let audit = VaultAuditEvent {
            timestamp: ts,
            event: "seal_secret".into(),
            context: Some(hexify(&blake3_hash(plaintext))),
            status: Some(format!("{:?}", policy)),
        };
        let sealed_data = seal_with_policy(plaintext, aad, &policy)?;
        let entry = SealedSecret {
            sealed_data,
            aad: aad.to_vec(),
            policy: policy.clone(),
            timestamp: ts,
            audit: audit.clone(),
        };
        self.sealed.lock().push(entry.clone());
        NONOS_VAULT.audit_log().lock().push(audit);
        Ok(entry)
    }
}

fn seal_with_policy(
    plaintext: &[u8],
    aad: &[u8],
    policy: &SealPolicy,
) -> Result<Vec<u8>, &'static str> {
    let master_key_guard = NONOS_VAULT.master_key().read();
    let master_key = master_key_guard.as_ref().ok_or("No master key")?;
    if master_key.len() < 32 {
        return Err("Master key too short");
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&get_random_bytes()[..12]);
    let key32: &[u8; 32] = master_key[..32].try_into().map_err(|_| "Key conversion failed")?;
    let ct = aes256_gcm_encrypt(key32, &nonce, aad, plaintext)?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&ct);
    match policy {
        SealPolicy::RAMOnly => {}
        SealPolicy::UEFI => {
            uefi_set_variable(
                "NONOS_VAULT_SECRET",
                &Guid::GLOBAL_VARIABLE,
                VariableAttributes::NON_VOLATILE | VariableAttributes::RUNTIME_ACCESS,
                &sealed,
            )
            .map_err(|_| "UEFI variable store failed")?;
        }
        SealPolicy::Disk => {
            let fs = NonosFilesystem::new();
            fs.create_file("nonos_vault.sealed", &sealed)?;
        }
        SealPolicy::Custom(backend) => {
            let fs = NonosFilesystem::new();
            fs.create_file(&format!("/vault/{}/sealed", backend), &sealed)?;
        }
    }
    Ok(sealed)
}
