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

//! NONOS Vault Seal Module - (RAM, UEFI, Disk)

extern crate alloc;
use alloc::{vec::Vec, string::String};
use spin::Mutex;
use crate::vault::nonos_vault::{NONOS_VAULT, VaultAuditEvent};
use crate::crypto::{aes256_gcm_encrypt, aes256_gcm_decrypt, get_random_bytes};
use crate::crypto::hash::blake3_hash;
use crate::arch::x86_64::uefi::{set_variable as uefi_set_variable, get_variable as uefi_get_variable, Guid, VariableAttributes};
use crate::fs::nonos_filesystem::NonosFilesystem;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealPolicy {
    RAMOnly,
    UEFI,
    Disk,
    Custom(String),
}

#[derive(Clone, Debug)]
pub struct SealedSecret {
    pub sealed_data: Vec<u8>,
    pub aad: Vec<u8>,
    pub policy: SealPolicy,
    pub timestamp: u64,
    pub audit: VaultAuditEvent,
}

pub struct VaultSealStore {
    sealed: Mutex<Vec<SealedSecret>>,
}

impl VaultSealStore {
    pub const fn new() -> Self {
        Self { sealed: Mutex::new(Vec::new()) }
    }

    pub fn seal_secret(&self, plaintext: &[u8], aad: &[u8], policy: SealPolicy) -> Result<SealedSecret, &'static str> {
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
        let sealed_data = match &policy {
            SealPolicy::RAMOnly => {
                let master_key_guard = NONOS_VAULT.master_key().read();
                let master_key = master_key_guard.as_ref().ok_or("No master key")?;
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&get_random_bytes()[..12]);
                if master_key.len() < 32 {
                    return Err("Master key too short");
                }
                let key32: &[u8; 32] = master_key[..32].try_into().map_err(|_| "Key conversion failed")?;
                let ct = aes256_gcm_encrypt(key32, &nonce, aad, plaintext)?;
                let mut sealed = nonce.to_vec();
                sealed.extend_from_slice(&ct);
                sealed
            }
            SealPolicy::UEFI => {
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
                // Store in UEFI variable
                uefi_set_variable(
                    "NONOS_VAULT_SECRET",
                    &Guid::GLOBAL_VARIABLE,
                    VariableAttributes::NON_VOLATILE | VariableAttributes::RUNTIME_ACCESS,
                    &sealed,
                ).map_err(|_| "UEFI variable store failed")?;
                sealed
            }
            SealPolicy::Disk => {
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
                // Store in file (using RAM or encrypted filesystem)
                let fs = NonosFilesystem::new();
                fs.create_file("nonos_vault.sealed", &sealed)?;
                sealed
            }
            SealPolicy::Custom(backend) => {
                // Custom backend: uses the backend name as a path prefix for file storage
                // e.g., Custom("secure_enclave") stores in /vault/secure_enclave/sealed
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
                // Store in custom backend path
                // Note: Directories in NONOS are implicit - files can be created at any path
                let fs = NonosFilesystem::new();
                let file_path = alloc::format!("/vault/{}/sealed", backend);
                fs.create_file(&file_path, &sealed)?;
                sealed
            }
        };
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

    pub fn unseal_secret(&self, sealed: &SealedSecret) -> Result<Vec<u8>, &'static str> {
        if !NONOS_VAULT.is_initialized() {
            return Err("Vault not initialized");
        }
        let pt = match &sealed.policy {
            SealPolicy::RAMOnly => {
                let master_key_guard = NONOS_VAULT.master_key().read();
                let master_key = master_key_guard.as_ref().ok_or("No master key")?;
                if master_key.len() < 32 {
                    return Err("Master key too short");
                }
                if sealed.sealed_data.len() < 12 + 16 {
                    return Err("Sealed data too short");
                }
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&sealed.sealed_data[..12]);
                let ct_and_tag = &sealed.sealed_data[12..];
                let key32: &[u8; 32] = master_key[..32].try_into().map_err(|_| "Key conversion failed")?;
                aes256_gcm_decrypt(key32, &nonce, &sealed.aad, ct_and_tag)?
            }
            SealPolicy::UEFI => {
                // Read from UEFI variable
                let var = uefi_get_variable("NONOS_VAULT_SECRET", &Guid::GLOBAL_VARIABLE)
                    .ok_or("UEFI variable not found")?;
                let sealed_buf = var.data;
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
                aes256_gcm_decrypt(key32, &nonce, &sealed.aad, ct_and_tag)?
            }
            SealPolicy::Disk => {
                // Read from file
                let fs = NonosFilesystem::new();
                let sealed_buf = fs.read_file("nonos_vault.sealed")?;
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
                aes256_gcm_decrypt(key32, &nonce, &sealed.aad, ct_and_tag)?
            }
            SealPolicy::Custom(backend) => {
                // Read from custom backend path
                let fs = NonosFilesystem::new();
                let file_path = alloc::format!("/vault/{}/sealed", backend);
                let sealed_buf = fs.read_file(&file_path)?;
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
                aes256_gcm_decrypt(key32, &nonce, &sealed.aad, ct_and_tag)?
            }
        };
        let audit = VaultAuditEvent {
            timestamp: crate::time::timestamp_millis(),
            event: "unseal_secret".into(),
            context: Some(hexify(&blake3_hash(&pt))),
            status: Some(format!("{:?}", sealed.policy)),
        };
        NONOS_VAULT.audit_log().lock().push(audit);
        Ok(pt)
    }

    pub fn list_sealed(&self) -> Vec<SealedSecret> {
        self.sealed.lock().clone()
    }

    pub fn secure_erase_sealed(&self, backend: Option<SealPolicy>) {
        let mut sealed = self.sealed.lock();
        for entry in sealed.iter_mut() {
            for b in entry.sealed_data.iter_mut() {
                unsafe { core::ptr::write_volatile(b, 0) };
            }
            entry.sealed_data.clear();
        }
        sealed.clear();
        if let Some(ref policy) = backend {
            match policy {
                SealPolicy::UEFI => {
                    // Overwrite UEFI variable
                    let _ = uefi_set_variable(
                        "NONOS_VAULT_SECRET",
                        &Guid::GLOBAL_VARIABLE,
                        VariableAttributes::NON_VOLATILE | VariableAttributes::RUNTIME_ACCESS,
                        &[],
                    );
                }
                SealPolicy::Disk => {
                    let fs = NonosFilesystem::new();
                    let _ = fs.delete_file("nonos_vault.sealed");
                }
                SealPolicy::Custom(_) | SealPolicy::RAMOnly => {}
            }
        }
        let audit = VaultAuditEvent {
            timestamp: crate::time::timestamp_millis(),
            event: "secure_erase_sealed".into(),
            context: backend.map(|b| format!("{:?}", b)),
            status: Some("success".into()),
        };
        NONOS_VAULT.audit_log().lock().push(audit);
    }
}

// Utility: Format hash bytes as hex
fn hexify(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------- Global instance ----------
pub static VAULT_SEAL_STORE: VaultSealStore = VaultSealStore::new();

// ---------- Public API ----------
pub fn seal_secret(plaintext: &[u8], aad: &[u8], policy: SealPolicy) -> Result<SealedSecret, &'static str> {
    VAULT_SEAL_STORE.seal_secret(plaintext, aad, policy)
}
pub fn unseal_secret(sealed: &SealedSecret) -> Result<Vec<u8>, &'static str> {
    VAULT_SEAL_STORE.unseal_secret(sealed)
}
pub fn list_sealed() -> Vec<SealedSecret> {
    VAULT_SEAL_STORE.list_sealed()
}
pub fn secure_erase_sealed(backend: Option<SealPolicy>) {
    VAULT_SEAL_STORE.secure_erase_sealed(backend)
}
