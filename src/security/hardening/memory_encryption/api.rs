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

use super::engine::{
    aes_gcm_decrypt, aes_gcm_encrypt, derive_region_key, generate_nonce, is_initialized,
    rotate_master_key,
};
use super::region::{get_region, register_region, unregister_region, update_region};
use super::types::EncryptionError;

pub fn encrypt_region(start: u64, size: usize) -> Result<(), EncryptionError> {
    if !is_initialized() {
        return Err(EncryptionError::NotInitialized);
    }
    let mut region = get_region(start).ok_or(EncryptionError::RegionNotFound)?;
    if region.encrypted {
        return Ok(());
    }
    if region.size != size {
        return Err(EncryptionError::SizeMismatch);
    }
    let key = derive_region_key(region.key_id);
    let nonce = generate_nonce();
    let data = unsafe { core::slice::from_raw_parts_mut(start as *mut u8, size) };
    let tag = aes_gcm_encrypt(&key, &nonce, data);
    region.nonce = nonce;
    region.tag = tag;
    region.encrypted = true;
    update_region(region);
    Ok(())
}

pub fn decrypt_region(start: u64, size: usize) -> Result<(), EncryptionError> {
    if !is_initialized() {
        return Err(EncryptionError::NotInitialized);
    }
    let mut region = get_region(start).ok_or(EncryptionError::RegionNotFound)?;
    if !region.encrypted {
        return Ok(());
    }
    if region.size != size {
        return Err(EncryptionError::SizeMismatch);
    }
    let key = derive_region_key(region.key_id);
    let data = unsafe { core::slice::from_raw_parts_mut(start as *mut u8, size) };
    if !aes_gcm_decrypt(&key, &region.nonce, data, &region.tag) {
        return Err(EncryptionError::AuthenticationFailed);
    }
    region.encrypted = false;
    update_region(region);
    Ok(())
}

pub fn protect_sensitive(ptr: *mut u8, size: usize) -> Result<u64, EncryptionError> {
    let start = ptr as u64;
    let key_id = register_region(start, size)?;
    encrypt_region(start, size)?;
    Ok(key_id)
}

pub fn unprotect_sensitive(ptr: *mut u8, size: usize) -> Result<(), EncryptionError> {
    let start = ptr as u64;
    decrypt_region(start, size)?;
    unregister_region(start)
}

pub fn rotate_keys() {
    rotate_master_key();
    crate::security::monitoring::audit::log_security_event(
        "memencrypt",
        crate::security::monitoring::audit::AuditSeverity::Info,
        alloc::format!("Memory encryption master key rotated"),
        None,
        None,
        None,
    );
}
