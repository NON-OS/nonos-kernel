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
use alloc::string::String;
use alloc::vec::Vec;
use crate::crypto::constant_time::ct_eq_32;
use super::types::{TrustedKey, SecureBootError, SecureBootResult};
use super::state::TRUSTED_BOOT_KEYS;

pub fn load_embedded_keys() -> SecureBootResult<()> {
    let mut keys = TRUSTED_BOOT_KEYS.write();

    let primary_key = TrustedKey {
        name: String::from("NONOS-PRIMARY-2024"),
        public_key: [
            0xb0, 0x79, 0xa0, 0xf5, 0xe0, 0xba, 0xaa, 0xe2,
            0xeb, 0x66, 0x2d, 0x28, 0xd5, 0xc2, 0x20, 0x9b,
            0x76, 0x37, 0xe1, 0xbd, 0xb5, 0x1a, 0xef, 0x45,
            0xa9, 0xa0, 0xcb, 0x64, 0xe1, 0xb6, 0x50, 0xe6,
        ],
        fingerprint: [0u8; 32],
        created_at: 1702500000,
        expires_at: 0,
        is_production: true,
    };

    let mut key_with_fp = primary_key.clone();
    key_with_fp.fingerprint = crate::crypto::blake3::blake3_hash(&key_with_fp.public_key);
    keys.production_keys.push(key_with_fp);

    let backup_key = TrustedKey {
        name: String::from("NONOS-BACKUP-2024"),
        public_key: [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x83, 0x95,
            0xa2, 0xf3, 0xb5, 0xc3, 0x8c, 0x88, 0x4c, 0xd8,
            0x79, 0x3f, 0x9d, 0x7c, 0x6a, 0x29, 0x8e, 0x53,
            0x58, 0x4c, 0xe8, 0xf0, 0x7b, 0x5e, 0x67, 0x94,
        ],
        fingerprint: [0u8; 32],
        created_at: 1702500000,
        expires_at: 0,
        is_production: true,
    };

    let mut backup_with_fp = backup_key.clone();
    backup_with_fp.fingerprint = crate::crypto::blake3::blake3_hash(&backup_with_fp.public_key);
    keys.production_keys.push(backup_with_fp);

    let recovery_key = TrustedKey {
        name: String::from("NONOS-RECOVERY-2024"),
        public_key: [
            0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3,
            0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
            0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac,
            0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
        ],
        fingerprint: [0u8; 32],
        created_at: 1702500000,
        expires_at: 0,
        is_production: true,
    };

    let mut recovery_with_fp = recovery_key.clone();
    recovery_with_fp.fingerprint = crate::crypto::blake3::blake3_hash(&recovery_with_fp.public_key);
    keys.production_keys.push(recovery_with_fp);

    crate::log::info!("[SECURE_BOOT] Loaded {} production keys", keys.production_keys.len());

    Ok(())
}

pub fn add_trusted_key(key: TrustedKey) -> SecureBootResult<()> {
    if let Some(proc) = crate::process::current_process() {
        let token = proc.capability_token();
        if !token.grants(crate::capabilities::Capability::Admin) {
            return Err(SecureBootError::PolicyViolation);
        }
    }

    let mut keys = TRUSTED_BOOT_KEYS.write();

    let mut key_with_fp = key;
    key_with_fp.fingerprint = crate::crypto::blake3::blake3_hash(&key_with_fp.public_key);

    for existing in &keys.production_keys {
        if ct_eq_32(&existing.fingerprint, &key_with_fp.fingerprint) {
            return Ok(());
        }
    }

    if key_with_fp.is_production {
        keys.production_keys.push(key_with_fp.clone());
    } else {
        keys.development_keys.push(key_with_fp.clone());
    }

    keys.rotation_count += 1;

    crate::log::info!("[SECURE_BOOT] Added trusted key: {}", key_with_fp.name);

    Ok(())
}

pub fn revoke_key(fingerprint: [u8; 32]) -> SecureBootResult<()> {
    if let Some(proc) = crate::process::current_process() {
        let token = proc.capability_token();
        if !token.grants(crate::capabilities::Capability::Admin) {
            return Err(SecureBootError::PolicyViolation);
        }
    }

    let mut keys = TRUSTED_BOOT_KEYS.write();

    for revoked in &keys.revoked_fingerprints {
        if ct_eq_32(revoked, &fingerprint) {
            return Ok(());
        }
    }

    keys.revoked_fingerprints.push(fingerprint);
    keys.rotation_count += 1;

    crate::log::log_warning!("[SECURE_BOOT] Key REVOKED: {:02x?}...", &fingerprint[..8]);

    Ok(())
}

pub fn list_trusted_keys() -> Vec<([u8; 32], String, bool)> {
    let keys = TRUSTED_BOOT_KEYS.read();
    let mut result = Vec::new();

    for key in &keys.production_keys {
        result.push((key.fingerprint, key.name.clone(), true));
    }

    for key in &keys.development_keys {
        result.push((key.fingerprint, key.name.clone(), false));
    }

    result
}
