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

use super::error::UefiError;
use super::manager::UEFI_MANAGER;
use super::types::Guid;

#[derive(Debug, Clone)]
pub struct SecureBootStatus {
    pub enabled: bool,
    pub setup_mode: bool,
    pub has_pk: bool,
    pub has_kek: bool,
    pub has_db: bool,
    pub has_dbx: bool,
    pub db_entry_count: usize,
    pub dbx_entry_count: usize,
}

impl SecureBootStatus {
    pub fn is_fully_configured(&self) -> bool {
        self.enabled && self.has_pk && self.has_kek && self.has_db
    }

    pub fn can_modify_keys(&self) -> bool {
        self.setup_mode
    }
}

impl Default for SecureBootStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            setup_mode: true,
            has_pk: false,
            has_kek: false,
            has_db: false,
            has_dbx: false,
            db_entry_count: 0,
            dbx_entry_count: 0,
        }
    }
}

pub fn is_enabled() -> bool {
    UEFI_MANAGER.is_secure_boot_enabled()
}

pub fn is_setup_mode() -> bool {
    UEFI_MANAGER.is_setup_mode()
}

pub fn verify_binary(binary_hash: &[u8; 32]) -> bool {
    UEFI_MANAGER.verify_hash(binary_hash).is_ok()
}

pub fn verify_hash(hash: &[u8]) -> Result<(), UefiError> {
    UEFI_MANAGER.verify_hash(hash)
}

pub fn authorize_signature(signature: &[u8; 32]) -> Result<(), UefiError> {
    UEFI_MANAGER.authorize_hash(signature)
}

pub fn authorize_hash(hash: &[u8]) -> Result<(), UefiError> {
    UEFI_MANAGER.authorize_hash(hash)
}

pub fn revoke_signature(signature: &[u8; 32]) -> Result<(), UefiError> {
    UEFI_MANAGER.revoke_hash(signature)
}

pub fn revoke_hash(hash: &[u8]) -> Result<(), UefiError> {
    UEFI_MANAGER.revoke_hash(hash)
}

pub fn get_status() -> SecureBootStatus {
    let has_pk = UEFI_MANAGER.get_variable("PK", &Guid::GLOBAL_VARIABLE).is_ok();
    let has_kek = UEFI_MANAGER.get_variable("KEK", &Guid::GLOBAL_VARIABLE).is_ok();

    let (has_db, db_count) = match UEFI_MANAGER.get_signature_database() {
        Ok(lists) => (true, lists.iter().map(|l| l.entry_count()).sum()),
        Err(_) => (false, 0),
    };

    let (has_dbx, dbx_count) = match UEFI_MANAGER.get_revoked_database() {
        Ok(lists) => (true, lists.iter().map(|l| l.entry_count()).sum()),
        Err(_) => (false, 0),
    };

    SecureBootStatus {
        enabled: is_enabled(),
        setup_mode: is_setup_mode(),
        has_pk,
        has_kek,
        has_db,
        has_dbx,
        db_entry_count: db_count,
        dbx_entry_count: dbx_count,
    }
}

pub fn get_authorized_hashes() -> Result<usize, UefiError> {
    let lists = UEFI_MANAGER.get_signature_database()?;
    Ok(lists.iter().map(|l| l.entry_count()).sum())
}

pub fn get_revoked_hashes() -> Result<usize, UefiError> {
    let lists = UEFI_MANAGER.get_revoked_database()?;
    Ok(lists.iter().map(|l| l.entry_count()).sum())
}

pub fn is_hash_authorized(hash: &[u8]) -> bool {
    if let Ok(lists) = UEFI_MANAGER.get_signature_database() {
        super::signature::hash_in_signature_lists(hash, &lists)
    } else {
        false
    }
}

pub fn is_hash_revoked(hash: &[u8]) -> bool {
    if let Ok(lists) = UEFI_MANAGER.get_revoked_database() {
        super::signature::hash_in_signature_lists(hash, &lists)
    } else {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    Allowed,
    NotInDatabase,
    Revoked,
    SecureBootDisabled,
}

pub fn verify_with_result(hash: &[u8]) -> VerificationResult {
    if !is_enabled() {
        return VerificationResult::SecureBootDisabled;
    }

    if is_hash_revoked(hash) {
        return VerificationResult::Revoked;
    }

    if is_hash_authorized(hash) {
        return VerificationResult::Allowed;
    }

    VerificationResult::NotInDatabase
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_default() {
        let status = SecureBootStatus::default();
        assert!(!status.enabled);
        assert!(status.setup_mode);
        assert!(!status.has_pk);
    }

    #[test]
    fn test_status_fully_configured() {
        let status = SecureBootStatus {
            enabled: true,
            setup_mode: false,
            has_pk: true,
            has_kek: true,
            has_db: true,
            has_dbx: true,
            db_entry_count: 10,
            dbx_entry_count: 5,
        };
        assert!(status.is_fully_configured());
        assert!(!status.can_modify_keys());
    }

    #[test]
    fn test_verification_result() {
        assert_eq!(VerificationResult::Allowed, VerificationResult::Allowed);
        assert_ne!(VerificationResult::Allowed, VerificationResult::Revoked);
    }
}
