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

use alloc::vec::Vec;

use crate::arch::x86_64::uefi::error::UefiError;
use crate::arch::x86_64::uefi::signature::{build_signature_list, hash_in_signature_lists, parse_signature_lists, SignatureList};
use crate::arch::x86_64::uefi::types::Guid;
use super::core::UefiManager;

impl UefiManager {
    pub fn get_signature_database(&self) -> Result<Vec<SignatureList>, UefiError> {
        let var = self.get_variable("db", &Guid::IMAGE_SECURITY_DATABASE)?;
        parse_signature_lists(&var.data)
    }

    pub fn get_revoked_database(&self) -> Result<Vec<SignatureList>, UefiError> {
        let var = self.get_variable("dbx", &Guid::IMAGE_SECURITY_DATABASE)?;
        parse_signature_lists(&var.data)
    }

    pub fn verify_hash(&self, hash: &[u8]) -> Result<(), UefiError> {
        if !self.is_secure_boot_enabled() {
            return Ok(());
        }

        if let Ok(dbx_lists) = self.get_revoked_database() {
            if hash_in_signature_lists(hash, &dbx_lists) {
                return Err(UefiError::HashRevoked);
            }
        }

        if let Ok(db_lists) = self.get_signature_database() {
            if hash_in_signature_lists(hash, &db_lists) {
                return Ok(());
            }
        }

        Err(UefiError::HashNotInDatabase)
    }

    pub fn authorize_hash(&self, hash: &[u8]) -> Result<(), UefiError> {
        if !self.is_setup_mode() {
            return Err(UefiError::NotInSetupMode);
        }

        let sig_type = match hash.len() {
            32 => Guid::CERT_SHA256,
            48 => Guid::CERT_SHA384,
            64 => Guid::CERT_SHA512,
            _ => return Err(UefiError::InvalidParameter { param: "hash length" }),
        };

        let sig_list = build_signature_list(&sig_type, &Guid::NONOS_OWNER, hash);
        self.append_variable("db", &Guid::IMAGE_SECURITY_DATABASE, &sig_list)
    }

    pub fn revoke_hash(&self, hash: &[u8]) -> Result<(), UefiError> {
        if !self.is_setup_mode() {
            return Err(UefiError::NotInSetupMode);
        }

        let sig_type = match hash.len() {
            32 => Guid::CERT_SHA256,
            48 => Guid::CERT_SHA384,
            64 => Guid::CERT_SHA512,
            _ => return Err(UefiError::InvalidParameter { param: "hash length" }),
        };

        let sig_list = build_signature_list(&sig_type, &Guid::NONOS_OWNER, hash);
        self.append_variable("dbx", &Guid::IMAGE_SECURITY_DATABASE, &sig_list)
    }
}
