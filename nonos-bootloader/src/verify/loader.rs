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

use crate::log::logger::{log_error, log_info};
use crate::verify::capsule::{validate_capsule, CapsuleStatus};
use alloc::vec::Vec;

pub fn load_validated_capsule(capsule_bytes: &[u8]) -> Option<Vec<u8>> {
    let (status, meta_opt) = validate_capsule(capsule_bytes);
    match status {
        CapsuleStatus::Valid => {
            log_info("loader", "Capsule status: Valid, extracting payload");
            if let Some(meta) = meta_opt {
                let payload =
                    &capsule_bytes[meta.offset_payload..meta.offset_payload + meta.len_payload];
                Some(payload.to_vec())
            } else {
                log_error("loader", "Capsule valid but metadata extraction failed");
                None
            }
        }
        CapsuleStatus::InvalidSignature => {
            log_error("loader", "Capsule signature is INVALID. Boot aborted.");
            None
        }
        CapsuleStatus::InvalidFormat => {
            log_error("loader", "Capsule format is INVALID. Boot aborted.");
            None
        }
        CapsuleStatus::IntegrityError => {
            log_error("loader", "Capsule integrity check FAILED. Boot aborted.");
            None
        }
        CapsuleStatus::UnsupportedVersion => {
            log_error("loader", "Capsule version unsupported. Boot aborted.");
            None
        }
        CapsuleStatus::Expired => {
            log_error("loader", "Capsule expired. Boot aborted.");
            None
        }
        CapsuleStatus::ParseError => {
            log_error("loader", "Capsule parse error. Boot aborted.");
            None
        }
    }
}
