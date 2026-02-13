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

#[cfg(feature = "zk-groth16")]
use super::keys::{verify_vk_fingerprint, CORE_CIRCUITS, ENTRIES, ENTRIES_WITH_FINGERPRINT};
#[cfg(feature = "zk-groth16")]
use super::types::{CircuitCategory, CircuitEntry, CircuitPermission};
#[cfg(feature = "zk-groth16")]
use crate::zk::verify::ct_eq32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    NotFound,
    FingerprintMismatch,
}

#[cfg(feature = "zk-groth16")]
pub fn lookup_verified(program_hash: &[u8; 32]) -> Result<&'static [u8], LookupError> {
    for entry in CORE_CIRCUITS {
        if ct_eq32(&entry.program_hash, program_hash) {
            if !entry.vk_bytes.is_empty() {
                return Ok(entry.vk_bytes);
            }
        }
    }
    for (h, vk) in ENTRIES {
        if ct_eq32(h, program_hash) {
            if !vk.is_empty() {
                return Ok(*vk);
            }
        }
    }
    for (h, vk, fingerprint) in ENTRIES_WITH_FINGERPRINT {
        if ct_eq32(h, program_hash) {
            if verify_vk_fingerprint(vk, fingerprint) {
                return Ok(*vk);
            } else {
                return Err(LookupError::FingerprintMismatch);
            }
        }
    }
    Err(LookupError::NotFound)
}

#[cfg(feature = "zk-groth16")]
pub fn lookup(program_hash: &[u8; 32]) -> Option<&'static [u8]> {
    match lookup_verified(program_hash) {
        Ok(vk) => Some(vk),
        Err(_) => None,
    }
}

#[cfg(feature = "zk-groth16")]
pub fn lookup_circuit(program_hash: &[u8; 32]) -> Option<&'static CircuitEntry> {
    for entry in CORE_CIRCUITS {
        if ct_eq32(&entry.program_hash, program_hash) {
            // 1. Core circuits with signatures must have valid signatures
            // 2. Core circuits without signatures are trusted (built-in)
            if entry.category == CircuitCategory::Core
                && entry.signature.is_some()
                && !entry.has_valid_signature()
            {
                return None;
            }
            return Some(entry);
        }
    }
    None
}

#[cfg(feature = "zk-groth16")]
pub fn has_permission(program_hash: &[u8; 32], permission: CircuitPermission) -> bool {
    if let Some(entry) = lookup_circuit(program_hash) {
        (entry.permissions & (permission as u32)) != 0
    } else {
        false
    }
}

#[cfg(feature = "zk-groth16")]
pub fn circuits_with_permission(
    permission: CircuitPermission,
) -> impl Iterator<Item = &'static CircuitEntry> {
    CORE_CIRCUITS
        .iter()
        .filter(move |e| (e.permissions & (permission as u32)) != 0)
}
