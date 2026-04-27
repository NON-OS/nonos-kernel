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
use super::parse_core::parse_signature_lists;
use super::types::SignatureList;
use crate::arch::x86_64::uefi::error::UefiError;
use crate::arch::x86_64::uefi::types::Guid;
use alloc::vec::Vec;

pub fn hash_in_signature_lists(hash: &[u8], lists: &[SignatureList]) -> bool {
    lists.iter().any(|list| list.contains_hash(hash))
}

pub fn count_signatures(data: &[u8]) -> Result<usize, UefiError> {
    let lists = parse_signature_lists(data)?;
    Ok(lists.iter().map(|l| l.entry_count()).sum())
}

pub fn extract_hashes(data: &[u8], hash_type: &Guid) -> Result<Vec<Vec<u8>>, UefiError> {
    let lists = parse_signature_lists(data)?;
    let mut hashes = Vec::new();
    for list in lists {
        if list.signature_type == *hash_type {
            for entry in list.entries {
                hashes.push(entry.data);
            }
        }
    }
    Ok(hashes)
}
