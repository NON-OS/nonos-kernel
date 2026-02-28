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

use crate::arch::x86_64::uefi::constants::{SIGNATURE_DATA_HEADER_SIZE, SIGNATURE_LIST_HEADER_SIZE};
use crate::arch::x86_64::uefi::error::UefiError;
use crate::arch::x86_64::uefi::types::Guid;
use super::types::{SignatureEntry, SignatureList};

pub fn parse_signature_lists(data: &[u8]) -> Result<Vec<SignatureList>, UefiError> {
    let mut lists = Vec::new();
    let mut offset = 0;

    while offset + SIGNATURE_LIST_HEADER_SIZE <= data.len() {
        let sig_type =
            Guid::from_bytes(&data[offset..]).ok_or(UefiError::SignatureListParseError { offset })?;

        let list_size = u32::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]) as usize;

        let header_size = u32::from_le_bytes([
            data[offset + 20],
            data[offset + 21],
            data[offset + 22],
            data[offset + 23],
        ]) as usize;

        let sig_size = u32::from_le_bytes([
            data[offset + 24],
            data[offset + 25],
            data[offset + 26],
            data[offset + 27],
        ]) as usize;

        if list_size == 0 || list_size < SIGNATURE_LIST_HEADER_SIZE {
            return Err(UefiError::SignatureListParseError { offset });
        }

        if sig_size < SIGNATURE_DATA_HEADER_SIZE {
            return Err(UefiError::SignatureListParseError { offset });
        }

        if offset + list_size > data.len() {
            return Err(UefiError::SignatureListParseError { offset });
        }

        let header_data = if header_size > 0 {
            data[offset + SIGNATURE_LIST_HEADER_SIZE..offset + SIGNATURE_LIST_HEADER_SIZE + header_size].to_vec()
        } else {
            Vec::new()
        };

        let entries_start = offset + SIGNATURE_LIST_HEADER_SIZE + header_size;
        let entries_total_size = list_size - SIGNATURE_LIST_HEADER_SIZE - header_size;

        let mut entries = Vec::new();
        if entries_total_size > 0 && sig_size > SIGNATURE_DATA_HEADER_SIZE {
            let num_entries = entries_total_size / sig_size;
            for i in 0..num_entries {
                let entry_offset = entries_start + i * sig_size;
                if entry_offset + sig_size > data.len() {
                    break;
                }

                let owner = Guid::from_bytes(&data[entry_offset..])
                    .ok_or(UefiError::SignatureListParseError { offset: entry_offset })?;

                let sig_data = data[entry_offset + SIGNATURE_DATA_HEADER_SIZE..entry_offset + sig_size].to_vec();

                entries.push(SignatureEntry::new(owner, sig_data));
            }
        }

        lists.push(SignatureList {
            signature_type: sig_type,
            header_data,
            entries,
        });

        offset += list_size;
    }

    Ok(lists)
}

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
