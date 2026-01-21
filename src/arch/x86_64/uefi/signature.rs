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

extern crate alloc;

use alloc::vec::Vec;

use super::constants::{SIGNATURE_DATA_HEADER_SIZE, SIGNATURE_LIST_HEADER_SIZE};
use super::error::UefiError;
use super::types::Guid;

#[derive(Debug, Clone)]
pub struct SignatureEntry {
    pub owner: Guid,
    pub data: Vec<u8>,
}

impl SignatureEntry {
    pub fn new(owner: Guid, data: Vec<u8>) -> Self {
        Self { owner, data }
    }

    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    pub fn total_size(&self) -> usize {
        SIGNATURE_DATA_HEADER_SIZE + self.data.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.total_size());
        bytes.extend_from_slice(&self.owner.to_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct SignatureList {
    pub signature_type: Guid,
    pub header_data: Vec<u8>,
    pub entries: Vec<SignatureEntry>,
}

impl SignatureList {
    pub fn new(signature_type: Guid) -> Self {
        Self {
            signature_type,
            header_data: Vec::new(),
            entries: Vec::new(),
        }
    }

    pub fn with_entries(signature_type: Guid, entries: Vec<SignatureEntry>) -> Self {
        Self {
            signature_type,
            header_data: Vec::new(),
            entries,
        }
    }

    pub fn add_entry(&mut self, entry: SignatureEntry) {
        self.entries.push(entry);
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn signature_size(&self) -> usize {
        if let Some(entry) = self.entries.first() {
            entry.total_size()
        } else if let Some(hash_size) = self.signature_type.hash_size() {
            SIGNATURE_DATA_HEADER_SIZE + hash_size
        } else {
            0
        }
    }

    pub fn total_size(&self) -> usize {
        let sig_size = self.signature_size();
        SIGNATURE_LIST_HEADER_SIZE + self.header_data.len() + (sig_size * self.entries.len())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let list_size = self.total_size();
        let sig_size = self.signature_size();

        let mut bytes = Vec::with_capacity(list_size);

        bytes.extend_from_slice(&self.signature_type.to_bytes());
        bytes.extend_from_slice(&(list_size as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.header_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(sig_size as u32).to_le_bytes());
        bytes.extend_from_slice(&self.header_data);

        for entry in &self.entries {
            bytes.extend_from_slice(&entry.to_bytes());
        }

        bytes
    }

    pub fn contains_hash(&self, hash: &[u8]) -> bool {
        if let Some(expected_size) = self.signature_type.hash_size() {
            if hash.len() != expected_size {
                return false;
            }
        }

        self.entries.iter().any(|entry| entry.data == hash)
    }
}

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

pub fn build_signature_list(signature_type: &Guid, owner: &Guid, hash: &[u8]) -> Vec<u8> {
    let entry = SignatureEntry::new(*owner, hash.to_vec());
    let list = SignatureList::with_entries(*signature_type, alloc::vec![entry]);
    list.to_bytes()
}

pub fn build_multi_signature_list(signature_type: &Guid, entries: &[(Guid, &[u8])]) -> Vec<u8> {
    let mut list = SignatureList::new(*signature_type);
    for (owner, hash) in entries {
        list.add_entry(SignatureEntry::new(*owner, hash.to_vec()));
    }
    list.to_bytes()
}

pub fn merge_signature_lists(lists: &[SignatureList]) -> Vec<u8> {
    let total_size: usize = lists.iter().map(|l| l.total_size()).sum();
    let mut result = Vec::with_capacity(total_size);
    for list in lists {
        result.extend_from_slice(&list.to_bytes());
    }
    result
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_entry_creation() {
        let owner = Guid::NONOS_OWNER;
        let data = vec![0xAB; 32];
        let entry = SignatureEntry::new(owner, data.clone());

        assert_eq!(entry.owner, owner);
        assert_eq!(entry.data, data);
        assert_eq!(entry.data_len(), 32);
        assert_eq!(entry.total_size(), 48);
    }

    #[test]
    fn test_signature_list_creation() {
        let list = SignatureList::new(Guid::CERT_SHA256);
        assert!(list.is_empty());
        assert_eq!(list.entry_count(), 0);
    }

    #[test]
    fn test_build_signature_list() {
        let hash = [0xAB; 32];
        let list_data = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &hash);

        assert_eq!(list_data.len(), 76);

        let sig_type = Guid::from_bytes(&list_data[0..16]).unwrap();
        assert_eq!(sig_type, Guid::CERT_SHA256);

        let list_size = u32::from_le_bytes([list_data[16], list_data[17], list_data[18], list_data[19]]);
        assert_eq!(list_size, 76);
    }

    #[test]
    fn test_parse_signature_list() {
        let hash = [0xAB; 32];
        let list_data = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &hash);

        let lists = parse_signature_lists(&list_data).unwrap();
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].signature_type, Guid::CERT_SHA256);
        assert_eq!(lists[0].entries.len(), 1);
        assert_eq!(lists[0].entries[0].owner, Guid::NONOS_OWNER);
        assert_eq!(lists[0].entries[0].data, hash.to_vec());
    }

    #[test]
    fn test_hash_in_signature_lists() {
        let hash = [0xCD; 32];
        let list_data = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &hash);
        let lists = parse_signature_lists(&list_data).unwrap();

        assert!(hash_in_signature_lists(&hash, &lists));
        assert!(!hash_in_signature_lists(&[0xFF; 32], &lists));
    }

    #[test]
    fn test_roundtrip() {
        let mut list = SignatureList::new(Guid::CERT_SHA256);
        list.add_entry(SignatureEntry::new(Guid::NONOS_OWNER, vec![0x11; 32]));
        list.add_entry(SignatureEntry::new(Guid::NONOS_OWNER, vec![0x22; 32]));

        let bytes = list.to_bytes();
        let parsed = parse_signature_lists(&bytes).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].entries.len(), 2);
        assert_eq!(parsed[0].entries[0].data, vec![0x11; 32]);
        assert_eq!(parsed[0].entries[1].data, vec![0x22; 32]);
    }

    #[test]
    fn test_multiple_lists() {
        let list1 = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &[0x11; 32]);
        let list2 = build_signature_list(&Guid::CERT_SHA384, &Guid::NONOS_OWNER, &[0x22; 48]);

        let mut combined = list1;
        combined.extend_from_slice(&list2);

        let parsed = parse_signature_lists(&combined).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].signature_type, Guid::CERT_SHA256);
        assert_eq!(parsed[1].signature_type, Guid::CERT_SHA384);
    }

    #[test]
    fn test_parse_empty() {
        let lists = parse_signature_lists(&[]).unwrap();
        assert!(lists.is_empty());
    }

    #[test]
    fn test_parse_invalid() {
        let result = parse_signature_lists(&[0; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_count_signatures() {
        let list = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &[0x11; 32]);
        assert_eq!(count_signatures(&list).unwrap(), 1);
    }

    #[test]
    fn test_extract_hashes() {
        let list = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &[0xAB; 32]);
        let hashes = extract_hashes(&list, &Guid::CERT_SHA256).unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], vec![0xAB; 32]);
    }
}
