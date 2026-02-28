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
use crate::arch::x86_64::uefi::types::Guid;

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
