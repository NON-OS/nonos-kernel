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

use crate::arch::x86_64::uefi::types::Guid;
use super::types::{SignatureEntry, SignatureList};

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
