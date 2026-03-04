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

pub(super) fn rlp_encode_u64(value: u64) -> alloc::vec::Vec<u8> {
    if value == 0 {
        return alloc::vec![0x80];
    }
    if value < 128 {
        return alloc::vec![value as u8];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let significant = &bytes[start..];
    let mut result = alloc::vec::Vec::with_capacity(1 + significant.len());
    result.push(0x80 + significant.len() as u8);
    result.extend_from_slice(significant);
    result
}

pub(super) fn rlp_encode_u128(value: u128) -> alloc::vec::Vec<u8> {
    if value == 0 {
        return alloc::vec![0x80];
    }
    if value < 128 {
        return alloc::vec![value as u8];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    let significant = &bytes[start..];
    let mut result = alloc::vec::Vec::with_capacity(1 + significant.len());
    result.push(0x80 + significant.len() as u8);
    result.extend_from_slice(significant);
    result
}

pub(super) fn rlp_encode_bytes(bytes: &[u8]) -> alloc::vec::Vec<u8> {
    if bytes.is_empty() {
        return alloc::vec![0x80];
    }
    if bytes.len() == 1 && bytes[0] < 128 {
        return alloc::vec![bytes[0]];
    }
    if bytes.len() < 56 {
        let mut result = alloc::vec::Vec::with_capacity(1 + bytes.len());
        result.push(0x80 + bytes.len() as u8);
        result.extend_from_slice(bytes);
        result
    } else {
        let len_bytes = encode_length(bytes.len());
        let mut result = alloc::vec::Vec::with_capacity(1 + len_bytes.len() + bytes.len());
        result.push(0xb7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
        result.extend_from_slice(bytes);
        result
    }
}

pub(super) fn rlp_encode_list(items: &[alloc::vec::Vec<u8>]) -> alloc::vec::Vec<u8> {
    let payload_len: usize = items.iter().map(|i| i.len()).sum();
    if payload_len < 56 {
        let mut result = alloc::vec::Vec::with_capacity(1 + payload_len);
        result.push(0xc0 + payload_len as u8);
        for item in items {
            result.extend_from_slice(item);
        }
        result
    } else {
        let len_bytes = encode_length(payload_len);
        let mut result = alloc::vec::Vec::with_capacity(1 + len_bytes.len() + payload_len);
        result.push(0xf7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
        for item in items {
            result.extend_from_slice(item);
        }
        result
    }
}

fn encode_length(len: usize) -> alloc::vec::Vec<u8> {
    if len == 0 {
        return alloc::vec::Vec::new();
    }
    let bytes = (len as u64).to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}
