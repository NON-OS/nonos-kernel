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

use alloc::vec;
use alloc::vec::Vec;

pub fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    if value < 128 {
        return vec![value as u8];
    }

    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let len = 8 - start;
    let mut result = Vec::with_capacity(1 + len);
    result.push(0x80 + len as u8);
    result.extend_from_slice(&bytes[start..]);
    result
}

pub fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    if value < 128 {
        return vec![value as u8];
    }

    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    let len = 16 - start;
    let mut result = Vec::with_capacity(1 + len);
    result.push(0x80 + len as u8);
    result.extend_from_slice(&bytes[start..]);
    result
}

pub fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 128 {
        return bytes.to_vec();
    }
    if bytes.is_empty() {
        return vec![0x80];
    }

    if bytes.len() < 56 {
        let mut result = Vec::with_capacity(1 + bytes.len());
        result.push(0x80 + bytes.len() as u8);
        result.extend_from_slice(bytes);
        result
    } else {
        let len_bytes = rlp_encode_length(bytes.len());
        let mut result = Vec::with_capacity(1 + len_bytes.len() + bytes.len());
        result.push(0xb7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
        result.extend_from_slice(bytes);
        result
    }
}

pub fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().cloned()).collect();
    if payload.len() < 56 {
        let mut result = Vec::with_capacity(1 + payload.len());
        result.push(0xc0 + payload.len() as u8);
        result.extend_from_slice(&payload);
        result
    } else {
        let len_bytes = rlp_encode_length(payload.len());
        let mut result = Vec::with_capacity(1 + len_bytes.len() + payload.len());
        result.push(0xf7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
        result.extend_from_slice(&payload);
        result
    }
}

pub(crate) fn rlp_encode_length(len: usize) -> Vec<u8> {
    if len < 256 {
        vec![len as u8]
    } else if len < 65536 {
        vec![(len >> 8) as u8, len as u8]
    } else if len < 16777216 {
        vec![(len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        vec![
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

pub(crate) fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    &bytes[start..]
}
