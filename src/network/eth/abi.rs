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

pub fn selector(sig: &str) -> [u8; 4] {
    let h = crate::crypto::keccak::keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

pub fn encode_call(sig: &str, params: &[&[u8]]) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + params.len() * 32);
    data.extend_from_slice(&selector(sig));
    for p in params { data.extend_from_slice(&pad32(p)); }
    data
}

pub fn encode_u256(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

pub fn encode_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr);
    out
}

pub fn encode_bytes32(b: &[u8; 32]) -> [u8; 32] { *b }

pub fn decode_u256(data: &[u8], offset: usize) -> Option<u128> {
    if offset + 32 > data.len() { return None; }
    let mut v = 0u128;
    for i in 16..32 { v = (v << 8) | data[offset + i] as u128; }
    Some(v)
}

pub fn decode_address(data: &[u8], offset: usize) -> Option<[u8; 20]> {
    if offset + 32 > data.len() { return None; }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&data[offset + 12..offset + 32]);
    Some(addr)
}

pub fn decode_bytes32(data: &[u8], offset: usize) -> Option<[u8; 32]> {
    if offset + 32 > data.len() { return None; }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[offset..offset + 32]);
    Some(out)
}

pub fn decode_bool(data: &[u8], offset: usize) -> Option<bool> {
    if offset + 32 > data.len() { return None; }
    Some(data[offset + 31] != 0)
}

fn pad32(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(data.len());
    let len = data.len().min(32);
    out[start..start + len].copy_from_slice(&data[data.len() - len..]);
    out
}
