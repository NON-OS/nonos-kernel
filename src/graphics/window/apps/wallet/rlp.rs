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

fn enc_len(l: usize) -> Vec<u8> {
    if l == 0 {
        Vec::new()
    } else {
        let b = (l as u64).to_be_bytes();
        let s = b.iter().position(|&x| x != 0).unwrap_or(7);
        b[s..].to_vec()
    }
}

pub(super) fn rlp_encode_u64(v: u64) -> Vec<u8> {
    if v == 0 {
        return alloc::vec![0x80];
    }
    if v < 128 {
        return alloc::vec![v as u8];
    }
    let b = v.to_be_bytes();
    let s = b.iter().position(|&x| x != 0).unwrap_or(7);
    let mut r = Vec::with_capacity(1 + 8 - s);
    r.push(0x80 + (8 - s) as u8);
    r.extend_from_slice(&b[s..]);
    r
}

pub(super) fn rlp_encode_u128(v: u128) -> Vec<u8> {
    if v == 0 {
        return alloc::vec![0x80];
    }
    if v < 128 {
        return alloc::vec![v as u8];
    }
    let b = v.to_be_bytes();
    let s = b.iter().position(|&x| x != 0).unwrap_or(15);
    let mut r = Vec::with_capacity(1 + 16 - s);
    r.push(0x80 + (16 - s) as u8);
    r.extend_from_slice(&b[s..]);
    r
}

pub(super) fn rlp_encode_bytes(b: &[u8]) -> Vec<u8> {
    if b.is_empty() {
        return alloc::vec![0x80];
    }
    if b.len() == 1 && b[0] < 128 {
        return alloc::vec![b[0]];
    }
    if b.len() < 56 {
        let mut r = Vec::with_capacity(1 + b.len());
        r.push(0x80 + b.len() as u8);
        r.extend_from_slice(b);
        r
    } else {
        let lb = enc_len(b.len());
        let mut r = Vec::with_capacity(1 + lb.len() + b.len());
        r.push(0xb7 + lb.len() as u8);
        r.extend_from_slice(&lb);
        r.extend_from_slice(b);
        r
    }
}

pub(super) fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let pl: usize = items.iter().map(|i| i.len()).sum();
    if pl < 56 {
        let mut r = Vec::with_capacity(1 + pl);
        r.push(0xc0 + pl as u8);
        for i in items {
            r.extend_from_slice(i);
        }
        r
    } else {
        let lb = enc_len(pl);
        let mut r = Vec::with_capacity(1 + lb.len() + pl);
        r.push(0xf7 + lb.len() as u8);
        r.extend_from_slice(&lb);
        for i in items {
            r.extend_from_slice(i);
        }
        r
    }
}
