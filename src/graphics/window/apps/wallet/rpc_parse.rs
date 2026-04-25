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
use super::rpc::RpcError;
use super::types::ADDRESS_LEN;
use alloc::{format, string::String};

pub(super) fn parse_hex_balance(r: &[u8]) -> Result<u128, RpcError> {
    let pat = b"\"result\":\"0x";
    if r.windows(14).any(|w| w == b"\"result\":null") {
        return Err(RpcError::InvalidResponse);
    }
    for i in 0..r.len().saturating_sub(pat.len()) {
        if &r[i..i + pat.len()] == pat {
            let s = i + pat.len();
            let mut e = s;
            while e < r.len() && r[e] != b'"' {
                e += 1;
            }
            return parse_hex_u128(&r[s..e]);
        }
    }
    if r.windows(7).any(|w| w == b"\"error\"") {
        return Err(RpcError::RpcResponseError);
    }
    Err(RpcError::ParseError)
}

pub(super) fn parse_hex_u128(h: &[u8]) -> Result<u128, RpcError> {
    let mut v: u128 = 0;
    for &b in h {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(RpcError::ParseError),
        };
        v = v
            .checked_mul(16)
            .ok_or(RpcError::ParseError)?
            .checked_add(d as u128)
            .ok_or(RpcError::ParseError)?;
    }
    Ok(v)
}

pub(super) fn parse_tx_hash(r: &[u8]) -> Result<[u8; 32], RpcError> {
    let pat = b"\"result\":\"0x";
    for i in 0..r.len().saturating_sub(pat.len()) {
        if &r[i..i + pat.len()] == pat {
            let s = i + pat.len();
            if s + 64 > r.len() {
                return Err(RpcError::ParseError);
            }
            let mut hash = [0u8; 32];
            for j in 0..32 {
                hash[j] = (hex_digit(r[s + j * 2])? << 4) | hex_digit(r[s + j * 2 + 1])?;
            }
            return Ok(hash);
        }
    }
    Err(RpcError::ParseError)
}

fn hex_digit(c: u8) -> Result<u8, RpcError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(RpcError::ParseError),
    }
}

pub(super) fn format_address_hex(a: &[u8; ADDRESS_LEN]) -> String {
    let mut h = String::from("0x");
    for b in a {
        h.push_str(&format!("{:02x}", b));
    }
    h
}

pub(super) fn parse_call_result(r: &[u8]) -> Result<alloc::vec::Vec<u8>, RpcError> {
    let pat = b"\"result\":\"0x";
    for i in 0..r.len().saturating_sub(pat.len()) {
        if &r[i..i + pat.len()] == pat {
            let s = i + pat.len();
            let mut e = s;
            while e < r.len() && r[e] != b'"' {
                e += 1;
            }
            let hex = &r[s..e];
            let mut data = alloc::vec::Vec::with_capacity(hex.len() / 2);
            for j in (0..hex.len()).step_by(2) {
                data.push((hex_digit(hex[j])? << 4) | hex_digit(hex[j + 1])?);
            }
            return Ok(data);
        }
    }
    Err(RpcError::ParseError)
}
