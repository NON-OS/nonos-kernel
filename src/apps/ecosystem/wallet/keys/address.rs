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
use super::types::hex_char;
use crate::crypto::hash::keccak256;
use crate::crypto::{CryptoError, CryptoResult};
use alloc::string::String;

pub fn address_to_hex(address: &[u8; 20]) -> String {
    let mut hex = String::with_capacity(42);
    hex.push_str("0x");
    for byte in address {
        hex.push_str(&alloc::format!("{:02x}", byte));
    }
    hex
}

pub fn address_from_hex(hex: &str) -> CryptoResult<[u8; 20]> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 40 {
        return Err(CryptoError::InvalidLength);
    }
    let mut address = [0u8; 20];
    for i in 0..20 {
        address[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| CryptoError::InvalidInput)?;
    }
    Ok(address)
}

pub fn checksum_address(address: &[u8; 20]) -> String {
    let mut hex_chars = [0u8; 40];
    for (i, byte) in address.iter().enumerate() {
        hex_chars[i * 2] = hex_char(byte >> 4);
        hex_chars[i * 2 + 1] = hex_char(byte & 0x0f);
    }
    let addr_hash = keccak256(&hex_chars);
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (i, c) in hex_chars.iter().enumerate() {
        let hash_nibble = if i % 2 == 0 { addr_hash[i / 2] >> 4 } else { addr_hash[i / 2] & 0x0f };
        if *c >= b'a' && *c <= b'f' && hash_nibble >= 8 {
            result.push((*c as char).to_ascii_uppercase());
        } else {
            result.push(*c as char);
        }
    }
    result
}

pub fn validate_address(address: &str) -> bool {
    let address = match address.strip_prefix("0x") {
        Some(a) => a,
        None => return false,
    };
    if address.len() != 40 {
        return false;
    }
    address.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn validate_checksum_address(address: &str) -> bool {
    if !address.starts_with("0x") || address.len() != 42 {
        return false;
    }
    let hex_part = &address[2..];
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let lower = hex_part.to_ascii_lowercase();
    let mut hex_bytes = [0u8; 40];
    for (i, c) in lower.chars().enumerate() {
        hex_bytes[i] = c as u8;
    }
    let hash = keccak256(&hex_bytes);
    for (i, c) in hex_part.chars().enumerate() {
        let hash_nibble = if i % 2 == 0 { hash[i / 2] >> 4 } else { hash[i / 2] & 0x0f };
        let expected_upper = c.is_ascii_alphabetic() && hash_nibble >= 8;
        if c.is_ascii_alphabetic() && expected_upper != c.is_ascii_uppercase() {
            return false;
        }
    }
    true
}
