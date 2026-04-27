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

use crate::apps::ecosystem::wallet::rpc::RpcResult;

pub fn parse_address(hex: &str) -> Option<[u8; 20]> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 40 {
        return None;
    }
    let mut address = [0u8; 20];
    for i in 0..20 {
        address[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(address)
}

pub fn encode_address(address: &[u8; 20]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[12..32].copy_from_slice(address);
    padded
}

pub fn encode_u256(value: u128) -> [u8; 32] {
    let mut encoded = [0u8; 32];
    let bytes = value.to_be_bytes();
    encoded[16..32].copy_from_slice(&bytes);
    encoded
}

pub fn decode_u256(data: &[u8]) -> RpcResult<u128> {
    if data.len() < 32 {
        return Ok(0);
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[16..32]);
    Ok(u128::from_be_bytes(bytes))
}
