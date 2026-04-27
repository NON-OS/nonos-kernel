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

pub(super) fn parse_eth_address(addr: &str) -> Option<[u8; 20]> {
    let hex = addr.strip_prefix("0x").unwrap_or(addr);
    if hex.len() != 40 {
        return None;
    }
    let mut a = [0u8; 20];
    for i in 0..20 {
        a[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(a)
}

pub(super) fn parse_eth_to_wei(amount: &str) -> Option<u128> {
    let parts: Vec<&str> = amount.split('.').collect();
    if parts.is_empty() || parts.len() > 2 {
        return None;
    }
    let whole: u128 = parts[0].parse().ok()?;
    let frac: u128 = if parts.len() == 2 {
        let fs = parts[1];
        if fs.len() > 18 {
            return None;
        }
        let mut f: u128 = fs.parse().ok()?;
        for _ in 0..(18 - fs.len()) {
            f = f.checked_mul(10)?;
        }
        f
    } else {
        0
    };
    whole.checked_mul(1_000_000_000_000_000_000)?.checked_add(frac)
}

pub(super) fn derive_signing_key(mk: &[u8; 32], idx: u32) -> [u8; 32] {
    use crate::crypto::blake3_hash;
    let mut p = [0u8; 57];
    p[0..32].copy_from_slice(mk);
    p[32..53].copy_from_slice(b"NONOS:WALLET:ACCOUNT:");
    p[53..57].copy_from_slice(&idx.to_le_bytes());
    blake3_hash(&p)
}

pub(super) fn build_erc20_transfer_data(to: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut d = Vec::with_capacity(68);
    d.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(to);
    d.extend_from_slice(&[0u8; 16]);
    d.extend_from_slice(&amount.to_be_bytes());
    d
}
