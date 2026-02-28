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
use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::sha3::keccak256;

pub fn eth_sign_message(message: &[u8]) -> [u8; 32] {
    let prefix = b"\x19Ethereum Signed Message:\n";
    let len_str = format_usize(message.len());

    let mut data = Vec::with_capacity(prefix.len() + len_str.len() + message.len());
    data.extend_from_slice(prefix);
    data.extend_from_slice(&len_str);
    data.extend_from_slice(message);

    keccak256(&data)
}

fn format_usize(n: usize) -> Vec<u8> {
    if n == 0 {
        return vec![b'0'];
    }

    let mut digits = Vec::new();
    let mut num = n;
    while num > 0 {
        digits.push(b'0' + (num % 10) as u8);
        num /= 10;
    }
    digits.reverse();
    digits
}

pub fn parse_wei(eth_str: &str) -> Option<u128> {
    let bytes = eth_str.as_bytes();
    let mut value: u128 = 0;
    let mut decimals: Option<u8> = None;
    let mut decimal_count: u8 = 0;

    for &c in bytes {
        match c {
            b'0'..=b'9' => {
                let digit = (c - b'0') as u128;
                value = value.checked_mul(10)?.checked_add(digit)?;
                if decimals.is_some() {
                    decimal_count += 1;
                    if decimal_count > 18 {
                        return None;
                    }
                }
            }
            b'.' => {
                if decimals.is_some() {
                    return None;
                }
                decimals = Some(0);
            }
            _ => return None,
        }
    }

    let remaining_decimals = 18 - decimal_count;
    for _ in 0..remaining_decimals {
        value = value.checked_mul(10)?;
    }

    Some(value)
}

pub fn wei_to_gwei(wei: u128) -> u128 {
    wei / 1_000_000_000
}

pub fn gwei_to_wei(gwei: u128) -> u128 {
    gwei * 1_000_000_000
}
