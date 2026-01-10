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

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::BigUint;

impl BigUint {
    pub fn to_bytes_be(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut bytes = Vec::with_capacity(self.limbs.len() * 8);

        let mut started = false;
        for &limb in self.limbs.iter().rev() {
            let limb_bytes = limb.to_be_bytes();
            if !started {
                for &b in &limb_bytes {
                    if b != 0 || started {
                        bytes.push(b);
                        started = true;
                    }
                }
            } else {
                bytes.extend_from_slice(&limb_bytes);
            }
        }

        if bytes.is_empty() {
            vec![0]
        } else {
            bytes
        }
    }

    pub fn to_bytes_be_padded(&self, size: usize) -> Option<Vec<u8>> {
        let bytes = self.to_bytes_be();
        if bytes.len() > size {
            return None;
        }

        let mut result = vec![0u8; size];
        let start = size - bytes.len();
        result[start..].copy_from_slice(&bytes);
        Some(result)
    }

    pub fn to_bytes_le(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut bytes = Vec::with_capacity(self.limbs.len() * 8);

        for &limb in &self.limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }

        while bytes.len() > 1 && bytes.last() == Some(&0) {
            bytes.pop();
        }

        bytes
    }

    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return String::from("0");
        }

        let bytes = self.to_bytes_be();
        let mut hex = String::with_capacity(bytes.len() * 2);

        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

        for (i, &b) in bytes.iter().enumerate() {
            if i == 0 {
                if b < 16 {
                    hex.push(HEX_CHARS[b as usize] as char);
                } else {
                    hex.push(HEX_CHARS[(b >> 4) as usize] as char);
                    hex.push(HEX_CHARS[(b & 0xf) as usize] as char);
                }
            } else {
                hex.push(HEX_CHARS[(b >> 4) as usize] as char);
                hex.push(HEX_CHARS[(b & 0xf) as usize] as char);
            }
        }

        hex
    }

    pub fn to_u64(&self) -> Option<u64> {
        if self.limbs.len() == 1 {
            Some(self.limbs[0])
        } else if self.limbs.is_empty() {
            Some(0)
        } else {
            None
        }
    }

    pub fn to_u128(&self) -> Option<u128> {
        match self.limbs.len() {
            0 => Some(0),
            1 => Some(self.limbs[0] as u128),
            2 => Some((self.limbs[1] as u128) << 64 | (self.limbs[0] as u128)),
            _ => None,
        }
    }
}

impl core::fmt::Display for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }

        let mut digits = Vec::new();
        let mut n = self.clone();
        let ten = Self::from_u64(10);

        while !n.is_zero() {
            let (q, r) = n.div_rem(&ten);
            digits.push((r.limbs[0] as u8) + b'0');
            n = q;
        }

        digits.reverse();

        for d in digits {
            write!(f, "{}", d as char)?;
        }

        Ok(())
    }
}

impl core::fmt::Debug for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BigUint(0x{})", self.to_hex())
    }
}

impl core::fmt::LowerHex for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
