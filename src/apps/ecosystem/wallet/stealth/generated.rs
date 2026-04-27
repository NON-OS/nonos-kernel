// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use crate::crypto::asymmetric::secp256k1::PublicKey;
use alloc::{string::String, vec::Vec};

#[derive(Clone)]
pub struct GeneratedStealthAddress {
    pub stealth_address: [u8; 20],
    pub ephemeral_pubkey: PublicKey,
    pub view_tag: u8,
}

impl GeneratedStealthAddress {
    pub fn stealth_address_hex(&self) -> String {
        let mut hex = String::with_capacity(42);
        hex.push_str("0x");
        for byte in &self.stealth_address {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }

    pub fn ephemeral_pubkey_hex(&self) -> String {
        let mut hex = String::with_capacity(132);
        hex.push_str("0x");
        for byte in &self.ephemeral_pubkey {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }
}

pub struct Announcement {
    pub stealth_address: [u8; 20],
    pub ephemeral_pubkey: PublicKey,
    pub view_tag: u8,
    pub metadata: Vec<u8>,
}
