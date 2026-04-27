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
use alloc::string::String;

#[derive(Clone)]
pub struct AccountInfo {
    pub index: u32,
    pub address: [u8; 20],
    pub label: String,
    pub balance_wei: u128,
    pub nonce: u64,
}

impl AccountInfo {
    pub fn new(index: u32, address: [u8; 20]) -> Self {
        Self { index, address, label: String::new(), balance_wei: 0, nonce: 0 }
    }

    pub fn address_hex(&self) -> String {
        let mut hex = String::with_capacity(42);
        hex.push_str("0x");
        for byte in &self.address {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }

    pub fn balance_eth(&self) -> f64 {
        self.balance_wei as f64 / 1_000_000_000_000_000_000.0
    }
}
