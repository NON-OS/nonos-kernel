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
use super::utils::bytes_to_hex;
use alloc::{format, string::String, vec::Vec};

#[derive(Debug, Clone)]
pub struct TransactionCall {
    pub from: Option<String>,
    pub to: String,
    pub gas: Option<u64>,
    pub gas_price: Option<u128>,
    pub value: Option<u128>,
    pub data: Option<Vec<u8>>,
}

impl TransactionCall {
    pub fn new(to: &str) -> Self {
        Self {
            from: None,
            to: String::from(to),
            gas: None,
            gas_price: None,
            value: None,
            data: None,
        }
    }

    pub fn with_data(to: &str, data: Vec<u8>) -> Self {
        Self {
            from: None,
            to: String::from(to),
            gas: None,
            gas_price: None,
            value: None,
            data: Some(data),
        }
    }

    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref from) = self.from {
            parts.push(format!(r#""from":"{}""#, from));
        }
        parts.push(format!(r#""to":"{}""#, self.to));
        if let Some(gas) = self.gas {
            parts.push(format!(r#""gas":"0x{:x}""#, gas));
        }
        if let Some(gas_price) = self.gas_price {
            parts.push(format!(r#""gasPrice":"0x{:x}""#, gas_price));
        }
        if let Some(value) = self.value {
            parts.push(format!(r#""value":"0x{:x}""#, value));
        }
        if let Some(ref data) = self.data {
            parts.push(format!(r#""data":"{}""#, bytes_to_hex(data)));
        }
        format!("{{{}}}", parts.join(","))
    }
}
