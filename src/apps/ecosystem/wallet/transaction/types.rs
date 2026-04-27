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
use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    Legacy,
    Eip2930,
    Eip1559,
}

#[derive(Debug, Clone)]
pub struct AccessListItem {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct TransactionRequest {
    pub tx_type: TransactionType,
    pub chain_id: u64,
    pub nonce: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub access_list: Vec<AccessListItem>,
}

impl TransactionRequest {
    pub fn new_legacy(chain_id: u64) -> Self {
        Self {
            tx_type: TransactionType::Legacy,
            chain_id,
            nonce: 0,
            to: None,
            value: 0,
            data: Vec::new(),
            gas_limit: 21000,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: Vec::new(),
        }
    }
    pub fn new_eip1559(chain_id: u64) -> Self {
        Self {
            tx_type: TransactionType::Eip1559,
            chain_id,
            nonce: 0,
            to: None,
            value: 0,
            data: Vec::new(),
            gas_limit: 21000,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: Vec::new(),
        }
    }
    pub fn with_to(mut self, to: [u8; 20]) -> Self {
        self.to = Some(to);
        self
    }
    pub fn with_value(mut self, value: u128) -> Self {
        self.value = value;
        self
    }
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }
    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }
    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }
    pub fn with_gas_price(mut self, gas_price: u128) -> Self {
        self.gas_price = Some(gas_price);
        self
    }
    pub fn with_eip1559_fees(mut self, max_fee: u128, priority_fee: u128) -> Self {
        self.max_fee_per_gas = Some(max_fee);
        self.max_priority_fee_per_gas = Some(priority_fee);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub raw: Vec<u8>,
    pub hash: [u8; 32],
    pub from: [u8; 20],
}

impl SignedTransaction {
    pub fn hash_hex(&self) -> String {
        let mut hex = String::with_capacity(66);
        hex.push_str("0x");
        for byte in &self.hash {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }
    pub fn raw_hex(&self) -> String {
        let mut hex = String::with_capacity(self.raw.len() * 2 + 2);
        hex.push_str("0x");
        for byte in &self.raw {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }
}
