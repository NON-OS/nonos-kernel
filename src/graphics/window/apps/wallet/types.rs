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

pub(super) const ADDRESS_LEN: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum TransactionType {
    Send,
    Receive,
    StealthSend,
    StealthReceive,
    ContractCall,
}

#[derive(Clone)]
pub(crate) struct Transaction {
    pub(crate) hash: [u8; 32],
    pub(crate) tx_type: TransactionType,
    pub(crate) from: [u8; ADDRESS_LEN],
    pub(crate) to: [u8; ADDRESS_LEN],
    pub(crate) value: u128,
    pub(crate) timestamp: u64,
    pub(crate) confirmed: bool,
}

impl Transaction {
    pub(crate) fn value_eth(&self) -> (u64, u64) {
        let wei_per_eth: u128 = 1_000_000_000_000_000_000;
        let eth = (self.value / wei_per_eth) as u64;
        let wei = (self.value % wei_per_eth) as u64;
        (eth, wei)
    }
}

#[derive(Clone)]
pub(crate) struct WalletAccount {
    pub(crate) index: u32,
    pub(crate) name: [u8; 32],
    pub(crate) name_len: usize,
    pub(crate) address: [u8; ADDRESS_LEN],
    pub(crate) secret_key: [u8; 32],
    pub(crate) balance: u128,
    pub(crate) transactions: Vec<Transaction>,
}

impl WalletAccount {
    pub(crate) fn new(index: u32, address: [u8; ADDRESS_LEN]) -> Self {
        let mut name = [0u8; 32];
        let default_name = b"Account ";
        name[..8].copy_from_slice(default_name);
        let idx_char = b'0' + (index % 10) as u8;
        name[8] = idx_char;

        Self {
            index,
            name,
            name_len: 9,
            address,
            secret_key: [0u8; 32],
            balance: 0,
            transactions: Vec::new(),
        }
    }

    pub(crate) fn with_secret_key(index: u32, address: [u8; ADDRESS_LEN], secret_key: [u8; 32]) -> Self {
        let mut account = Self::new(index, address);
        account.secret_key = secret_key;
        account
    }

    pub(crate) fn private_key_hex(&self) -> alloc::string::String {
        use alloc::string::String;
        let mut result = String::with_capacity(66);
        result.push_str("0x");
        let hex_chars: &[u8; 16] = b"0123456789abcdef";
        for byte in &self.secret_key {
            result.push(hex_chars[(byte >> 4) as usize] as char);
            result.push(hex_chars[(byte & 0x0f) as usize] as char);
        }
        result
    }

    pub(crate) fn balance_eth(&self) -> (u64, u64) {
        let wei_per_eth: u128 = 1_000_000_000_000_000_000;
        let eth = (self.balance / wei_per_eth) as u64;
        let wei = (self.balance % wei_per_eth) as u64;
        (eth, wei)
    }

    pub(crate) fn address_hex(&self) -> [u8; 42] {
        let mut result = [0u8; 42];
        result[0] = b'0';
        result[1] = b'x';
        let hex_chars: &[u8; 16] = b"0123456789abcdef";
        for i in 0..20 {
            result[2 + i * 2] = hex_chars[(self.address[i] >> 4) as usize];
            result[2 + i * 2 + 1] = hex_chars[(self.address[i] & 0x0f) as usize];
        }
        result
    }
}

pub(crate) fn format_address(addr: &[u8; ADDRESS_LEN]) -> [u8; 42] {
    let mut result = [0u8; 42];
    result[0] = b'0';
    result[1] = b'x';
    let hex_chars: &[u8; 16] = b"0123456789abcdef";
    for i in 0..20 {
        result[2 + i * 2] = hex_chars[(addr[i] >> 4) as usize];
        result[2 + i * 2 + 1] = hex_chars[(addr[i] & 0x0f) as usize];
    }
    result
}

pub(super) fn truncate_address(addr: &[u8; 42]) -> [u8; 13] {
    let mut result = [0u8; 13];
    result[..6].copy_from_slice(&addr[..6]);
    result[6] = b'.';
    result[7] = b'.';
    result[8] = b'.';
    result[9..13].copy_from_slice(&addr[38..42]);
    result
}
