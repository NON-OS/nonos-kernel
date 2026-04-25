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
use alloc::{string::String, vec::Vec};

pub(super) const ADDRESS_LEN: usize = 20;
const HEX: &[u8; 16] = b"0123456789abcdef";
const WEI: u128 = 1_000_000_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenType {
    Eth,
    Nox,
}
impl TokenType {
    pub(crate) fn symbol(&self) -> &'static [u8] {
        match self {
            Self::Eth => b"ETH",
            Self::Nox => b"NOX",
        }
    }
}

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
    pub hash: [u8; 32],
    pub tx_type: TransactionType,
    pub from: [u8; ADDRESS_LEN],
    pub to: [u8; ADDRESS_LEN],
    pub value: u128,
    pub timestamp: u64,
    pub confirmed: bool,
}
impl Transaction {
    pub(crate) fn value_eth(&self) -> (u64, u64) {
        ((self.value / WEI) as u64, (self.value % WEI) as u64)
    }
}

#[derive(Clone)]
pub(crate) struct WalletAccount {
    pub index: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub address: [u8; ADDRESS_LEN],
    pub secret_key: [u8; 32],
    pub balance: u128,
    pub nox_balance: u128,
    pub transactions: Vec<Transaction>,
}
impl WalletAccount {
    pub(crate) fn new(i: u32, addr: [u8; ADDRESS_LEN]) -> Self {
        let mut n = [0u8; 32];
        n[..8].copy_from_slice(b"Account ");
        n[8] = b'0' + (i % 10) as u8;
        Self {
            index: i,
            name: n,
            name_len: 9,
            address: addr,
            secret_key: [0u8; 32],
            balance: 0,
            nox_balance: 0,
            transactions: Vec::new(),
        }
    }
    pub(crate) fn with_secret_key(i: u32, addr: [u8; ADDRESS_LEN], sk: [u8; 32]) -> Self {
        let mut a = Self::new(i, addr);
        a.secret_key = sk;
        a
    }
    pub(crate) fn private_key_hex(&self) -> String {
        let mut r = String::with_capacity(66);
        r.push_str("0x");
        for b in &self.secret_key {
            r.push(HEX[(b >> 4) as usize] as char);
            r.push(HEX[(b & 0x0f) as usize] as char);
        }
        r
    }
    pub(crate) fn balance_eth(&self) -> (u64, u64) {
        ((self.balance / WEI) as u64, (self.balance % WEI) as u64)
    }
    pub(crate) fn balance_nox(&self) -> (u64, u64) {
        ((self.nox_balance / WEI) as u64, (self.nox_balance % WEI) as u64)
    }
    pub(crate) fn address_hex(&self) -> [u8; 42] {
        let mut r = [0u8; 42];
        r[0] = b'0';
        r[1] = b'x';
        for i in 0..20 {
            r[2 + i * 2] = HEX[(self.address[i] >> 4) as usize];
            r[2 + i * 2 + 1] = HEX[(self.address[i] & 0x0f) as usize];
        }
        r
    }
}

pub(crate) fn format_address(addr: &[u8; ADDRESS_LEN]) -> [u8; 42] {
    let mut r = [0u8; 42];
    r[0] = b'0';
    r[1] = b'x';
    for i in 0..20 {
        r[2 + i * 2] = HEX[(addr[i] >> 4) as usize];
        r[2 + i * 2 + 1] = HEX[(addr[i] & 0x0f) as usize];
    }
    r
}
pub(super) fn truncate_address(a: &[u8; 42]) -> [u8; 13] {
    let mut r = [0u8; 13];
    r[..6].copy_from_slice(&a[..6]);
    r[6..9].copy_from_slice(b"...");
    r[9..13].copy_from_slice(&a[38..42]);
    r
}
