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

use crate::zksync::types::AccountState;
use crate::zksync::types::{Address, Nonce, U256};
use alloc::collections::BTreeMap;

pub struct AccountStorage {
    accounts: BTreeMap<Address, AccountState>,
}

impl AccountStorage {
    pub fn new() -> Self {
        Self { accounts: BTreeMap::new() }
    }

    pub fn get(&self, address: &Address) -> Option<&AccountState> {
        self.accounts.get(address)
    }

    pub fn get_mut(&mut self, address: &Address) -> Option<&mut AccountState> {
        self.accounts.get_mut(address)
    }

    pub fn get_or_create(&mut self, address: Address) -> &mut AccountState {
        self.accounts.entry(address).or_default()
    }

    pub fn exists(&self, address: &Address) -> bool {
        self.accounts.contains_key(address)
    }

    pub fn balance(&self, address: &Address) -> U256 {
        self.accounts.get(address).map(|a| a.balance).unwrap_or(U256::ZERO)
    }

    pub fn nonce(&self, address: &Address) -> Nonce {
        self.accounts.get(address).map(|a| a.nonce).unwrap_or(Nonce(0))
    }

    pub fn set_balance(&mut self, address: Address, balance: U256) {
        self.get_or_create(address).balance = balance;
    }

    pub fn set_nonce(&mut self, address: Address, nonce: Nonce) {
        self.get_or_create(address).nonce = nonce;
    }

    pub fn increment_nonce(&mut self, address: &Address) {
        if let Some(account) = self.accounts.get_mut(address) {
            account.nonce.increment();
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Address, &AccountState)> {
        self.accounts.iter()
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}

impl Default for AccountStorage {
    fn default() -> Self {
        Self::new()
    }
}
