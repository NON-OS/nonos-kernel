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

use crate::zksync::types::{Address, U256};
use alloc::collections::BTreeMap;

pub struct ContractStorage {
    storage: BTreeMap<(Address, U256), U256>,
}

impl ContractStorage {
    pub fn new() -> Self {
        Self { storage: BTreeMap::new() }
    }

    pub fn get(&self, address: &Address, slot: &U256) -> U256 {
        self.storage.get(&(*address, *slot)).copied().unwrap_or(U256::ZERO)
    }

    pub fn set(&mut self, address: Address, slot: U256, value: U256) {
        if value.is_zero() {
            self.storage.remove(&(address, slot));
        } else {
            self.storage.insert((address, slot), value);
        }
    }

    pub fn remove(&mut self, address: &Address, slot: &U256) -> Option<U256> {
        self.storage.remove(&(*address, *slot))
    }

    pub fn clear_account(&mut self, address: &Address) {
        self.storage.retain(|(addr, _), _| addr != address);
    }

    pub fn iter_account<'a>(
        &'a self,
        address: &'a Address,
    ) -> impl Iterator<Item = (&'a U256, &'a U256)> + 'a {
        self.storage
            .iter()
            .filter(move |((addr, _), _)| addr == address)
            .map(|((_, slot), value)| (slot, value))
    }

    pub fn len(&self) -> usize {
        self.storage.len()
    }
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }
}

impl Default for ContractStorage {
    fn default() -> Self {
        Self::new()
    }
}
