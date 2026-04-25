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

use super::tree::SparseMerkleTree;
use crate::crypto::sha256;
use crate::zksync::error::ZkSyncError;
use crate::zksync::types::AccountState;
use crate::zksync::types::{Address, BatchNumber, BlockNumber, Nonce, U256};
use alloc::collections::BTreeMap;

pub struct StateManager {
    state_tree: SparseMerkleTree,
    accounts: BTreeMap<Address, AccountState>,
    current_block: BlockNumber,
    current_batch: BatchNumber,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            state_tree: SparseMerkleTree::new(),
            accounts: BTreeMap::new(),
            current_block: BlockNumber(0),
            current_batch: BatchNumber(0),
        }
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_tree.root()
    }

    pub fn get_account(&self, address: &Address) -> Option<&AccountState> {
        self.accounts.get(address)
    }

    pub fn get_balance(&self, address: &Address) -> U256 {
        self.accounts.get(address).map(|a| a.balance).unwrap_or(U256::ZERO)
    }

    pub fn get_nonce(&self, address: &Address) -> Nonce {
        self.accounts.get(address).map(|a| a.nonce).unwrap_or(Nonce(0))
    }

    pub fn set_balance(&mut self, address: Address, balance: U256) {
        let account = self.accounts.entry(address).or_default();
        account.balance = balance;
        self.update_account_hash(&address);
    }

    pub fn increment_nonce(&mut self, address: &Address) {
        if let Some(account) = self.accounts.get_mut(address) {
            account.nonce.increment();
            self.update_account_hash(address);
        }
    }

    pub fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: U256,
    ) -> Result<(), ZkSyncError> {
        let from_balance = self.get_balance(from);
        let new_from = from_balance.checked_sub(&amount).ok_or(ZkSyncError::InsufficientBalance)?;
        let to_balance = self.get_balance(to);
        let new_to = to_balance.checked_add(&amount).ok_or(ZkSyncError::InternalError)?;
        self.set_balance(*from, new_from);
        self.set_balance(*to, new_to);
        Ok(())
    }

    fn update_account_hash(&mut self, address: &Address) {
        let account = match self.accounts.get(address) {
            Some(a) => a,
            None => return,
        };
        let mut data = [0u8; 92];
        data[..8].copy_from_slice(&account.nonce.0.to_le_bytes());
        data[8..40].copy_from_slice(&account.balance.to_bytes_be());
        data[40..72].copy_from_slice(&account.code_hash);
        data[72..92].copy_from_slice(&address.0[..]);
        let hash = sha256(&data);
        let mut key = [0u8; 32];
        key[12..].copy_from_slice(address.as_bytes());
        self.state_tree.insert(key, hash);
    }

    pub fn current_block(&self) -> BlockNumber {
        self.current_block
    }
    pub fn current_batch(&self) -> BatchNumber {
        self.current_batch
    }
    pub fn advance_block(&mut self) {
        self.current_block.0 += 1;
    }
    pub fn advance_batch(&mut self) {
        self.current_batch.0 += 1;
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}
