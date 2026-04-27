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

use crate::zksync::error::ZkSyncError;
use crate::zksync::state::StateManager;
use crate::zksync::types::{Address, U256};
use alloc::collections::VecDeque;

#[derive(Clone, Debug)]
pub struct Deposit {
    pub l1_tx_hash: [u8; 32],
    pub recipient: Address,
    pub amount: U256,
    pub l1_block: u64,
}

pub struct DepositHandler {
    pending: VecDeque<Deposit>,
}

impl DepositHandler {
    pub fn new() -> Self {
        Self { pending: VecDeque::new() }
    }

    pub fn queue(&mut self, deposit: Deposit) {
        self.pending.push_back(deposit);
    }

    pub fn process_next(
        &mut self,
        state: &mut StateManager,
    ) -> Result<Option<Deposit>, ZkSyncError> {
        let deposit = match self.pending.pop_front() {
            Some(d) => d,
            None => return Ok(None),
        };
        let current = state.get_balance(&deposit.recipient);
        let new_balance = current.checked_add(&deposit.amount).ok_or(ZkSyncError::InternalError)?;
        state.set_balance(deposit.recipient, new_balance);
        Ok(Some(deposit))
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

impl Default for DepositHandler {
    fn default() -> Self {
        Self::new()
    }
}
