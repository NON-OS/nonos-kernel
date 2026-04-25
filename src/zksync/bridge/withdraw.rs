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
use crate::zksync::types::{Address, BatchNumber, U256};
use alloc::collections::VecDeque;

#[derive(Clone, Debug)]
pub(super) struct Withdrawal {
    pub sender: Address,
    pub l1_recipient: Address,
    pub amount: U256,
    pub batch: BatchNumber,
    pub message_hash: [u8; 32],
}

pub struct WithdrawHandler {
    pending: VecDeque<Withdrawal>,
    finalized: VecDeque<Withdrawal>,
}

impl WithdrawHandler {
    pub fn new() -> Self {
        Self { pending: VecDeque::new(), finalized: VecDeque::new() }
    }

    pub fn initiate(
        &mut self,
        state: &mut StateManager,
        sender: Address,
        recipient: Address,
        amount: U256,
    ) -> Result<[u8; 32], ZkSyncError> {
        let balance = state.get_balance(&sender);
        let new_balance = balance.checked_sub(&amount).ok_or(ZkSyncError::InsufficientBalance)?;
        state.set_balance(sender, new_balance);
        let batch = state.current_batch();
        let mut hash_input = [0u8; 72];
        hash_input[..20].copy_from_slice(sender.as_bytes());
        hash_input[20..40].copy_from_slice(recipient.as_bytes());
        hash_input[40..72].copy_from_slice(&amount.to_bytes_be());
        let message_hash = crate::crypto::sha256(&hash_input);
        let withdrawal =
            Withdrawal { sender, l1_recipient: recipient, amount, batch, message_hash };
        self.pending.push_back(withdrawal);
        Ok(message_hash)
    }

    pub fn finalize_batch(&mut self, batch: BatchNumber) {
        while let Some(w) = self.pending.front() {
            if w.batch.0 <= batch.0 {
                if let Some(w) = self.pending.pop_front() {
                    self.finalized.push_back(w);
                }
            } else {
                break;
            }
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
    pub fn finalized_count(&self) -> usize {
        self.finalized.len()
    }
}

impl Default for WithdrawHandler {
    fn default() -> Self {
        Self::new()
    }
}
