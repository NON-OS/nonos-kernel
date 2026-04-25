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
use crate::zksync::types::{BlockNumber, L2Transaction, TransactionStatus, TxFailReason};

pub struct TransactionExecutor<'a> {
    state: &'a mut StateManager,
}

impl<'a> TransactionExecutor<'a> {
    pub fn new(state: &'a mut StateManager) -> Self {
        Self { state }
    }

    pub fn execute(&mut self, tx: &L2Transaction) -> Result<TransactionStatus, ZkSyncError> {
        let sender_nonce = self.state.get_nonce(&tx.from);
        if tx.nonce.0 < sender_nonce.0 {
            return Ok(TransactionStatus::Failed { reason: TxFailReason::NonceTooLow });
        }
        if tx.nonce.0 > sender_nonce.0 {
            return Ok(TransactionStatus::Failed { reason: TxFailReason::NonceTooHigh });
        }
        let sender_balance = self.state.get_balance(&tx.from);
        if sender_balance.checked_sub(&tx.value).is_none() {
            return Ok(TransactionStatus::Failed { reason: TxFailReason::InsufficientBalance });
        }
        if let Some(to) = tx.to {
            self.state.transfer(&tx.from, &to, tx.value)?;
        }
        self.state.increment_nonce(&tx.from);
        Ok(TransactionStatus::Included { block: self.state.current_block() })
    }

    pub fn validate(&self, tx: &L2Transaction) -> Result<(), TxFailReason> {
        let sender_nonce = self.state.get_nonce(&tx.from);
        if tx.nonce.0 < sender_nonce.0 {
            return Err(TxFailReason::NonceTooLow);
        }
        let sender_balance = self.state.get_balance(&tx.from);
        if sender_balance.checked_sub(&tx.value).is_none() {
            return Err(TxFailReason::InsufficientBalance);
        }
        Ok(())
    }

    pub fn current_block(&self) -> BlockNumber {
        self.state.current_block()
    }
}
