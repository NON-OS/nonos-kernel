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

use super::{Address, BatchNumber, BlockNumber, Gas, Nonce, TxHash, U256};
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct L2Transaction {
    pub hash: TxHash,
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub nonce: Nonce,
    pub gas_limit: Gas,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub signature: TransactionSignature,
}

#[derive(Clone, Debug, Default)]
pub struct TransactionSignature {
    pub v: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Included { block: BlockNumber },
    Committed { batch: BatchNumber },
    Proven { batch: BatchNumber },
    Finalized { batch: BatchNumber },
    Failed { reason: TxFailReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxFailReason {
    InvalidSignature,
    InsufficientBalance,
    NonceTooLow,
    NonceTooHigh,
    GasLimitExceeded,
    OutOfGas,
    Reverted,
    InvalidInput,
}
