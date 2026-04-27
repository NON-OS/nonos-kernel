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

use super::{BatchNumber, BlockNumber, Nonce, TxHash, U256};
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct L2Block {
    pub number: BlockNumber,
    pub timestamp: u64,
    pub parent_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub transactions: Vec<TxHash>,
    pub batch_number: Option<BatchNumber>,
}

#[derive(Clone, Debug)]
pub struct Batch {
    pub number: BatchNumber,
    pub blocks: Vec<BlockNumber>,
    pub timestamp: u64,
    pub l1_commit_block: Option<u64>,
    pub l1_prove_block: Option<u64>,
    pub l1_execute_block: Option<u64>,
    pub commitment: Option<[u8; 32]>,
    pub state_root_before: [u8; 32],
    pub state_root_after: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct AccountState {
    pub nonce: Nonce,
    pub balance: U256,
    pub code_hash: [u8; 32],
    pub storage_root: [u8; 32],
}

impl AccountState {
    pub const EMPTY_CODE_HASH: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];

    pub fn is_empty(&self) -> bool {
        self.nonce.0 == 0 && self.balance.is_zero() && self.code_hash == Self::EMPTY_CODE_HASH
    }
}
