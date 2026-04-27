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

#![allow(dead_code)]

extern crate alloc;

pub mod bridge;
pub mod config;
pub mod eravm;
pub mod error;
pub mod prover;
pub mod sequencer;
pub mod state;
pub mod syscall;
pub mod types;

mod global;

pub use config::ZkSyncConfig;
pub use error::ZkSyncError;
pub use global::{init_zksync, is_initialized};
pub use prover::boojum::GoldilocksField;
pub use state::SparseMerkleTree;
pub use types::{Address, BatchNumber, BlockNumber, Gas, Nonce, TxHash, U256};

pub const SYS_ZKSYNC_SUBMIT_TX: u64 = 420;
pub const SYS_ZKSYNC_GET_TX_STATUS: u64 = 421;
pub const SYS_ZKSYNC_GET_BALANCE: u64 = 422;
pub const SYS_ZKSYNC_GET_NONCE: u64 = 423;
pub const SYS_ZKSYNC_CALL: u64 = 424;
pub const SYS_ZKSYNC_ESTIMATE_GAS: u64 = 425;
pub const SYS_ZKSYNC_GET_BLOCK: u64 = 426;
pub const SYS_ZKSYNC_GET_BATCH: u64 = 427;
pub const SYS_ZKSYNC_PROVE_BATCH: u64 = 428;
pub const SYS_ZKSYNC_GET_PROOF: u64 = 429;
pub const SYS_ZKSYNC_BRIDGE_DEPOSIT: u64 = 430;
pub const SYS_ZKSYNC_BRIDGE_WITHDRAW: u64 = 431;

#[cfg(test)]
#[cfg(test)]
pub mod tests;
