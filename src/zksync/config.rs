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

#[derive(Clone, Debug)]
pub struct ZkSyncConfig {
    pub max_tx_per_block: usize,
    pub max_blocks_per_batch: usize,
    pub block_time_ms: u64,
    pub gas_per_pubdata_byte: u64,
    pub max_gas_per_batch: u64,
    pub l1_chain_id: u64,
    pub l2_chain_id: u64,
    pub sequencer_address: [u8; 20],
    pub bootloader_hash: [u8; 32],
    pub default_aa_hash: [u8; 32],
}

impl Default for ZkSyncConfig {
    fn default() -> Self {
        Self {
            max_tx_per_block: 1000,
            max_blocks_per_batch: 100,
            block_time_ms: 1000,
            gas_per_pubdata_byte: 800,
            max_gas_per_batch: 80_000_000,
            l1_chain_id: 1,
            l2_chain_id: 324,
            sequencer_address: [0u8; 20],
            bootloader_hash: [0u8; 32],
            default_aa_hash: [0u8; 32],
        }
    }
}

impl ZkSyncConfig {
    pub fn mainnet() -> Self {
        Self { l1_chain_id: 1, l2_chain_id: 324, ..Default::default() }
    }

    pub fn sepolia() -> Self {
        Self { l1_chain_id: 11155111, l2_chain_id: 300, ..Default::default() }
    }
}
