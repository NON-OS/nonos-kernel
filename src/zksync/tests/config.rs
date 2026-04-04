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

extern crate alloc;

use crate::zksync::config::ZkSyncConfig;

#[test]
fn test_config_default_max_tx_per_block() {
    let config = ZkSyncConfig::default();
    assert_eq!(config.max_tx_per_block, 1000);
}

#[test]
fn test_config_default_max_blocks_per_batch() {
    let config = ZkSyncConfig::default();
    assert_eq!(config.max_blocks_per_batch, 100);
}

#[test]
fn test_config_default_block_time_ms() {
    let config = ZkSyncConfig::default();
    assert_eq!(config.block_time_ms, 1000);
}

#[test]
fn test_config_default_gas_per_pubdata_byte() {
    let config = ZkSyncConfig::default();
    assert_eq!(config.gas_per_pubdata_byte, 800);
}

#[test]
fn test_config_default_max_gas_per_batch() {
    let config = ZkSyncConfig::default();
    assert_eq!(config.max_gas_per_batch, 80_000_000);
}

#[test]
fn test_config_default_l1_chain_id() {
    let config = ZkSyncConfig::default();
    assert_eq!(config.l1_chain_id, 1);
}

#[test]
fn test_config_default_l2_chain_id() {
    let config = ZkSyncConfig::default();
    assert_eq!(config.l2_chain_id, 324);
}

#[test]
fn test_config_default_sequencer_address() {
    let config = ZkSyncConfig::default();
    assert_eq!(config.sequencer_address, [0u8; 20]);
}

#[test]
fn test_config_default_bootloader_hash() {
    let config = ZkSyncConfig::default();
    assert_eq!(config.bootloader_hash, [0u8; 32]);
}

#[test]
fn test_config_default_default_aa_hash() {
    let config = ZkSyncConfig::default();
    assert_eq!(config.default_aa_hash, [0u8; 32]);
}

#[test]
fn test_config_mainnet_l1_chain_id() {
    let config = ZkSyncConfig::mainnet();
    assert_eq!(config.l1_chain_id, 1);
}

#[test]
fn test_config_mainnet_l2_chain_id() {
    let config = ZkSyncConfig::mainnet();
    assert_eq!(config.l2_chain_id, 324);
}

#[test]
fn test_config_sepolia_l1_chain_id() {
    let config = ZkSyncConfig::sepolia();
    assert_eq!(config.l1_chain_id, 11155111);
}

#[test]
fn test_config_sepolia_l2_chain_id() {
    let config = ZkSyncConfig::sepolia();
    assert_eq!(config.l2_chain_id, 300);
}

#[test]
fn test_config_clone() {
    let config = ZkSyncConfig::default();
    let cloned = config.clone();
    assert_eq!(config.max_tx_per_block, cloned.max_tx_per_block);
    assert_eq!(config.l1_chain_id, cloned.l1_chain_id);
    assert_eq!(config.l2_chain_id, cloned.l2_chain_id);
}

#[test]
fn test_config_debug_format() {
    let config = ZkSyncConfig::default();
    let debug = alloc::format!("{:?}", config);
    assert!(debug.contains("ZkSyncConfig"));
}

#[test]
fn test_config_custom_values() {
    let config = ZkSyncConfig {
        max_tx_per_block: 500,
        max_blocks_per_batch: 50,
        block_time_ms: 500,
        gas_per_pubdata_byte: 400,
        max_gas_per_batch: 40_000_000,
        l1_chain_id: 5,
        l2_chain_id: 280,
        sequencer_address: [1u8; 20],
        bootloader_hash: [2u8; 32],
        default_aa_hash: [3u8; 32],
    };
    assert_eq!(config.max_tx_per_block, 500);
    assert_eq!(config.l1_chain_id, 5);
    assert_eq!(config.l2_chain_id, 280);
}

#[test]
fn test_config_mainnet_inherits_defaults() {
    let mainnet = ZkSyncConfig::mainnet();
    let default = ZkSyncConfig::default();
    assert_eq!(mainnet.max_tx_per_block, default.max_tx_per_block);
    assert_eq!(mainnet.max_blocks_per_batch, default.max_blocks_per_batch);
}

#[test]
fn test_config_sepolia_inherits_defaults() {
    let sepolia = ZkSyncConfig::sepolia();
    let default = ZkSyncConfig::default();
    assert_eq!(sepolia.max_tx_per_block, default.max_tx_per_block);
    assert_eq!(sepolia.gas_per_pubdata_byte, default.gas_per_pubdata_byte);
}
