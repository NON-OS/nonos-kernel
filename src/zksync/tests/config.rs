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

use crate::test::framework::TestResult;
use crate::zksync::config::ZkSyncConfig;

pub(crate) fn test_config_default_max_tx_per_block() -> TestResult {
    let config = ZkSyncConfig::default();
    if config.max_tx_per_block != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_default_max_blocks_per_batch() -> TestResult {
    let config = ZkSyncConfig::default();
    if config.max_blocks_per_batch != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_default_block_time_ms() -> TestResult {
    let config = ZkSyncConfig::default();
    if config.block_time_ms != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_default_gas_per_pubdata_byte() -> TestResult {
    let config = ZkSyncConfig::default();
    if config.gas_per_pubdata_byte != 800 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_default_max_gas_per_batch() -> TestResult {
    let config = ZkSyncConfig::default();
    if config.max_gas_per_batch != 80_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_default_l1_chain_id() -> TestResult {
    let config = ZkSyncConfig::default();
    if config.l1_chain_id != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_default_l2_chain_id() -> TestResult {
    let config = ZkSyncConfig::default();
    if config.l2_chain_id != 324 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_default_sequencer_address() -> TestResult {
    let config = ZkSyncConfig::default();
    if config.sequencer_address != [0u8; 20] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_default_bootloader_hash() -> TestResult {
    let config = ZkSyncConfig::default();
    if config.bootloader_hash != [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_default_default_aa_hash() -> TestResult {
    let config = ZkSyncConfig::default();
    if config.default_aa_hash != [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_mainnet_l1_chain_id() -> TestResult {
    let config = ZkSyncConfig::mainnet();
    if config.l1_chain_id != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_mainnet_l2_chain_id() -> TestResult {
    let config = ZkSyncConfig::mainnet();
    if config.l2_chain_id != 324 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_sepolia_l1_chain_id() -> TestResult {
    let config = ZkSyncConfig::sepolia();
    if config.l1_chain_id != 11155111 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_sepolia_l2_chain_id() -> TestResult {
    let config = ZkSyncConfig::sepolia();
    if config.l2_chain_id != 300 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_clone() -> TestResult {
    let config = ZkSyncConfig::default();
    let cloned = config.clone();
    if config.max_tx_per_block != cloned.max_tx_per_block {
        return TestResult::Fail;
    }
    if config.l1_chain_id != cloned.l1_chain_id {
        return TestResult::Fail;
    }
    if config.l2_chain_id != cloned.l2_chain_id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_debug_format() -> TestResult {
    let config = ZkSyncConfig::default();
    let debug = alloc::format!("{:?}", config);
    if !debug.contains("ZkSyncConfig") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_custom_values() -> TestResult {
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
    if config.max_tx_per_block != 500 {
        return TestResult::Fail;
    }
    if config.l1_chain_id != 5 {
        return TestResult::Fail;
    }
    if config.l2_chain_id != 280 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_mainnet_inherits_defaults() -> TestResult {
    let mainnet = ZkSyncConfig::mainnet();
    let default = ZkSyncConfig::default();
    if mainnet.max_tx_per_block != default.max_tx_per_block {
        return TestResult::Fail;
    }
    if mainnet.max_blocks_per_batch != default.max_blocks_per_batch {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_sepolia_inherits_defaults() -> TestResult {
    let sepolia = ZkSyncConfig::sepolia();
    let default = ZkSyncConfig::default();
    if sepolia.max_tx_per_block != default.max_tx_per_block {
        return TestResult::Fail;
    }
    if sepolia.gas_per_pubdata_byte != default.gas_per_pubdata_byte {
        return TestResult::Fail;
    }
    TestResult::Pass
}
