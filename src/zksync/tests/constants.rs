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

use crate::test::framework::TestResult;
use crate::zksync::*;

pub(crate) fn test_syscall_submit_tx() -> TestResult {
    if SYS_ZKSYNC_SUBMIT_TX != 420 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_get_tx_status() -> TestResult {
    if SYS_ZKSYNC_GET_TX_STATUS != 421 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_get_balance() -> TestResult {
    if SYS_ZKSYNC_GET_BALANCE != 422 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_get_nonce() -> TestResult {
    if SYS_ZKSYNC_GET_NONCE != 423 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_call() -> TestResult {
    if SYS_ZKSYNC_CALL != 424 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_estimate_gas() -> TestResult {
    if SYS_ZKSYNC_ESTIMATE_GAS != 425 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_get_block() -> TestResult {
    if SYS_ZKSYNC_GET_BLOCK != 426 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_get_batch() -> TestResult {
    if SYS_ZKSYNC_GET_BATCH != 427 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_prove_batch() -> TestResult {
    if SYS_ZKSYNC_PROVE_BATCH != 428 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_get_proof() -> TestResult {
    if SYS_ZKSYNC_GET_PROOF != 429 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_bridge_deposit() -> TestResult {
    if SYS_ZKSYNC_BRIDGE_DEPOSIT != 430 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_bridge_withdraw() -> TestResult {
    if SYS_ZKSYNC_BRIDGE_WITHDRAW != 431 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_numbers_sequential() -> TestResult {
    if SYS_ZKSYNC_GET_TX_STATUS != SYS_ZKSYNC_SUBMIT_TX + 1 {
        return TestResult::Fail;
    }
    if SYS_ZKSYNC_GET_BALANCE != SYS_ZKSYNC_GET_TX_STATUS + 1 {
        return TestResult::Fail;
    }
    if SYS_ZKSYNC_GET_NONCE != SYS_ZKSYNC_GET_BALANCE + 1 {
        return TestResult::Fail;
    }
    if SYS_ZKSYNC_CALL != SYS_ZKSYNC_GET_NONCE + 1 {
        return TestResult::Fail;
    }
    if SYS_ZKSYNC_ESTIMATE_GAS != SYS_ZKSYNC_CALL + 1 {
        return TestResult::Fail;
    }
    if SYS_ZKSYNC_GET_BLOCK != SYS_ZKSYNC_ESTIMATE_GAS + 1 {
        return TestResult::Fail;
    }
    if SYS_ZKSYNC_GET_BATCH != SYS_ZKSYNC_GET_BLOCK + 1 {
        return TestResult::Fail;
    }
    if SYS_ZKSYNC_PROVE_BATCH != SYS_ZKSYNC_GET_BATCH + 1 {
        return TestResult::Fail;
    }
    if SYS_ZKSYNC_GET_PROOF != SYS_ZKSYNC_PROVE_BATCH + 1 {
        return TestResult::Fail;
    }
    if SYS_ZKSYNC_BRIDGE_DEPOSIT != SYS_ZKSYNC_GET_PROOF + 1 {
        return TestResult::Fail;
    }
    if SYS_ZKSYNC_BRIDGE_WITHDRAW != SYS_ZKSYNC_BRIDGE_DEPOSIT + 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_numbers_unique() -> TestResult {
    let syscalls = [
        SYS_ZKSYNC_SUBMIT_TX,
        SYS_ZKSYNC_GET_TX_STATUS,
        SYS_ZKSYNC_GET_BALANCE,
        SYS_ZKSYNC_GET_NONCE,
        SYS_ZKSYNC_CALL,
        SYS_ZKSYNC_ESTIMATE_GAS,
        SYS_ZKSYNC_GET_BLOCK,
        SYS_ZKSYNC_GET_BATCH,
        SYS_ZKSYNC_PROVE_BATCH,
        SYS_ZKSYNC_GET_PROOF,
        SYS_ZKSYNC_BRIDGE_DEPOSIT,
        SYS_ZKSYNC_BRIDGE_WITHDRAW,
    ];
    for i in 0..syscalls.len() {
        for j in (i + 1)..syscalls.len() {
            if syscalls[i] == syscalls[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_public_exports_address() -> TestResult {
    let _: Address = Address::ZERO;
    TestResult::Pass
}

pub(crate) fn test_public_exports_u256() -> TestResult {
    let _: U256 = U256::ZERO;
    TestResult::Pass
}

pub(crate) fn test_public_exports_batch_number() -> TestResult {
    let _: BatchNumber = BatchNumber(0);
    TestResult::Pass
}

pub(crate) fn test_public_exports_block_number() -> TestResult {
    let _: BlockNumber = BlockNumber(0);
    TestResult::Pass
}

pub(crate) fn test_public_exports_nonce() -> TestResult {
    let _: Nonce = Nonce(0);
    TestResult::Pass
}

pub(crate) fn test_public_exports_gas() -> TestResult {
    let _: Gas = Gas(0);
    TestResult::Pass
}

pub(crate) fn test_public_exports_tx_hash() -> TestResult {
    let _: TxHash = TxHash::ZERO;
    TestResult::Pass
}

pub(crate) fn test_public_exports_zksync_config() -> TestResult {
    let _: ZkSyncConfig = ZkSyncConfig::default();
    TestResult::Pass
}

pub(crate) fn test_public_exports_zksync_error() -> TestResult {
    let _: ZkSyncError = ZkSyncError::NotInitialized;
    TestResult::Pass
}

pub(crate) fn test_public_exports_goldilocks_field() -> TestResult {
    let _: GoldilocksField = GoldilocksField::ZERO;
    TestResult::Pass
}

pub(crate) fn test_public_exports_sparse_merkle_tree() -> TestResult {
    let _: SparseMerkleTree = SparseMerkleTree::new();
    TestResult::Pass
}

pub(crate) fn test_init_zksync_function_exists() -> TestResult {
    let _ = init_zksync(ZkSyncConfig::default());
    TestResult::Pass
}

pub(crate) fn test_is_initialized_function_exists() -> TestResult {
    let _ = is_initialized();
    TestResult::Pass
}
