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

use crate::zksync::*;

#[test]
fn test_syscall_submit_tx() {
    assert_eq!(SYS_ZKSYNC_SUBMIT_TX, 420);
}

#[test]
fn test_syscall_get_tx_status() {
    assert_eq!(SYS_ZKSYNC_GET_TX_STATUS, 421);
}

#[test]
fn test_syscall_get_balance() {
    assert_eq!(SYS_ZKSYNC_GET_BALANCE, 422);
}

#[test]
fn test_syscall_get_nonce() {
    assert_eq!(SYS_ZKSYNC_GET_NONCE, 423);
}

#[test]
fn test_syscall_call() {
    assert_eq!(SYS_ZKSYNC_CALL, 424);
}

#[test]
fn test_syscall_estimate_gas() {
    assert_eq!(SYS_ZKSYNC_ESTIMATE_GAS, 425);
}

#[test]
fn test_syscall_get_block() {
    assert_eq!(SYS_ZKSYNC_GET_BLOCK, 426);
}

#[test]
fn test_syscall_get_batch() {
    assert_eq!(SYS_ZKSYNC_GET_BATCH, 427);
}

#[test]
fn test_syscall_prove_batch() {
    assert_eq!(SYS_ZKSYNC_PROVE_BATCH, 428);
}

#[test]
fn test_syscall_get_proof() {
    assert_eq!(SYS_ZKSYNC_GET_PROOF, 429);
}

#[test]
fn test_syscall_bridge_deposit() {
    assert_eq!(SYS_ZKSYNC_BRIDGE_DEPOSIT, 430);
}

#[test]
fn test_syscall_bridge_withdraw() {
    assert_eq!(SYS_ZKSYNC_BRIDGE_WITHDRAW, 431);
}

#[test]
fn test_syscall_numbers_sequential() {
    assert_eq!(SYS_ZKSYNC_GET_TX_STATUS, SYS_ZKSYNC_SUBMIT_TX + 1);
    assert_eq!(SYS_ZKSYNC_GET_BALANCE, SYS_ZKSYNC_GET_TX_STATUS + 1);
    assert_eq!(SYS_ZKSYNC_GET_NONCE, SYS_ZKSYNC_GET_BALANCE + 1);
    assert_eq!(SYS_ZKSYNC_CALL, SYS_ZKSYNC_GET_NONCE + 1);
    assert_eq!(SYS_ZKSYNC_ESTIMATE_GAS, SYS_ZKSYNC_CALL + 1);
    assert_eq!(SYS_ZKSYNC_GET_BLOCK, SYS_ZKSYNC_ESTIMATE_GAS + 1);
    assert_eq!(SYS_ZKSYNC_GET_BATCH, SYS_ZKSYNC_GET_BLOCK + 1);
    assert_eq!(SYS_ZKSYNC_PROVE_BATCH, SYS_ZKSYNC_GET_BATCH + 1);
    assert_eq!(SYS_ZKSYNC_GET_PROOF, SYS_ZKSYNC_PROVE_BATCH + 1);
    assert_eq!(SYS_ZKSYNC_BRIDGE_DEPOSIT, SYS_ZKSYNC_GET_PROOF + 1);
    assert_eq!(SYS_ZKSYNC_BRIDGE_WITHDRAW, SYS_ZKSYNC_BRIDGE_DEPOSIT + 1);
}

#[test]
fn test_syscall_numbers_unique() {
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
            assert_ne!(syscalls[i], syscalls[j]);
        }
    }
}

#[test]
fn test_public_exports_address() {
    let _: Address = Address::ZERO;
}

#[test]
fn test_public_exports_u256() {
    let _: U256 = U256::ZERO;
}

#[test]
fn test_public_exports_batch_number() {
    let _: BatchNumber = BatchNumber(0);
}

#[test]
fn test_public_exports_block_number() {
    let _: BlockNumber = BlockNumber(0);
}

#[test]
fn test_public_exports_nonce() {
    let _: Nonce = Nonce(0);
}

#[test]
fn test_public_exports_gas() {
    let _: Gas = Gas(0);
}

#[test]
fn test_public_exports_tx_hash() {
    let _: TxHash = TxHash::ZERO;
}

#[test]
fn test_public_exports_zksync_config() {
    let _: ZkSyncConfig = ZkSyncConfig::default();
}

#[test]
fn test_public_exports_zksync_error() {
    let _: ZkSyncError = ZkSyncError::NotInitialized;
}

#[test]
fn test_public_exports_goldilocks_field() {
    let _: GoldilocksField = GoldilocksField::ZERO;
}

#[test]
fn test_public_exports_sparse_merkle_tree() {
    let _: SparseMerkleTree = SparseMerkleTree::new();
}

#[test]
fn test_init_zksync_function_exists() {
    let _ = init_zksync(ZkSyncConfig::default());
}

#[test]
fn test_is_initialized_function_exists() {
    let _ = is_initialized();
}
