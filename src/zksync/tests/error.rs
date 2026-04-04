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

use crate::zksync::error::ZkSyncError;

#[test]
fn test_error_not_initialized() {
    let err = ZkSyncError::NotInitialized;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("not initialized"));
}

#[test]
fn test_error_invalid_transaction() {
    let err = ZkSyncError::InvalidTransaction;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("invalid transaction"));
}

#[test]
fn test_error_invalid_signature() {
    let err = ZkSyncError::InvalidSignature;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("invalid signature"));
}

#[test]
fn test_error_insufficient_balance() {
    let err = ZkSyncError::InsufficientBalance;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("insufficient balance"));
}

#[test]
fn test_error_nonce_mismatch() {
    let err = ZkSyncError::NonceMismatch;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("nonce mismatch"));
}

#[test]
fn test_error_gas_limit_exceeded() {
    let err = ZkSyncError::GasLimitExceeded;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("gas limit exceeded"));
}

#[test]
fn test_error_invalid_proof() {
    let err = ZkSyncError::InvalidProof;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("invalid proof"));
}

#[test]
fn test_error_batch_not_found() {
    let err = ZkSyncError::BatchNotFound;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("batch not found"));
}

#[test]
fn test_error_block_not_found() {
    let err = ZkSyncError::BlockNotFound;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("block not found"));
}

#[test]
fn test_error_account_not_found() {
    let err = ZkSyncError::AccountNotFound;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("account not found"));
}

#[test]
fn test_error_storage_error() {
    let err = ZkSyncError::StorageError;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("storage error"));
}

#[test]
fn test_error_proving_failed() {
    let err = ZkSyncError::ProvingFailed;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("proving failed"));
}

#[test]
fn test_error_witness_generation_failed() {
    let err = ZkSyncError::WitnessGenerationFailed;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("witness generation failed"));
}

#[test]
fn test_error_l1_communication_failed() {
    let err = ZkSyncError::L1CommunicationFailed;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("L1 communication failed"));
}

#[test]
fn test_error_bridge_error() {
    let err = ZkSyncError::BridgeError;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("bridge error"));
}

#[test]
fn test_error_capability_denied() {
    let err = ZkSyncError::CapabilityDenied;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("capability denied"));
}

#[test]
fn test_error_invalid_input() {
    let err = ZkSyncError::InvalidInput;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("invalid input"));
}

#[test]
fn test_error_out_of_memory() {
    let err = ZkSyncError::OutOfMemory;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("out of memory"));
}

#[test]
fn test_error_internal_error() {
    let err = ZkSyncError::InternalError;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("internal error"));
}

#[test]
fn test_error_debug_format() {
    let err = ZkSyncError::NotInitialized;
    let debug = alloc::format!("{:?}", err);
    assert!(debug.contains("NotInitialized"));
}

#[test]
fn test_error_equality() {
    assert_eq!(ZkSyncError::NotInitialized, ZkSyncError::NotInitialized);
    assert_ne!(ZkSyncError::NotInitialized, ZkSyncError::InvalidTransaction);
}

#[test]
fn test_error_clone() {
    let err = ZkSyncError::InvalidProof;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_error_copy() {
    let err = ZkSyncError::StorageError;
    let copied = err;
    assert_eq!(err, copied);
}

#[test]
fn test_all_error_variants_distinct() {
    let errors = [
        ZkSyncError::NotInitialized,
        ZkSyncError::InvalidTransaction,
        ZkSyncError::InvalidSignature,
        ZkSyncError::InsufficientBalance,
        ZkSyncError::NonceMismatch,
        ZkSyncError::GasLimitExceeded,
        ZkSyncError::InvalidProof,
        ZkSyncError::BatchNotFound,
        ZkSyncError::BlockNotFound,
        ZkSyncError::AccountNotFound,
        ZkSyncError::StorageError,
        ZkSyncError::ProvingFailed,
        ZkSyncError::WitnessGenerationFailed,
        ZkSyncError::L1CommunicationFailed,
        ZkSyncError::BridgeError,
        ZkSyncError::CapabilityDenied,
        ZkSyncError::InvalidInput,
        ZkSyncError::OutOfMemory,
        ZkSyncError::InternalError,
    ];
    for i in 0..errors.len() {
        for j in (i + 1)..errors.len() {
            assert_ne!(errors[i], errors[j]);
        }
    }
}
