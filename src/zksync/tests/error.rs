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
use crate::zksync::error::ZkSyncError;

pub(crate) fn test_error_not_initialized() -> TestResult {
    let err = ZkSyncError::NotInitialized;
    let msg = alloc::format!("{}", err);
    if !msg.contains("not initialized") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_transaction() -> TestResult {
    let err = ZkSyncError::InvalidTransaction;
    let msg = alloc::format!("{}", err);
    if !msg.contains("invalid transaction") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_signature() -> TestResult {
    let err = ZkSyncError::InvalidSignature;
    let msg = alloc::format!("{}", err);
    if !msg.contains("invalid signature") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_insufficient_balance() -> TestResult {
    let err = ZkSyncError::InsufficientBalance;
    let msg = alloc::format!("{}", err);
    if !msg.contains("insufficient balance") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_nonce_mismatch() -> TestResult {
    let err = ZkSyncError::NonceMismatch;
    let msg = alloc::format!("{}", err);
    if !msg.contains("nonce mismatch") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_gas_limit_exceeded() -> TestResult {
    let err = ZkSyncError::GasLimitExceeded;
    let msg = alloc::format!("{}", err);
    if !msg.contains("gas limit exceeded") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_proof() -> TestResult {
    let err = ZkSyncError::InvalidProof;
    let msg = alloc::format!("{}", err);
    if !msg.contains("invalid proof") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_batch_not_found() -> TestResult {
    let err = ZkSyncError::BatchNotFound;
    let msg = alloc::format!("{}", err);
    if !msg.contains("batch not found") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_block_not_found() -> TestResult {
    let err = ZkSyncError::BlockNotFound;
    let msg = alloc::format!("{}", err);
    if !msg.contains("block not found") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_account_not_found() -> TestResult {
    let err = ZkSyncError::AccountNotFound;
    let msg = alloc::format!("{}", err);
    if !msg.contains("account not found") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_storage_error() -> TestResult {
    let err = ZkSyncError::StorageError;
    let msg = alloc::format!("{}", err);
    if !msg.contains("storage error") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_proving_failed() -> TestResult {
    let err = ZkSyncError::ProvingFailed;
    let msg = alloc::format!("{}", err);
    if !msg.contains("proving failed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_witness_generation_failed() -> TestResult {
    let err = ZkSyncError::WitnessGenerationFailed;
    let msg = alloc::format!("{}", err);
    if !msg.contains("witness generation failed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_l1_communication_failed() -> TestResult {
    let err = ZkSyncError::L1CommunicationFailed;
    let msg = alloc::format!("{}", err);
    if !msg.contains("L1 communication failed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_bridge_error() -> TestResult {
    let err = ZkSyncError::BridgeError;
    let msg = alloc::format!("{}", err);
    if !msg.contains("bridge error") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_capability_denied() -> TestResult {
    let err = ZkSyncError::CapabilityDenied;
    let msg = alloc::format!("{}", err);
    if !msg.contains("capability denied") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_input() -> TestResult {
    let err = ZkSyncError::InvalidInput;
    let msg = alloc::format!("{}", err);
    if !msg.contains("invalid input") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_out_of_memory() -> TestResult {
    let err = ZkSyncError::OutOfMemory;
    let msg = alloc::format!("{}", err);
    if !msg.contains("out of memory") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_internal_error() -> TestResult {
    let err = ZkSyncError::InternalError;
    let msg = alloc::format!("{}", err);
    if !msg.contains("internal error") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_debug_format() -> TestResult {
    let err = ZkSyncError::NotInitialized;
    let debug = alloc::format!("{:?}", err);
    if !debug.contains("NotInitialized") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_equality() -> TestResult {
    if ZkSyncError::NotInitialized != ZkSyncError::NotInitialized {
        return TestResult::Fail;
    }
    if ZkSyncError::NotInitialized == ZkSyncError::InvalidTransaction {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_clone() -> TestResult {
    let err = ZkSyncError::InvalidProof;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_copy() -> TestResult {
    let err = ZkSyncError::StorageError;
    let copied = err;
    if err != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_error_variants_distinct() -> TestResult {
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
            if errors[i] == errors[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}
