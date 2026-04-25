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
use crate::zksync::types::*;

pub(crate) fn test_address_zero() -> TestResult {
    let addr = Address::ZERO;
    if addr.0 != [0u8; 20] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_from_bytes_valid() -> TestResult {
    let bytes = [1u8; 20];
    let addr = Address::from_bytes(&bytes);
    if addr.is_none() {
        return TestResult::Fail;
    }
    if addr.unwrap().0 != bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_from_bytes_invalid_length() -> TestResult {
    let short: [u8; 19] = [1u8; 19];
    let addr = Address::from_bytes(&short);
    if addr.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_from_slice() -> TestResult {
    let bytes = [0xAB; 20];
    let addr = Address::from_slice(&bytes);
    if addr.0 != bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_as_bytes() -> TestResult {
    let bytes = [0xCD; 20];
    let addr = Address::from_slice(&bytes);
    if addr.as_bytes() != &bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_from_array() -> TestResult {
    let bytes: [u8; 20] = [0x12; 20];
    let addr: Address = bytes.into();
    if addr.0 != bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_as_ref() -> TestResult {
    let bytes = [0x34; 20];
    let addr = Address::from_slice(&bytes);
    let slice: &[u8] = addr.as_ref();
    if slice != &bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_debug_format() -> TestResult {
    let addr = Address::ZERO;
    let debug = alloc::format!("{:?}", addr);
    if !debug.starts_with("0x") {
        return TestResult::Fail;
    }
    if debug.len() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_equality() -> TestResult {
    let a1 = Address::from_slice(&[1u8; 20]);
    let a2 = Address::from_slice(&[1u8; 20]);
    let a3 = Address::from_slice(&[2u8; 20]);
    if a1 != a2 {
        return TestResult::Fail;
    }
    if a1 == a3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_ordering() -> TestResult {
    let a1 = Address::from_slice(&[0u8; 20]);
    let a2 = Address::from_slice(&[1u8; 20]);
    if !(a1 < a2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_default() -> TestResult {
    let addr: Address = Default::default();
    if addr != Address::ZERO {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_zero() -> TestResult {
    let u = U256::ZERO;
    if !u.is_zero() {
        return TestResult::Fail;
    }
    if u.0 != [0, 0, 0, 0] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_one() -> TestResult {
    let u = U256::ONE;
    if u.is_zero() {
        return TestResult::Fail;
    }
    if u.0[0] != 1 {
        return TestResult::Fail;
    }
    if u.0[1] != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_from_u64() -> TestResult {
    let u = U256::from_u64(12345);
    if u.0[0] != 12345 {
        return TestResult::Fail;
    }
    if u.0[1] != 0 {
        return TestResult::Fail;
    }
    if u.0[2] != 0 {
        return TestResult::Fail;
    }
    if u.0[3] != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_from_bytes_be() -> TestResult {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let u = U256::from_bytes_be(&bytes);
    if u.0[0] != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_to_bytes_be() -> TestResult {
    let u = U256::from_u64(0x0102030405060708);
    let bytes = u.to_bytes_be();
    if bytes[24] != 0x01 {
        return TestResult::Fail;
    }
    if bytes[31] != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_roundtrip() -> TestResult {
    let original = U256([0x1111, 0x2222, 0x3333, 0x4444]);
    let bytes = original.to_bytes_be();
    let restored = U256::from_bytes_be(&bytes);
    if original != restored {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_checked_add() -> TestResult {
    let a = U256::from_u64(100);
    let b = U256::from_u64(200);
    let sum = a.checked_add(&b);
    if sum.is_none() {
        return TestResult::Fail;
    }
    if sum.unwrap().0[0] != 300 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_checked_add_overflow() -> TestResult {
    let max = U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
    let one = U256::ONE;
    let result = max.checked_add(&one);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_checked_sub() -> TestResult {
    let a = U256::from_u64(300);
    let b = U256::from_u64(100);
    let diff = a.checked_sub(&b);
    if diff.is_none() {
        return TestResult::Fail;
    }
    if diff.unwrap().0[0] != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_checked_sub_underflow() -> TestResult {
    let a = U256::from_u64(100);
    let b = U256::from_u64(200);
    let result = a.checked_sub(&b);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_is_zero() -> TestResult {
    if !U256::ZERO.is_zero() {
        return TestResult::Fail;
    }
    if U256::ONE.is_zero() {
        return TestResult::Fail;
    }
    if U256::from_u64(1).is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_debug_format() -> TestResult {
    let u = U256::from_u64(0xFF);
    let debug = alloc::format!("{:?}", u);
    if !debug.starts_with("0x") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_equality() -> TestResult {
    let a = U256::from_u64(42);
    let b = U256::from_u64(42);
    let c = U256::from_u64(43);
    if a != b {
        return TestResult::Fail;
    }
    if a == c {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_u256_ordering() -> TestResult {
    let a = U256::from_u64(10);
    let b = U256::from_u64(20);
    if !(a < b) {
        return TestResult::Fail;
    }
    if !(b > a) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_batch_number_default() -> TestResult {
    let bn: BatchNumber = Default::default();
    if bn.0 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_batch_number_equality() -> TestResult {
    let a = BatchNumber(10);
    let b = BatchNumber(10);
    let c = BatchNumber(11);
    if a != b {
        return TestResult::Fail;
    }
    if a == c {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_batch_number_ordering() -> TestResult {
    let a = BatchNumber(5);
    let b = BatchNumber(10);
    if !(a < b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_block_number_default() -> TestResult {
    let bn: BlockNumber = Default::default();
    if bn.0 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_block_number_equality() -> TestResult {
    let a = BlockNumber(100);
    let b = BlockNumber(100);
    if a != b {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nonce_default() -> TestResult {
    let n: Nonce = Default::default();
    if n.0 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nonce_increment() -> TestResult {
    let mut n = Nonce(0);
    n.increment();
    if n.0 != 1 {
        return TestResult::Fail;
    }
    n.increment();
    if n.0 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nonce_increment_saturating() -> TestResult {
    let mut n = Nonce(u64::MAX);
    n.increment();
    if n.0 != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gas_default() -> TestResult {
    let g: Gas = Default::default();
    if g.0 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gas_equality() -> TestResult {
    let a = Gas(21000);
    let b = Gas(21000);
    if a != b {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_hash_zero() -> TestResult {
    let h = TxHash::ZERO;
    if h.0 != [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_hash_from_bytes() -> TestResult {
    let bytes = [0xAB; 32];
    let h = TxHash::from_bytes(&bytes);
    if h.0 != bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_hash_as_bytes() -> TestResult {
    let bytes = [0xCD; 32];
    let h = TxHash::from_bytes(&bytes);
    if h.as_bytes() != &bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_hash_from_array() -> TestResult {
    let bytes: [u8; 32] = [0xEF; 32];
    let h: TxHash = bytes.into();
    if h.0 != bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_hash_debug_format() -> TestResult {
    let h = TxHash::ZERO;
    let debug = alloc::format!("{:?}", h);
    if !debug.starts_with("0x") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_hash_equality() -> TestResult {
    let a = TxHash::from_bytes(&[1u8; 32]);
    let b = TxHash::from_bytes(&[1u8; 32]);
    let c = TxHash::from_bytes(&[2u8; 32]);
    if a != b {
        return TestResult::Fail;
    }
    if a == c {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_signature_default() -> TestResult {
    let sig: TransactionSignature = Default::default();
    if sig.v != 0 {
        return TestResult::Fail;
    }
    if sig.r != [0u8; 32] {
        return TestResult::Fail;
    }
    if sig.s != [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_status_pending() -> TestResult {
    let status = TransactionStatus::Pending;
    if status != TransactionStatus::Pending {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_status_included() -> TestResult {
    let status = TransactionStatus::Included { block: BlockNumber(100) };
    if let TransactionStatus::Included { block } = status {
        if block.0 != 100 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_status_committed() -> TestResult {
    let status = TransactionStatus::Committed { batch: BatchNumber(50) };
    if let TransactionStatus::Committed { batch } = status {
        if batch.0 != 50 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_status_proven() -> TestResult {
    let status = TransactionStatus::Proven { batch: BatchNumber(25) };
    if let TransactionStatus::Proven { batch } = status {
        if batch.0 != 25 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_status_finalized() -> TestResult {
    let status = TransactionStatus::Finalized { batch: BatchNumber(10) };
    if let TransactionStatus::Finalized { batch } = status {
        if batch.0 != 10 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_status_failed() -> TestResult {
    let status = TransactionStatus::Failed { reason: TxFailReason::OutOfGas };
    if let TransactionStatus::Failed { reason } = status {
        if reason != TxFailReason::OutOfGas {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_fail_reason_variants() -> TestResult {
    let reasons = [
        TxFailReason::InvalidSignature,
        TxFailReason::InsufficientBalance,
        TxFailReason::NonceTooLow,
        TxFailReason::NonceTooHigh,
        TxFailReason::GasLimitExceeded,
        TxFailReason::OutOfGas,
        TxFailReason::Reverted,
        TxFailReason::InvalidInput,
    ];
    for (i, reason) in reasons.iter().enumerate() {
        if *reason != reasons[i] {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_account_state_default() -> TestResult {
    let state: AccountState = Default::default();
    if state.nonce.0 != 0 {
        return TestResult::Fail;
    }
    if !state.balance.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_state_empty_code_hash() -> TestResult {
    let expected = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];
    if AccountState::EMPTY_CODE_HASH != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_state_is_empty_true() -> TestResult {
    let state = AccountState {
        nonce: Nonce(0),
        balance: U256::ZERO,
        code_hash: AccountState::EMPTY_CODE_HASH,
        storage_root: [0u8; 32],
    };
    if !state.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_state_is_empty_false_nonce() -> TestResult {
    let state = AccountState {
        nonce: Nonce(1),
        balance: U256::ZERO,
        code_hash: AccountState::EMPTY_CODE_HASH,
        storage_root: [0u8; 32],
    };
    if state.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_state_is_empty_false_balance() -> TestResult {
    let state = AccountState {
        nonce: Nonce(0),
        balance: U256::ONE,
        code_hash: AccountState::EMPTY_CODE_HASH,
        storage_root: [0u8; 32],
    };
    if state.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_state_is_empty_false_code() -> TestResult {
    let state = AccountState {
        nonce: Nonce(0),
        balance: U256::ZERO,
        code_hash: [1u8; 32],
        storage_root: [0u8; 32],
    };
    if state.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_l2_block_clone() -> TestResult {
    let block = L2Block {
        number: BlockNumber(100),
        timestamp: 1234567890,
        parent_hash: [0xAB; 32],
        state_root: [0xCD; 32],
        transactions: alloc::vec![TxHash::ZERO],
        batch_number: Some(BatchNumber(5)),
    };
    let cloned = block.clone();
    if block.number != cloned.number {
        return TestResult::Fail;
    }
    if block.timestamp != cloned.timestamp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_batch_clone() -> TestResult {
    let batch = Batch {
        number: BatchNumber(10),
        blocks: alloc::vec![BlockNumber(1), BlockNumber(2)],
        timestamp: 9999,
        l1_commit_block: Some(100),
        l1_prove_block: None,
        l1_execute_block: None,
        commitment: Some([0xFF; 32]),
        state_root_before: [0x11; 32],
        state_root_after: [0x22; 32],
    };
    let cloned = batch.clone();
    if batch.number != cloned.number {
        return TestResult::Fail;
    }
    if batch.blocks.len() != cloned.blocks.len() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
