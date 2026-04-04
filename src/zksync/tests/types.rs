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

use crate::zksync::types::*;

#[test]
fn test_address_zero() {
    let addr = Address::ZERO;
    assert_eq!(addr.0, [0u8; 20]);
}

#[test]
fn test_address_from_bytes_valid() {
    let bytes = [1u8; 20];
    let addr = Address::from_bytes(&bytes);
    assert!(addr.is_some());
    assert_eq!(addr.unwrap().0, bytes);
}

#[test]
fn test_address_from_bytes_invalid_length() {
    let short: [u8; 19] = [1u8; 19];
    let addr = Address::from_bytes(&short);
    assert!(addr.is_none());
}

#[test]
fn test_address_from_slice() {
    let bytes = [0xAB; 20];
    let addr = Address::from_slice(&bytes);
    assert_eq!(addr.0, bytes);
}

#[test]
fn test_address_as_bytes() {
    let bytes = [0xCD; 20];
    let addr = Address::from_slice(&bytes);
    assert_eq!(addr.as_bytes(), &bytes);
}

#[test]
fn test_address_from_array() {
    let bytes: [u8; 20] = [0x12; 20];
    let addr: Address = bytes.into();
    assert_eq!(addr.0, bytes);
}

#[test]
fn test_address_as_ref() {
    let bytes = [0x34; 20];
    let addr = Address::from_slice(&bytes);
    let slice: &[u8] = addr.as_ref();
    assert_eq!(slice, &bytes);
}

#[test]
fn test_address_debug_format() {
    let addr = Address::ZERO;
    let debug = alloc::format!("{:?}", addr);
    assert!(debug.starts_with("0x"));
    assert_eq!(debug.len(), 42);
}

#[test]
fn test_address_equality() {
    let a1 = Address::from_slice(&[1u8; 20]);
    let a2 = Address::from_slice(&[1u8; 20]);
    let a3 = Address::from_slice(&[2u8; 20]);
    assert_eq!(a1, a2);
    assert_ne!(a1, a3);
}

#[test]
fn test_address_ordering() {
    let a1 = Address::from_slice(&[0u8; 20]);
    let a2 = Address::from_slice(&[1u8; 20]);
    assert!(a1 < a2);
}

#[test]
fn test_address_default() {
    let addr: Address = Default::default();
    assert_eq!(addr, Address::ZERO);
}

#[test]
fn test_u256_zero() {
    let u = U256::ZERO;
    assert!(u.is_zero());
    assert_eq!(u.0, [0, 0, 0, 0]);
}

#[test]
fn test_u256_one() {
    let u = U256::ONE;
    assert!(!u.is_zero());
    assert_eq!(u.0[0], 1);
    assert_eq!(u.0[1], 0);
}

#[test]
fn test_u256_from_u64() {
    let u = U256::from_u64(12345);
    assert_eq!(u.0[0], 12345);
    assert_eq!(u.0[1], 0);
    assert_eq!(u.0[2], 0);
    assert_eq!(u.0[3], 0);
}

#[test]
fn test_u256_from_bytes_be() {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let u = U256::from_bytes_be(&bytes);
    assert_eq!(u.0[0], 1);
}

#[test]
fn test_u256_to_bytes_be() {
    let u = U256::from_u64(0x0102030405060708);
    let bytes = u.to_bytes_be();
    assert_eq!(bytes[24], 0x01);
    assert_eq!(bytes[31], 0x08);
}

#[test]
fn test_u256_roundtrip() {
    let original = U256([0x1111, 0x2222, 0x3333, 0x4444]);
    let bytes = original.to_bytes_be();
    let restored = U256::from_bytes_be(&bytes);
    assert_eq!(original, restored);
}

#[test]
fn test_u256_checked_add() {
    let a = U256::from_u64(100);
    let b = U256::from_u64(200);
    let sum = a.checked_add(&b);
    assert!(sum.is_some());
    assert_eq!(sum.unwrap().0[0], 300);
}

#[test]
fn test_u256_checked_add_overflow() {
    let max = U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
    let one = U256::ONE;
    let result = max.checked_add(&one);
    assert!(result.is_none());
}

#[test]
fn test_u256_checked_sub() {
    let a = U256::from_u64(300);
    let b = U256::from_u64(100);
    let diff = a.checked_sub(&b);
    assert!(diff.is_some());
    assert_eq!(diff.unwrap().0[0], 200);
}

#[test]
fn test_u256_checked_sub_underflow() {
    let a = U256::from_u64(100);
    let b = U256::from_u64(200);
    let result = a.checked_sub(&b);
    assert!(result.is_none());
}

#[test]
fn test_u256_is_zero() {
    assert!(U256::ZERO.is_zero());
    assert!(!U256::ONE.is_zero());
    assert!(!U256::from_u64(1).is_zero());
}

#[test]
fn test_u256_debug_format() {
    let u = U256::from_u64(0xFF);
    let debug = alloc::format!("{:?}", u);
    assert!(debug.starts_with("0x"));
}

#[test]
fn test_u256_equality() {
    let a = U256::from_u64(42);
    let b = U256::from_u64(42);
    let c = U256::from_u64(43);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_u256_ordering() {
    let a = U256::from_u64(10);
    let b = U256::from_u64(20);
    assert!(a < b);
    assert!(b > a);
}

#[test]
fn test_batch_number_default() {
    let bn: BatchNumber = Default::default();
    assert_eq!(bn.0, 0);
}

#[test]
fn test_batch_number_equality() {
    let a = BatchNumber(10);
    let b = BatchNumber(10);
    let c = BatchNumber(11);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_batch_number_ordering() {
    let a = BatchNumber(5);
    let b = BatchNumber(10);
    assert!(a < b);
}

#[test]
fn test_block_number_default() {
    let bn: BlockNumber = Default::default();
    assert_eq!(bn.0, 0);
}

#[test]
fn test_block_number_equality() {
    let a = BlockNumber(100);
    let b = BlockNumber(100);
    assert_eq!(a, b);
}

#[test]
fn test_nonce_default() {
    let n: Nonce = Default::default();
    assert_eq!(n.0, 0);
}

#[test]
fn test_nonce_increment() {
    let mut n = Nonce(0);
    n.increment();
    assert_eq!(n.0, 1);
    n.increment();
    assert_eq!(n.0, 2);
}

#[test]
fn test_nonce_increment_saturating() {
    let mut n = Nonce(u64::MAX);
    n.increment();
    assert_eq!(n.0, u64::MAX);
}

#[test]
fn test_gas_default() {
    let g: Gas = Default::default();
    assert_eq!(g.0, 0);
}

#[test]
fn test_gas_equality() {
    let a = Gas(21000);
    let b = Gas(21000);
    assert_eq!(a, b);
}

#[test]
fn test_tx_hash_zero() {
    let h = TxHash::ZERO;
    assert_eq!(h.0, [0u8; 32]);
}

#[test]
fn test_tx_hash_from_bytes() {
    let bytes = [0xAB; 32];
    let h = TxHash::from_bytes(&bytes);
    assert_eq!(h.0, bytes);
}

#[test]
fn test_tx_hash_as_bytes() {
    let bytes = [0xCD; 32];
    let h = TxHash::from_bytes(&bytes);
    assert_eq!(h.as_bytes(), &bytes);
}

#[test]
fn test_tx_hash_from_array() {
    let bytes: [u8; 32] = [0xEF; 32];
    let h: TxHash = bytes.into();
    assert_eq!(h.0, bytes);
}

#[test]
fn test_tx_hash_debug_format() {
    let h = TxHash::ZERO;
    let debug = alloc::format!("{:?}", h);
    assert!(debug.starts_with("0x"));
}

#[test]
fn test_tx_hash_equality() {
    let a = TxHash::from_bytes(&[1u8; 32]);
    let b = TxHash::from_bytes(&[1u8; 32]);
    let c = TxHash::from_bytes(&[2u8; 32]);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_transaction_signature_default() {
    let sig: TransactionSignature = Default::default();
    assert_eq!(sig.v, 0);
    assert_eq!(sig.r, [0u8; 32]);
    assert_eq!(sig.s, [0u8; 32]);
}

#[test]
fn test_transaction_status_pending() {
    let status = TransactionStatus::Pending;
    assert_eq!(status, TransactionStatus::Pending);
}

#[test]
fn test_transaction_status_included() {
    let status = TransactionStatus::Included { block: BlockNumber(100) };
    if let TransactionStatus::Included { block } = status {
        assert_eq!(block.0, 100);
    } else {
        panic!("Expected Included status");
    }
}

#[test]
fn test_transaction_status_committed() {
    let status = TransactionStatus::Committed { batch: BatchNumber(50) };
    if let TransactionStatus::Committed { batch } = status {
        assert_eq!(batch.0, 50);
    } else {
        panic!("Expected Committed status");
    }
}

#[test]
fn test_transaction_status_proven() {
    let status = TransactionStatus::Proven { batch: BatchNumber(25) };
    if let TransactionStatus::Proven { batch } = status {
        assert_eq!(batch.0, 25);
    } else {
        panic!("Expected Proven status");
    }
}

#[test]
fn test_transaction_status_finalized() {
    let status = TransactionStatus::Finalized { batch: BatchNumber(10) };
    if let TransactionStatus::Finalized { batch } = status {
        assert_eq!(batch.0, 10);
    } else {
        panic!("Expected Finalized status");
    }
}

#[test]
fn test_transaction_status_failed() {
    let status = TransactionStatus::Failed { reason: TxFailReason::OutOfGas };
    if let TransactionStatus::Failed { reason } = status {
        assert_eq!(reason, TxFailReason::OutOfGas);
    } else {
        panic!("Expected Failed status");
    }
}

#[test]
fn test_tx_fail_reason_variants() {
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
        assert_eq!(*reason, reasons[i]);
    }
}

#[test]
fn test_account_state_default() {
    let state: AccountState = Default::default();
    assert_eq!(state.nonce.0, 0);
    assert!(state.balance.is_zero());
}

#[test]
fn test_account_state_empty_code_hash() {
    let expected = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
        0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
        0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
    ];
    assert_eq!(AccountState::EMPTY_CODE_HASH, expected);
}

#[test]
fn test_account_state_is_empty_true() {
    let state = AccountState {
        nonce: Nonce(0),
        balance: U256::ZERO,
        code_hash: AccountState::EMPTY_CODE_HASH,
        storage_root: [0u8; 32],
    };
    assert!(state.is_empty());
}

#[test]
fn test_account_state_is_empty_false_nonce() {
    let state = AccountState {
        nonce: Nonce(1),
        balance: U256::ZERO,
        code_hash: AccountState::EMPTY_CODE_HASH,
        storage_root: [0u8; 32],
    };
    assert!(!state.is_empty());
}

#[test]
fn test_account_state_is_empty_false_balance() {
    let state = AccountState {
        nonce: Nonce(0),
        balance: U256::ONE,
        code_hash: AccountState::EMPTY_CODE_HASH,
        storage_root: [0u8; 32],
    };
    assert!(!state.is_empty());
}

#[test]
fn test_account_state_is_empty_false_code() {
    let state = AccountState {
        nonce: Nonce(0),
        balance: U256::ZERO,
        code_hash: [1u8; 32],
        storage_root: [0u8; 32],
    };
    assert!(!state.is_empty());
}

#[test]
fn test_l2_block_clone() {
    let block = L2Block {
        number: BlockNumber(100),
        timestamp: 1234567890,
        parent_hash: [0xAB; 32],
        state_root: [0xCD; 32],
        transactions: alloc::vec![TxHash::ZERO],
        batch_number: Some(BatchNumber(5)),
    };
    let cloned = block.clone();
    assert_eq!(block.number, cloned.number);
    assert_eq!(block.timestamp, cloned.timestamp);
}

#[test]
fn test_batch_clone() {
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
    assert_eq!(batch.number, cloned.number);
    assert_eq!(batch.blocks.len(), cloned.blocks.len());
}
