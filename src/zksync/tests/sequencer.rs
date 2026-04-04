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

use crate::zksync::sequencer::*;
use crate::zksync::state::StateManager;
use crate::zksync::types::*;

fn create_test_tx(hash: [u8; 32], from: Address, nonce: u64, value: u64) -> L2Transaction {
    L2Transaction {
        hash: TxHash(hash),
        from,
        to: Some(Address::ZERO),
        value: U256::from_u64(value),
        data: alloc::vec![],
        nonce: Nonce(nonce),
        gas_limit: Gas(21000),
        max_fee_per_gas: U256::from_u64(1000000000),
        max_priority_fee_per_gas: U256::from_u64(1000000),
        signature: TransactionSignature::default(),
    }
}

#[test]
fn test_transaction_pool_new() {
    let pool = TransactionPool::new(100);
    assert!(pool.is_empty());
    assert_eq!(pool.len(), 0);
}

#[test]
fn test_transaction_pool_default() {
    let pool: TransactionPool = Default::default();
    assert!(pool.is_empty());
}

#[test]
fn test_transaction_pool_insert() {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    assert!(pool.insert(tx));
    assert_eq!(pool.len(), 1);
}

#[test]
fn test_transaction_pool_insert_duplicate() {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx1 = create_test_tx([1u8; 32], from, 0, 100);
    let tx2 = create_test_tx([1u8; 32], from, 0, 100);
    assert!(pool.insert(tx1));
    assert!(!pool.insert(tx2));
    assert_eq!(pool.len(), 1);
}

#[test]
fn test_transaction_pool_insert_full() {
    let mut pool = TransactionPool::new(2);
    let from = Address::from_slice(&[1u8; 20]);
    let tx1 = create_test_tx([1u8; 32], from, 0, 100);
    let tx2 = create_test_tx([2u8; 32], from, 1, 200);
    let tx3 = create_test_tx([3u8; 32], from, 2, 300);
    assert!(pool.insert(tx1));
    assert!(pool.insert(tx2));
    assert!(!pool.insert(tx3));
    assert_eq!(pool.len(), 2);
}

#[test]
fn test_transaction_pool_get() {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let hash = tx.hash;
    pool.insert(tx);
    let retrieved = pool.get(&hash);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().value, U256::from_u64(100));
}

#[test]
fn test_transaction_pool_get_nonexistent() {
    let pool = TransactionPool::new(100);
    let hash = TxHash([99u8; 32]);
    assert!(pool.get(&hash).is_none());
}

#[test]
fn test_transaction_pool_contains() {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let hash = tx.hash;
    let other_hash = TxHash([99u8; 32]);
    pool.insert(tx);
    assert!(pool.contains(&hash));
    assert!(!pool.contains(&other_hash));
}

#[test]
fn test_transaction_pool_remove() {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let hash = tx.hash;
    pool.insert(tx);
    let removed = pool.remove(&hash);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().value, U256::from_u64(100));
    assert!(pool.is_empty());
}

#[test]
fn test_transaction_pool_remove_nonexistent() {
    let mut pool = TransactionPool::new(100);
    let hash = TxHash([99u8; 32]);
    assert!(pool.remove(&hash).is_none());
}

#[test]
fn test_transaction_pool_get_pending_for() {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let other = Address::from_slice(&[2u8; 20]);
    let tx1 = create_test_tx([1u8; 32], from, 0, 100);
    let tx2 = create_test_tx([2u8; 32], from, 1, 200);
    let tx3 = create_test_tx([3u8; 32], other, 0, 300);
    pool.insert(tx1);
    pool.insert(tx2);
    pool.insert(tx3);
    let pending = pool.get_pending_for(&from);
    assert_eq!(pending.len(), 2);
}

#[test]
fn test_transaction_pool_get_pending_for_empty() {
    let pool = TransactionPool::new(100);
    let addr = Address::from_slice(&[1u8; 20]);
    let pending = pool.get_pending_for(&addr);
    assert!(pending.is_empty());
}

#[test]
fn test_transaction_pool_next_nonce_for() {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx1 = create_test_tx([1u8; 32], from, 5, 100);
    let tx2 = create_test_tx([2u8; 32], from, 7, 200);
    pool.insert(tx1);
    pool.insert(tx2);
    let next_nonce = pool.next_nonce_for(&from, Nonce(3));
    assert_eq!(next_nonce.0, 7);
}

#[test]
fn test_transaction_pool_next_nonce_for_current_higher() {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx = create_test_tx([1u8; 32], from, 2, 100);
    pool.insert(tx);
    let next_nonce = pool.next_nonce_for(&from, Nonce(10));
    assert_eq!(next_nonce.0, 10);
}

#[test]
fn test_transaction_pool_drain_batch() {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    for i in 0..5u8 {
        let mut hash = [0u8; 32];
        hash[0] = i;
        pool.insert(create_test_tx(hash, from, i as u64, (i as u64) * 100));
    }
    assert_eq!(pool.len(), 5);
    let batch = pool.drain_batch(3);
    assert_eq!(batch.len(), 3);
    assert_eq!(pool.len(), 2);
}

#[test]
fn test_transaction_pool_drain_batch_more_than_available() {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    for i in 0..2u8 {
        let mut hash = [0u8; 32];
        hash[0] = i;
        pool.insert(create_test_tx(hash, from, i as u64, (i as u64) * 100));
    }
    let batch = pool.drain_batch(10);
    assert_eq!(batch.len(), 2);
    assert!(pool.is_empty());
}

#[test]
fn test_transaction_executor_new() {
    let mut state = StateManager::new();
    let _executor = TransactionExecutor::new(&mut state);
}

#[test]
fn test_transaction_executor_current_block() {
    let mut state = StateManager::new();
    state.advance_block();
    state.advance_block();
    let executor = TransactionExecutor::new(&mut state);
    assert_eq!(executor.current_block().0, 2);
}

#[test]
fn test_transaction_executor_execute_success() {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    let to = Address::from_slice(&[2u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    let tx = L2Transaction {
        hash: TxHash([1u8; 32]),
        from,
        to: Some(to),
        value: U256::from_u64(100),
        data: alloc::vec![],
        nonce: Nonce(0),
        gas_limit: Gas(21000),
        max_fee_per_gas: U256::from_u64(1000000000),
        max_priority_fee_per_gas: U256::from_u64(1000000),
        signature: TransactionSignature::default(),
    };
    let mut executor = TransactionExecutor::new(&mut state);
    let result = executor.execute(&tx);
    assert!(result.is_ok());
    if let Ok(TransactionStatus::Included { block: _ }) = result {
    } else {
        panic!("Expected Included status");
    }
}

#[test]
fn test_transaction_executor_execute_nonce_too_low() {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    state.increment_nonce(&from);
    state.increment_nonce(&from);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let mut executor = TransactionExecutor::new(&mut state);
    let result = executor.execute(&tx);
    assert!(result.is_ok());
    if let Ok(TransactionStatus::Failed { reason }) = result {
        assert_eq!(reason, TxFailReason::NonceTooLow);
    } else {
        panic!("Expected Failed status with NonceTooLow");
    }
}

#[test]
fn test_transaction_executor_execute_nonce_too_high() {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    let tx = create_test_tx([1u8; 32], from, 5, 100);
    let mut executor = TransactionExecutor::new(&mut state);
    let result = executor.execute(&tx);
    assert!(result.is_ok());
    if let Ok(TransactionStatus::Failed { reason }) = result {
        assert_eq!(reason, TxFailReason::NonceTooHigh);
    } else {
        panic!("Expected Failed status with NonceTooHigh");
    }
}

#[test]
fn test_transaction_executor_execute_insufficient_balance() {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(50));
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let mut executor = TransactionExecutor::new(&mut state);
    let result = executor.execute(&tx);
    assert!(result.is_ok());
    if let Ok(TransactionStatus::Failed { reason }) = result {
        assert_eq!(reason, TxFailReason::InsufficientBalance);
    } else {
        panic!("Expected Failed status with InsufficientBalance");
    }
}

#[test]
fn test_transaction_executor_validate_success() {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let executor = TransactionExecutor::new(&mut state);
    let result = executor.validate(&tx);
    assert!(result.is_ok());
}

#[test]
fn test_transaction_executor_validate_nonce_too_low() {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    state.increment_nonce(&from);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let executor = TransactionExecutor::new(&mut state);
    let result = executor.validate(&tx);
    assert_eq!(result.unwrap_err(), TxFailReason::NonceTooLow);
}

#[test]
fn test_transaction_executor_validate_insufficient_balance() {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(50));
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let executor = TransactionExecutor::new(&mut state);
    let result = executor.validate(&tx);
    assert_eq!(result.unwrap_err(), TxFailReason::InsufficientBalance);
}

#[test]
fn test_transaction_executor_increments_nonce() {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    let to = Address::from_slice(&[2u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    let tx = L2Transaction {
        hash: TxHash([1u8; 32]),
        from,
        to: Some(to),
        value: U256::from_u64(100),
        data: alloc::vec![],
        nonce: Nonce(0),
        gas_limit: Gas(21000),
        max_fee_per_gas: U256::from_u64(1000000000),
        max_priority_fee_per_gas: U256::from_u64(1000000),
        signature: TransactionSignature::default(),
    };
    let mut executor = TransactionExecutor::new(&mut state);
    let _ = executor.execute(&tx);
    assert_eq!(state.get_nonce(&from).0, 1);
}

#[test]
fn test_transaction_executor_transfers_value() {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    let to = Address::from_slice(&[2u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    let tx = L2Transaction {
        hash: TxHash([1u8; 32]),
        from,
        to: Some(to),
        value: U256::from_u64(300),
        data: alloc::vec![],
        nonce: Nonce(0),
        gas_limit: Gas(21000),
        max_fee_per_gas: U256::from_u64(1000000000),
        max_priority_fee_per_gas: U256::from_u64(1000000),
        signature: TransactionSignature::default(),
    };
    let mut executor = TransactionExecutor::new(&mut state);
    let _ = executor.execute(&tx);
    assert_eq!(state.get_balance(&from), U256::from_u64(700));
    assert_eq!(state.get_balance(&to), U256::from_u64(300));
}
