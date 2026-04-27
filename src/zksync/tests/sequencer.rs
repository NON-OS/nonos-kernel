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

pub(crate) fn test_transaction_pool_new() -> TestResult {
    let pool = TransactionPool::new(100);
    if !pool.is_empty() {
        return TestResult::Fail;
    }
    if pool.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_default() -> TestResult {
    let pool: TransactionPool = Default::default();
    if !pool.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_insert() -> TestResult {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    if !pool.insert(tx) {
        return TestResult::Fail;
    }
    if pool.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_insert_duplicate() -> TestResult {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx1 = create_test_tx([1u8; 32], from, 0, 100);
    let tx2 = create_test_tx([1u8; 32], from, 0, 100);
    if !pool.insert(tx1) {
        return TestResult::Fail;
    }
    if pool.insert(tx2) {
        return TestResult::Fail;
    }
    if pool.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_insert_full() -> TestResult {
    let mut pool = TransactionPool::new(2);
    let from = Address::from_slice(&[1u8; 20]);
    let tx1 = create_test_tx([1u8; 32], from, 0, 100);
    let tx2 = create_test_tx([2u8; 32], from, 1, 200);
    let tx3 = create_test_tx([3u8; 32], from, 2, 300);
    if !pool.insert(tx1) {
        return TestResult::Fail;
    }
    if !pool.insert(tx2) {
        return TestResult::Fail;
    }
    if pool.insert(tx3) {
        return TestResult::Fail;
    }
    if pool.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_get() -> TestResult {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let hash = tx.hash;
    pool.insert(tx);
    let retrieved = pool.get(&hash);
    if retrieved.is_none() {
        return TestResult::Fail;
    }
    if retrieved.unwrap().value != U256::from_u64(100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_get_nonexistent() -> TestResult {
    let pool = TransactionPool::new(100);
    let hash = TxHash([99u8; 32]);
    if pool.get(&hash).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_contains() -> TestResult {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let hash = tx.hash;
    let other_hash = TxHash([99u8; 32]);
    pool.insert(tx);
    if !pool.contains(&hash) {
        return TestResult::Fail;
    }
    if pool.contains(&other_hash) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_remove() -> TestResult {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let hash = tx.hash;
    pool.insert(tx);
    let removed = pool.remove(&hash);
    if removed.is_none() {
        return TestResult::Fail;
    }
    if removed.unwrap().value != U256::from_u64(100) {
        return TestResult::Fail;
    }
    if !pool.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_remove_nonexistent() -> TestResult {
    let mut pool = TransactionPool::new(100);
    let hash = TxHash([99u8; 32]);
    if pool.remove(&hash).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_get_pending_for() -> TestResult {
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
    if pending.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_get_pending_for_empty() -> TestResult {
    let pool = TransactionPool::new(100);
    let addr = Address::from_slice(&[1u8; 20]);
    let pending = pool.get_pending_for(&addr);
    if !pending.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_next_nonce_for() -> TestResult {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx1 = create_test_tx([1u8; 32], from, 5, 100);
    let tx2 = create_test_tx([2u8; 32], from, 7, 200);
    pool.insert(tx1);
    pool.insert(tx2);
    let next_nonce = pool.next_nonce_for(&from, Nonce(3));
    if next_nonce.0 != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_next_nonce_for_current_higher() -> TestResult {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    let tx = create_test_tx([1u8; 32], from, 2, 100);
    pool.insert(tx);
    let next_nonce = pool.next_nonce_for(&from, Nonce(10));
    if next_nonce.0 != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_drain_batch() -> TestResult {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    for i in 0..5u8 {
        let mut hash = [0u8; 32];
        hash[0] = i;
        pool.insert(create_test_tx(hash, from, i as u64, (i as u64) * 100));
    }
    if pool.len() != 5 {
        return TestResult::Fail;
    }
    let batch = pool.drain_batch(3);
    if batch.len() != 3 {
        return TestResult::Fail;
    }
    if pool.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_pool_drain_batch_more_than_available() -> TestResult {
    let mut pool = TransactionPool::new(100);
    let from = Address::from_slice(&[1u8; 20]);
    for i in 0..2u8 {
        let mut hash = [0u8; 32];
        hash[0] = i;
        pool.insert(create_test_tx(hash, from, i as u64, (i as u64) * 100));
    }
    let batch = pool.drain_batch(10);
    if batch.len() != 2 {
        return TestResult::Fail;
    }
    if !pool.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_executor_new() -> TestResult {
    let mut state = StateManager::new();
    let _executor = TransactionExecutor::new(&mut state);
    TestResult::Pass
}

pub(crate) fn test_transaction_executor_current_block() -> TestResult {
    let mut state = StateManager::new();
    state.advance_block();
    state.advance_block();
    let executor = TransactionExecutor::new(&mut state);
    if executor.current_block().0 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_executor_execute_success() -> TestResult {
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
    if result.is_err() {
        return TestResult::Fail;
    }
    if let Ok(TransactionStatus::Included { block: _ }) = result {
        TestResult::Pass
    } else {
        TestResult::Fail
    }
}

pub(crate) fn test_transaction_executor_execute_nonce_too_low() -> TestResult {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    state.increment_nonce(&from);
    state.increment_nonce(&from);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let mut executor = TransactionExecutor::new(&mut state);
    let result = executor.execute(&tx);
    if result.is_err() {
        return TestResult::Fail;
    }
    if let Ok(TransactionStatus::Failed { reason }) = result {
        if reason != TxFailReason::NonceTooLow {
            return TestResult::Fail;
        }
        TestResult::Pass
    } else {
        TestResult::Fail
    }
}

pub(crate) fn test_transaction_executor_execute_nonce_too_high() -> TestResult {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    let tx = create_test_tx([1u8; 32], from, 5, 100);
    let mut executor = TransactionExecutor::new(&mut state);
    let result = executor.execute(&tx);
    if result.is_err() {
        return TestResult::Fail;
    }
    if let Ok(TransactionStatus::Failed { reason }) = result {
        if reason != TxFailReason::NonceTooHigh {
            return TestResult::Fail;
        }
        TestResult::Pass
    } else {
        TestResult::Fail
    }
}

pub(crate) fn test_transaction_executor_execute_insufficient_balance() -> TestResult {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(50));
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let mut executor = TransactionExecutor::new(&mut state);
    let result = executor.execute(&tx);
    if result.is_err() {
        return TestResult::Fail;
    }
    if let Ok(TransactionStatus::Failed { reason }) = result {
        if reason != TxFailReason::InsufficientBalance {
            return TestResult::Fail;
        }
        TestResult::Pass
    } else {
        TestResult::Fail
    }
}

pub(crate) fn test_transaction_executor_validate_success() -> TestResult {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let executor = TransactionExecutor::new(&mut state);
    let result = executor.validate(&tx);
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_executor_validate_nonce_too_low() -> TestResult {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(1000));
    state.increment_nonce(&from);
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let executor = TransactionExecutor::new(&mut state);
    let result = executor.validate(&tx);
    if result.unwrap_err() != TxFailReason::NonceTooLow {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_executor_validate_insufficient_balance() -> TestResult {
    let mut state = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    state.set_balance(from, U256::from_u64(50));
    let tx = create_test_tx([1u8; 32], from, 0, 100);
    let executor = TransactionExecutor::new(&mut state);
    let result = executor.validate(&tx);
    if result.unwrap_err() != TxFailReason::InsufficientBalance {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_executor_increments_nonce() -> TestResult {
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
    if state.get_nonce(&from).0 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transaction_executor_transfers_value() -> TestResult {
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
    if state.get_balance(&from) != U256::from_u64(700) {
        return TestResult::Fail;
    }
    if state.get_balance(&to) != U256::from_u64(300) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
