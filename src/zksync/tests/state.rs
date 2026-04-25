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
use crate::zksync::state::*;
use crate::zksync::types::*;

pub(crate) fn test_sparse_merkle_tree_new() -> TestResult {
    let tree = SparseMerkleTree::new();
    if tree.root() == [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sparse_merkle_tree_default() -> TestResult {
    let tree: SparseMerkleTree = Default::default();
    if tree.root() == [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sparse_merkle_tree_insert() -> TestResult {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let value = [2u8; 32];
    tree.insert(key, value);
    if tree.get(&key) != Some(value) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sparse_merkle_tree_get_nonexistent() -> TestResult {
    let tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    if tree.get(&key) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sparse_merkle_tree_remove() -> TestResult {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let value = [2u8; 32];
    tree.insert(key, value);
    let removed = tree.remove(&key);
    if removed != Some(value) {
        return TestResult::Fail;
    }
    if tree.get(&key) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sparse_merkle_tree_remove_nonexistent() -> TestResult {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    if tree.remove(&key) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sparse_merkle_tree_root_changes_on_insert() -> TestResult {
    let mut tree = SparseMerkleTree::new();
    let root_before = tree.root();
    tree.insert([1u8; 32], [2u8; 32]);
    let root_after = tree.root();
    if root_before == root_after {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sparse_merkle_tree_root_changes_on_remove() -> TestResult {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    tree.insert(key, [2u8; 32]);
    let root_with_value = tree.root();
    tree.remove(&key);
    let root_after_remove = tree.root();
    if root_with_value == root_after_remove {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sparse_merkle_tree_proof() -> TestResult {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let value = [2u8; 32];
    tree.insert(key, value);
    let proof = tree.proof(&key);
    if proof.key != key {
        return TestResult::Fail;
    }
    if proof.value != Some(value) {
        return TestResult::Fail;
    }
    if proof.siblings.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sparse_merkle_tree_proof_nonexistent() -> TestResult {
    let tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let proof = tree.proof(&key);
    if proof.key != key {
        return TestResult::Fail;
    }
    if proof.value != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_merkle_proof_verify() -> TestResult {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let value = [2u8; 32];
    tree.insert(key, value);
    let proof = tree.proof(&key);
    let root = tree.root();
    if !proof.verify(&root) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_merkle_proof_verify_wrong_root() -> TestResult {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let value = [2u8; 32];
    tree.insert(key, value);
    let proof = tree.proof(&key);
    let wrong_root = [0xFFu8; 32];
    if proof.verify(&wrong_root) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_new() -> TestResult {
    let manager = StateManager::new();
    if manager.current_block().0 != 0 {
        return TestResult::Fail;
    }
    if manager.current_batch().0 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_default() -> TestResult {
    let manager: StateManager = Default::default();
    if manager.current_block().0 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_get_account_nonexistent() -> TestResult {
    let manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    if manager.get_account(&addr).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_get_balance_nonexistent() -> TestResult {
    let manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    if !manager.get_balance(&addr).is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_get_nonce_nonexistent() -> TestResult {
    let manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    if manager.get_nonce(&addr).0 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_set_balance() -> TestResult {
    let mut manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let balance = U256::from_u64(1000);
    manager.set_balance(addr, balance);
    if manager.get_balance(&addr) != balance {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_increment_nonce() -> TestResult {
    let mut manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    manager.set_balance(addr, U256::ONE);
    manager.increment_nonce(&addr);
    if manager.get_nonce(&addr).0 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_increment_nonce_nonexistent() -> TestResult {
    let mut manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    manager.increment_nonce(&addr);
    if manager.get_nonce(&addr).0 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_transfer() -> TestResult {
    let mut manager = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    let to = Address::from_slice(&[2u8; 20]);
    manager.set_balance(from, U256::from_u64(1000));
    let result = manager.transfer(&from, &to, U256::from_u64(300));
    if result.is_err() {
        return TestResult::Fail;
    }
    if manager.get_balance(&from) != U256::from_u64(700) {
        return TestResult::Fail;
    }
    if manager.get_balance(&to) != U256::from_u64(300) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_transfer_insufficient_balance() -> TestResult {
    let mut manager = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    let to = Address::from_slice(&[2u8; 20]);
    manager.set_balance(from, U256::from_u64(100));
    let result = manager.transfer(&from, &to, U256::from_u64(200));
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_state_root_changes() -> TestResult {
    let mut manager = StateManager::new();
    let root_before = manager.state_root();
    let addr = Address::from_slice(&[1u8; 20]);
    manager.set_balance(addr, U256::from_u64(1000));
    let root_after = manager.state_root();
    if root_before == root_after {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_advance_block() -> TestResult {
    let mut manager = StateManager::new();
    if manager.current_block().0 != 0 {
        return TestResult::Fail;
    }
    manager.advance_block();
    if manager.current_block().0 != 1 {
        return TestResult::Fail;
    }
    manager.advance_block();
    if manager.current_block().0 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_manager_advance_batch() -> TestResult {
    let mut manager = StateManager::new();
    if manager.current_batch().0 != 0 {
        return TestResult::Fail;
    }
    manager.advance_batch();
    if manager.current_batch().0 != 1 {
        return TestResult::Fail;
    }
    manager.advance_batch();
    if manager.current_batch().0 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_storage_new() -> TestResult {
    let storage = AccountStorage::new();
    if !storage.is_empty() {
        return TestResult::Fail;
    }
    if storage.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_storage_default() -> TestResult {
    let storage: AccountStorage = Default::default();
    if !storage.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_storage_get_nonexistent() -> TestResult {
    let storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    if storage.get(&addr).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_storage_exists() -> TestResult {
    let mut storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    if storage.exists(&addr) {
        return TestResult::Fail;
    }
    storage.get_or_create(addr);
    if !storage.exists(&addr) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_storage_get_or_create() -> TestResult {
    let mut storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let account = storage.get_or_create(addr);
    if account.nonce.0 != 0 {
        return TestResult::Fail;
    }
    if !account.balance.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_storage_balance() -> TestResult {
    let mut storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    if !storage.balance(&addr).is_zero() {
        return TestResult::Fail;
    }
    storage.set_balance(addr, U256::from_u64(500));
    if storage.balance(&addr) != U256::from_u64(500) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_storage_nonce() -> TestResult {
    let mut storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    if storage.nonce(&addr).0 != 0 {
        return TestResult::Fail;
    }
    storage.set_nonce(addr, Nonce(5));
    if storage.nonce(&addr).0 != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_storage_increment_nonce() -> TestResult {
    let mut storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    storage.set_nonce(addr, Nonce(0));
    storage.increment_nonce(&addr);
    if storage.nonce(&addr).0 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_storage_len() -> TestResult {
    let mut storage = AccountStorage::new();
    if storage.len() != 0 {
        return TestResult::Fail;
    }
    storage.get_or_create(Address::from_slice(&[1u8; 20]));
    if storage.len() != 1 {
        return TestResult::Fail;
    }
    storage.get_or_create(Address::from_slice(&[2u8; 20]));
    if storage.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_account_storage_iter() -> TestResult {
    let mut storage = AccountStorage::new();
    let addr1 = Address::from_slice(&[1u8; 20]);
    let addr2 = Address::from_slice(&[2u8; 20]);
    storage.set_balance(addr1, U256::from_u64(100));
    storage.set_balance(addr2, U256::from_u64(200));
    let count = storage.iter().count();
    if count != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contract_storage_new() -> TestResult {
    let storage = ContractStorage::new();
    if !storage.is_empty() {
        return TestResult::Fail;
    }
    if storage.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contract_storage_default() -> TestResult {
    let storage: ContractStorage = Default::default();
    if !storage.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contract_storage_get_nonexistent() -> TestResult {
    let storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let slot = U256::from_u64(0);
    if !storage.get(&addr, &slot).is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contract_storage_set_get() -> TestResult {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let slot = U256::from_u64(0);
    let value = U256::from_u64(12345);
    storage.set(addr, slot, value);
    if storage.get(&addr, &slot) != value {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contract_storage_set_zero_removes() -> TestResult {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let slot = U256::from_u64(0);
    storage.set(addr, slot, U256::from_u64(100));
    if storage.len() != 1 {
        return TestResult::Fail;
    }
    storage.set(addr, slot, U256::ZERO);
    if storage.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contract_storage_remove() -> TestResult {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let slot = U256::from_u64(0);
    storage.set(addr, slot, U256::from_u64(100));
    let removed = storage.remove(&addr, &slot);
    if removed != Some(U256::from_u64(100)) {
        return TestResult::Fail;
    }
    if !storage.get(&addr, &slot).is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contract_storage_remove_nonexistent() -> TestResult {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let slot = U256::from_u64(0);
    if storage.remove(&addr, &slot).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contract_storage_clear_account() -> TestResult {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    storage.set(addr, U256::from_u64(0), U256::from_u64(1));
    storage.set(addr, U256::from_u64(1), U256::from_u64(2));
    storage.set(addr, U256::from_u64(2), U256::from_u64(3));
    if storage.len() != 3 {
        return TestResult::Fail;
    }
    storage.clear_account(&addr);
    if storage.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contract_storage_iter_account() -> TestResult {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    storage.set(addr, U256::from_u64(0), U256::from_u64(10));
    storage.set(addr, U256::from_u64(1), U256::from_u64(20));
    let count = storage.iter_account(&addr).count();
    if count != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contract_storage_multiple_accounts() -> TestResult {
    let mut storage = ContractStorage::new();
    let addr1 = Address::from_slice(&[1u8; 20]);
    let addr2 = Address::from_slice(&[2u8; 20]);
    storage.set(addr1, U256::from_u64(0), U256::from_u64(100));
    storage.set(addr2, U256::from_u64(0), U256::from_u64(200));
    if storage.get(&addr1, &U256::from_u64(0)) != U256::from_u64(100) {
        return TestResult::Fail;
    }
    if storage.get(&addr2, &U256::from_u64(0)) != U256::from_u64(200) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
