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

use crate::zksync::state::*;
use crate::zksync::types::*;

#[test]
fn test_sparse_merkle_tree_new() {
    let tree = SparseMerkleTree::new();
    assert_ne!(tree.root(), [0u8; 32]);
}

#[test]
fn test_sparse_merkle_tree_default() {
    let tree: SparseMerkleTree = Default::default();
    assert_ne!(tree.root(), [0u8; 32]);
}

#[test]
fn test_sparse_merkle_tree_insert() {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let value = [2u8; 32];
    tree.insert(key, value);
    assert_eq!(tree.get(&key), Some(value));
}

#[test]
fn test_sparse_merkle_tree_get_nonexistent() {
    let tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    assert_eq!(tree.get(&key), None);
}

#[test]
fn test_sparse_merkle_tree_remove() {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let value = [2u8; 32];
    tree.insert(key, value);
    let removed = tree.remove(&key);
    assert_eq!(removed, Some(value));
    assert_eq!(tree.get(&key), None);
}

#[test]
fn test_sparse_merkle_tree_remove_nonexistent() {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    assert_eq!(tree.remove(&key), None);
}

#[test]
fn test_sparse_merkle_tree_root_changes_on_insert() {
    let mut tree = SparseMerkleTree::new();
    let root_before = tree.root();
    tree.insert([1u8; 32], [2u8; 32]);
    let root_after = tree.root();
    assert_ne!(root_before, root_after);
}

#[test]
fn test_sparse_merkle_tree_root_changes_on_remove() {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    tree.insert(key, [2u8; 32]);
    let root_with_value = tree.root();
    tree.remove(&key);
    let root_after_remove = tree.root();
    assert_ne!(root_with_value, root_after_remove);
}

#[test]
fn test_sparse_merkle_tree_proof() {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let value = [2u8; 32];
    tree.insert(key, value);
    let proof = tree.proof(&key);
    assert_eq!(proof.key, key);
    assert_eq!(proof.value, Some(value));
    assert!(!proof.siblings.is_empty());
}

#[test]
fn test_sparse_merkle_tree_proof_nonexistent() {
    let tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let proof = tree.proof(&key);
    assert_eq!(proof.key, key);
    assert_eq!(proof.value, None);
}

#[test]
fn test_merkle_proof_verify() {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let value = [2u8; 32];
    tree.insert(key, value);
    let proof = tree.proof(&key);
    let root = tree.root();
    assert!(proof.verify(&root));
}

#[test]
fn test_merkle_proof_verify_wrong_root() {
    let mut tree = SparseMerkleTree::new();
    let key = [1u8; 32];
    let value = [2u8; 32];
    tree.insert(key, value);
    let proof = tree.proof(&key);
    let wrong_root = [0xFFu8; 32];
    assert!(!proof.verify(&wrong_root));
}

#[test]
fn test_state_manager_new() {
    let manager = StateManager::new();
    assert_eq!(manager.current_block().0, 0);
    assert_eq!(manager.current_batch().0, 0);
}

#[test]
fn test_state_manager_default() {
    let manager: StateManager = Default::default();
    assert_eq!(manager.current_block().0, 0);
}

#[test]
fn test_state_manager_get_account_nonexistent() {
    let manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    assert!(manager.get_account(&addr).is_none());
}

#[test]
fn test_state_manager_get_balance_nonexistent() {
    let manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    assert!(manager.get_balance(&addr).is_zero());
}

#[test]
fn test_state_manager_get_nonce_nonexistent() {
    let manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    assert_eq!(manager.get_nonce(&addr).0, 0);
}

#[test]
fn test_state_manager_set_balance() {
    let mut manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let balance = U256::from_u64(1000);
    manager.set_balance(addr, balance);
    assert_eq!(manager.get_balance(&addr), balance);
}

#[test]
fn test_state_manager_increment_nonce() {
    let mut manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    manager.set_balance(addr, U256::ONE);
    manager.increment_nonce(&addr);
    assert_eq!(manager.get_nonce(&addr).0, 1);
}

#[test]
fn test_state_manager_increment_nonce_nonexistent() {
    let mut manager = StateManager::new();
    let addr = Address::from_slice(&[1u8; 20]);
    manager.increment_nonce(&addr);
    assert_eq!(manager.get_nonce(&addr).0, 0);
}

#[test]
fn test_state_manager_transfer() {
    let mut manager = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    let to = Address::from_slice(&[2u8; 20]);
    manager.set_balance(from, U256::from_u64(1000));
    let result = manager.transfer(&from, &to, U256::from_u64(300));
    assert!(result.is_ok());
    assert_eq!(manager.get_balance(&from), U256::from_u64(700));
    assert_eq!(manager.get_balance(&to), U256::from_u64(300));
}

#[test]
fn test_state_manager_transfer_insufficient_balance() {
    let mut manager = StateManager::new();
    let from = Address::from_slice(&[1u8; 20]);
    let to = Address::from_slice(&[2u8; 20]);
    manager.set_balance(from, U256::from_u64(100));
    let result = manager.transfer(&from, &to, U256::from_u64(200));
    assert!(result.is_err());
}

#[test]
fn test_state_manager_state_root_changes() {
    let mut manager = StateManager::new();
    let root_before = manager.state_root();
    let addr = Address::from_slice(&[1u8; 20]);
    manager.set_balance(addr, U256::from_u64(1000));
    let root_after = manager.state_root();
    assert_ne!(root_before, root_after);
}

#[test]
fn test_state_manager_advance_block() {
    let mut manager = StateManager::new();
    assert_eq!(manager.current_block().0, 0);
    manager.advance_block();
    assert_eq!(manager.current_block().0, 1);
    manager.advance_block();
    assert_eq!(manager.current_block().0, 2);
}

#[test]
fn test_state_manager_advance_batch() {
    let mut manager = StateManager::new();
    assert_eq!(manager.current_batch().0, 0);
    manager.advance_batch();
    assert_eq!(manager.current_batch().0, 1);
    manager.advance_batch();
    assert_eq!(manager.current_batch().0, 2);
}

#[test]
fn test_account_storage_new() {
    let storage = AccountStorage::new();
    assert!(storage.is_empty());
    assert_eq!(storage.len(), 0);
}

#[test]
fn test_account_storage_default() {
    let storage: AccountStorage = Default::default();
    assert!(storage.is_empty());
}

#[test]
fn test_account_storage_get_nonexistent() {
    let storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    assert!(storage.get(&addr).is_none());
}

#[test]
fn test_account_storage_exists() {
    let mut storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    assert!(!storage.exists(&addr));
    storage.get_or_create(addr);
    assert!(storage.exists(&addr));
}

#[test]
fn test_account_storage_get_or_create() {
    let mut storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let account = storage.get_or_create(addr);
    assert_eq!(account.nonce.0, 0);
    assert!(account.balance.is_zero());
}

#[test]
fn test_account_storage_balance() {
    let mut storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    assert!(storage.balance(&addr).is_zero());
    storage.set_balance(addr, U256::from_u64(500));
    assert_eq!(storage.balance(&addr), U256::from_u64(500));
}

#[test]
fn test_account_storage_nonce() {
    let mut storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    assert_eq!(storage.nonce(&addr).0, 0);
    storage.set_nonce(addr, Nonce(5));
    assert_eq!(storage.nonce(&addr).0, 5);
}

#[test]
fn test_account_storage_increment_nonce() {
    let mut storage = AccountStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    storage.set_nonce(addr, Nonce(0));
    storage.increment_nonce(&addr);
    assert_eq!(storage.nonce(&addr).0, 1);
}

#[test]
fn test_account_storage_len() {
    let mut storage = AccountStorage::new();
    assert_eq!(storage.len(), 0);
    storage.get_or_create(Address::from_slice(&[1u8; 20]));
    assert_eq!(storage.len(), 1);
    storage.get_or_create(Address::from_slice(&[2u8; 20]));
    assert_eq!(storage.len(), 2);
}

#[test]
fn test_account_storage_iter() {
    let mut storage = AccountStorage::new();
    let addr1 = Address::from_slice(&[1u8; 20]);
    let addr2 = Address::from_slice(&[2u8; 20]);
    storage.set_balance(addr1, U256::from_u64(100));
    storage.set_balance(addr2, U256::from_u64(200));
    let count = storage.iter().count();
    assert_eq!(count, 2);
}

#[test]
fn test_contract_storage_new() {
    let storage = ContractStorage::new();
    assert!(storage.is_empty());
    assert_eq!(storage.len(), 0);
}

#[test]
fn test_contract_storage_default() {
    let storage: ContractStorage = Default::default();
    assert!(storage.is_empty());
}

#[test]
fn test_contract_storage_get_nonexistent() {
    let storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let slot = U256::from_u64(0);
    assert!(storage.get(&addr, &slot).is_zero());
}

#[test]
fn test_contract_storage_set_get() {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let slot = U256::from_u64(0);
    let value = U256::from_u64(12345);
    storage.set(addr, slot, value);
    assert_eq!(storage.get(&addr, &slot), value);
}

#[test]
fn test_contract_storage_set_zero_removes() {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let slot = U256::from_u64(0);
    storage.set(addr, slot, U256::from_u64(100));
    assert_eq!(storage.len(), 1);
    storage.set(addr, slot, U256::ZERO);
    assert_eq!(storage.len(), 0);
}

#[test]
fn test_contract_storage_remove() {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let slot = U256::from_u64(0);
    storage.set(addr, slot, U256::from_u64(100));
    let removed = storage.remove(&addr, &slot);
    assert_eq!(removed, Some(U256::from_u64(100)));
    assert!(storage.get(&addr, &slot).is_zero());
}

#[test]
fn test_contract_storage_remove_nonexistent() {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    let slot = U256::from_u64(0);
    assert!(storage.remove(&addr, &slot).is_none());
}

#[test]
fn test_contract_storage_clear_account() {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    storage.set(addr, U256::from_u64(0), U256::from_u64(1));
    storage.set(addr, U256::from_u64(1), U256::from_u64(2));
    storage.set(addr, U256::from_u64(2), U256::from_u64(3));
    assert_eq!(storage.len(), 3);
    storage.clear_account(&addr);
    assert_eq!(storage.len(), 0);
}

#[test]
fn test_contract_storage_iter_account() {
    let mut storage = ContractStorage::new();
    let addr = Address::from_slice(&[1u8; 20]);
    storage.set(addr, U256::from_u64(0), U256::from_u64(10));
    storage.set(addr, U256::from_u64(1), U256::from_u64(20));
    let count = storage.iter_account(&addr).count();
    assert_eq!(count, 2);
}

#[test]
fn test_contract_storage_multiple_accounts() {
    let mut storage = ContractStorage::new();
    let addr1 = Address::from_slice(&[1u8; 20]);
    let addr2 = Address::from_slice(&[2u8; 20]);
    storage.set(addr1, U256::from_u64(0), U256::from_u64(100));
    storage.set(addr2, U256::from_u64(0), U256::from_u64(200));
    assert_eq!(storage.get(&addr1, &U256::from_u64(0)), U256::from_u64(100));
    assert_eq!(storage.get(&addr2, &U256::from_u64(0)), U256::from_u64(200));
}
