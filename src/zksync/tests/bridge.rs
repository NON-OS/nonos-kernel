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

use crate::zksync::bridge::*;
use crate::zksync::state::StateManager;
use crate::zksync::types::*;

#[test]
fn test_deposit_handler_new() {
    let handler = DepositHandler::new();
    assert!(handler.is_empty());
    assert_eq!(handler.pending_count(), 0);
}

#[test]
fn test_deposit_handler_default() {
    let handler: DepositHandler = Default::default();
    assert!(handler.is_empty());
}

#[test]
fn test_deposit_handler_queue() {
    let mut handler = DepositHandler::new();
    let deposit = Deposit {
        l1_tx_hash: [1u8; 32],
        recipient: Address::from_slice(&[2u8; 20]),
        amount: U256::from_u64(1000),
        l1_block: 100,
    };
    handler.queue(deposit);
    assert_eq!(handler.pending_count(), 1);
    assert!(!handler.is_empty());
}

#[test]
fn test_deposit_handler_queue_multiple() {
    let mut handler = DepositHandler::new();
    for i in 0..5u8 {
        let mut hash = [0u8; 32];
        hash[0] = i;
        let deposit = Deposit {
            l1_tx_hash: hash,
            recipient: Address::from_slice(&[i; 20]),
            amount: U256::from_u64((i as u64) * 100),
            l1_block: i as u64,
        };
        handler.queue(deposit);
    }
    assert_eq!(handler.pending_count(), 5);
}

#[test]
fn test_deposit_handler_process_next_empty() {
    let mut handler = DepositHandler::new();
    let mut state = StateManager::new();
    let result = handler.process_next(&mut state);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn test_deposit_handler_process_next() {
    let mut handler = DepositHandler::new();
    let mut state = StateManager::new();
    let recipient = Address::from_slice(&[1u8; 20]);
    let deposit = Deposit {
        l1_tx_hash: [0xAB; 32],
        recipient,
        amount: U256::from_u64(500),
        l1_block: 10,
    };
    handler.queue(deposit);
    let result = handler.process_next(&mut state);
    assert!(result.is_ok());
    let processed = result.unwrap();
    assert!(processed.is_some());
    assert_eq!(state.get_balance(&recipient), U256::from_u64(500));
}

#[test]
fn test_deposit_handler_process_next_fifo() {
    let mut handler = DepositHandler::new();
    let mut state = StateManager::new();
    let recipient1 = Address::from_slice(&[1u8; 20]);
    let recipient2 = Address::from_slice(&[2u8; 20]);
    handler.queue(Deposit {
        l1_tx_hash: [1u8; 32],
        recipient: recipient1,
        amount: U256::from_u64(100),
        l1_block: 1,
    });
    handler.queue(Deposit {
        l1_tx_hash: [2u8; 32],
        recipient: recipient2,
        amount: U256::from_u64(200),
        l1_block: 2,
    });
    let first = handler.process_next(&mut state).unwrap().unwrap();
    assert_eq!(first.l1_tx_hash, [1u8; 32]);
    let second = handler.process_next(&mut state).unwrap().unwrap();
    assert_eq!(second.l1_tx_hash, [2u8; 32]);
}

#[test]
fn test_deposit_handler_process_accumulates_balance() {
    let mut handler = DepositHandler::new();
    let mut state = StateManager::new();
    let recipient = Address::from_slice(&[1u8; 20]);
    handler.queue(Deposit {
        l1_tx_hash: [1u8; 32],
        recipient,
        amount: U256::from_u64(100),
        l1_block: 1,
    });
    handler.queue(Deposit {
        l1_tx_hash: [2u8; 32],
        recipient,
        amount: U256::from_u64(200),
        l1_block: 2,
    });
    let _ = handler.process_next(&mut state);
    let _ = handler.process_next(&mut state);
    assert_eq!(state.get_balance(&recipient), U256::from_u64(300));
}

#[test]
fn test_deposit_clone() {
    let deposit = Deposit {
        l1_tx_hash: [0xAB; 32],
        recipient: Address::from_slice(&[0xCD; 20]),
        amount: U256::from_u64(1234),
        l1_block: 567,
    };
    let cloned = deposit.clone();
    assert_eq!(deposit.l1_tx_hash, cloned.l1_tx_hash);
    assert_eq!(deposit.recipient, cloned.recipient);
    assert_eq!(deposit.amount, cloned.amount);
    assert_eq!(deposit.l1_block, cloned.l1_block);
}

#[test]
fn test_deposit_debug() {
    let deposit = Deposit {
        l1_tx_hash: [0u8; 32],
        recipient: Address::ZERO,
        amount: U256::ZERO,
        l1_block: 0,
    };
    let debug = alloc::format!("{:?}", deposit);
    assert!(debug.contains("Deposit"));
}

#[test]
fn test_withdraw_handler_new() {
    let handler = WithdrawHandler::new();
    assert_eq!(handler.pending_count(), 0);
    assert_eq!(handler.finalized_count(), 0);
}

#[test]
fn test_withdraw_handler_default() {
    let handler: WithdrawHandler = Default::default();
    assert_eq!(handler.pending_count(), 0);
}

#[test]
fn test_withdraw_handler_initiate() {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let result = handler.initiate(&mut state, sender, recipient, U256::from_u64(300));
    assert!(result.is_ok());
    assert_eq!(handler.pending_count(), 1);
    assert_eq!(state.get_balance(&sender), U256::from_u64(700));
}

#[test]
fn test_withdraw_handler_initiate_insufficient_balance() {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(100));
    let result = handler.initiate(&mut state, sender, recipient, U256::from_u64(500));
    assert!(result.is_err());
    assert_eq!(handler.pending_count(), 0);
}

#[test]
fn test_withdraw_handler_initiate_returns_hash() {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let hash = handler.initiate(&mut state, sender, recipient, U256::from_u64(300)).unwrap();
    assert_ne!(hash, [0u8; 32]);
}

#[test]
fn test_withdraw_handler_initiate_multiple() {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    assert_eq!(handler.pending_count(), 3);
    assert_eq!(state.get_balance(&sender), U256::from_u64(700));
}

#[test]
fn test_withdraw_handler_finalize_batch() {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    assert_eq!(handler.pending_count(), 1);
    assert_eq!(handler.finalized_count(), 0);
    handler.finalize_batch(BatchNumber(0));
    assert_eq!(handler.pending_count(), 0);
    assert_eq!(handler.finalized_count(), 1);
}

#[test]
fn test_withdraw_handler_finalize_batch_partial() {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    state.advance_batch();
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    state.advance_batch();
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    assert_eq!(handler.pending_count(), 3);
    handler.finalize_batch(BatchNumber(1));
    assert_eq!(handler.pending_count(), 1);
    assert_eq!(handler.finalized_count(), 2);
}

#[test]
fn test_withdraw_handler_finalize_batch_none() {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    state.advance_batch();
    state.advance_batch();
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    handler.finalize_batch(BatchNumber(0));
    assert_eq!(handler.pending_count(), 1);
    assert_eq!(handler.finalized_count(), 0);
}

#[test]
fn test_withdraw_handler_different_hashes() {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient1 = Address::from_slice(&[2u8; 20]);
    let recipient2 = Address::from_slice(&[3u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let hash1 = handler.initiate(&mut state, sender, recipient1, U256::from_u64(100)).unwrap();
    let hash2 = handler.initiate(&mut state, sender, recipient2, U256::from_u64(100)).unwrap();
    assert_ne!(hash1, hash2);
}
