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
use crate::zksync::bridge::*;
use crate::zksync::state::StateManager;
use crate::zksync::types::*;

pub(crate) fn test_deposit_handler_new() -> TestResult {
    let handler = DepositHandler::new();
    if !handler.is_empty() {
        return TestResult::Fail;
    }
    if handler.pending_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deposit_handler_default() -> TestResult {
    let handler: DepositHandler = Default::default();
    if !handler.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deposit_handler_queue() -> TestResult {
    let mut handler = DepositHandler::new();
    let deposit = Deposit {
        l1_tx_hash: [1u8; 32],
        recipient: Address::from_slice(&[2u8; 20]),
        amount: U256::from_u64(1000),
        l1_block: 100,
    };
    handler.queue(deposit);
    if handler.pending_count() != 1 {
        return TestResult::Fail;
    }
    if handler.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deposit_handler_queue_multiple() -> TestResult {
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
    if handler.pending_count() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deposit_handler_process_next_empty() -> TestResult {
    let mut handler = DepositHandler::new();
    let mut state = StateManager::new();
    let result = handler.process_next(&mut state);
    if result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deposit_handler_process_next() -> TestResult {
    let mut handler = DepositHandler::new();
    let mut state = StateManager::new();
    let recipient = Address::from_slice(&[1u8; 20]);
    let deposit =
        Deposit { l1_tx_hash: [0xAB; 32], recipient, amount: U256::from_u64(500), l1_block: 10 };
    handler.queue(deposit);
    let result = handler.process_next(&mut state);
    if result.is_err() {
        return TestResult::Fail;
    }
    let processed = result.unwrap();
    if processed.is_none() {
        return TestResult::Fail;
    }
    if state.get_balance(&recipient) != U256::from_u64(500) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deposit_handler_process_next_fifo() -> TestResult {
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
    if first.l1_tx_hash != [1u8; 32] {
        return TestResult::Fail;
    }
    let second = handler.process_next(&mut state).unwrap().unwrap();
    if second.l1_tx_hash != [2u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deposit_handler_process_accumulates_balance() -> TestResult {
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
    if state.get_balance(&recipient) != U256::from_u64(300) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deposit_clone() -> TestResult {
    let deposit = Deposit {
        l1_tx_hash: [0xAB; 32],
        recipient: Address::from_slice(&[0xCD; 20]),
        amount: U256::from_u64(1234),
        l1_block: 567,
    };
    let cloned = deposit.clone();
    if deposit.l1_tx_hash != cloned.l1_tx_hash {
        return TestResult::Fail;
    }
    if deposit.recipient != cloned.recipient {
        return TestResult::Fail;
    }
    if deposit.amount != cloned.amount {
        return TestResult::Fail;
    }
    if deposit.l1_block != cloned.l1_block {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deposit_debug() -> TestResult {
    let deposit = Deposit {
        l1_tx_hash: [0u8; 32],
        recipient: Address::ZERO,
        amount: U256::ZERO,
        l1_block: 0,
    };
    let debug = alloc::format!("{:?}", deposit);
    if !debug.contains("Deposit") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_withdraw_handler_new() -> TestResult {
    let handler = WithdrawHandler::new();
    if handler.pending_count() != 0 {
        return TestResult::Fail;
    }
    if handler.finalized_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_withdraw_handler_default() -> TestResult {
    let handler: WithdrawHandler = Default::default();
    if handler.pending_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_withdraw_handler_initiate() -> TestResult {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let result = handler.initiate(&mut state, sender, recipient, U256::from_u64(300));
    if result.is_err() {
        return TestResult::Fail;
    }
    if handler.pending_count() != 1 {
        return TestResult::Fail;
    }
    if state.get_balance(&sender) != U256::from_u64(700) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_withdraw_handler_initiate_insufficient_balance() -> TestResult {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(100));
    let result = handler.initiate(&mut state, sender, recipient, U256::from_u64(500));
    if result.is_ok() {
        return TestResult::Fail;
    }
    if handler.pending_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_withdraw_handler_initiate_returns_hash() -> TestResult {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let hash = handler.initiate(&mut state, sender, recipient, U256::from_u64(300)).unwrap();
    if hash == [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_withdraw_handler_initiate_multiple() -> TestResult {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    if handler.pending_count() != 3 {
        return TestResult::Fail;
    }
    if state.get_balance(&sender) != U256::from_u64(700) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_withdraw_handler_finalize_batch() -> TestResult {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    if handler.pending_count() != 1 {
        return TestResult::Fail;
    }
    if handler.finalized_count() != 0 {
        return TestResult::Fail;
    }
    handler.finalize_batch(BatchNumber(0));
    if handler.pending_count() != 0 {
        return TestResult::Fail;
    }
    if handler.finalized_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_withdraw_handler_finalize_batch_partial() -> TestResult {
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
    if handler.pending_count() != 3 {
        return TestResult::Fail;
    }
    handler.finalize_batch(BatchNumber(1));
    if handler.pending_count() != 1 {
        return TestResult::Fail;
    }
    if handler.finalized_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_withdraw_handler_finalize_batch_none() -> TestResult {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient = Address::from_slice(&[2u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    state.advance_batch();
    state.advance_batch();
    let _ = handler.initiate(&mut state, sender, recipient, U256::from_u64(100));
    handler.finalize_batch(BatchNumber(0));
    if handler.pending_count() != 1 {
        return TestResult::Fail;
    }
    if handler.finalized_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_withdraw_handler_different_hashes() -> TestResult {
    let mut handler = WithdrawHandler::new();
    let mut state = StateManager::new();
    let sender = Address::from_slice(&[1u8; 20]);
    let recipient1 = Address::from_slice(&[2u8; 20]);
    let recipient2 = Address::from_slice(&[3u8; 20]);
    state.set_balance(sender, U256::from_u64(1000));
    let hash1 = handler.initiate(&mut state, sender, recipient1, U256::from_u64(100)).unwrap();
    let hash2 = handler.initiate(&mut state, sender, recipient2, U256::from_u64(100)).unwrap();
    if hash1 == hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
