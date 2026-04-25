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

use super::bridge::{Deposit, DepositHandler, WithdrawHandler};
use super::config::ZkSyncConfig;
use super::sequencer::TransactionPool;
use super::state::{ContractStorage, StateManager};
use super::types::{Address, L2Transaction, TransactionStatus, TxHash, U256};
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut CONFIG: Option<ZkSyncConfig> = None;
static STATE_MANAGER: Once<Mutex<StateManager>> = Once::new();
static TX_POOL: Once<Mutex<TransactionPool>> = Once::new();
static TX_STATUS: Once<Mutex<BTreeMap<TxHash, TransactionStatus>>> = Once::new();
static CONTRACT_STORAGE: Once<Mutex<ContractStorage>> = Once::new();
static DEPOSIT_HANDLER: Once<Mutex<DepositHandler>> = Once::new();
static WITHDRAW_HANDLER: Once<Mutex<WithdrawHandler>> = Once::new();

pub fn init_zksync(config: ZkSyncConfig) -> Result<(), super::ZkSyncError> {
    if INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }
    STATE_MANAGER.call_once(|| Mutex::new(StateManager::new()));
    TX_POOL.call_once(|| Mutex::new(TransactionPool::default()));
    TX_STATUS.call_once(|| Mutex::new(BTreeMap::new()));
    CONTRACT_STORAGE.call_once(|| Mutex::new(ContractStorage::new()));
    DEPOSIT_HANDLER.call_once(|| Mutex::new(DepositHandler::new()));
    WITHDRAW_HANDLER.call_once(|| Mutex::new(WithdrawHandler::new()));
    unsafe {
        CONFIG = Some(config);
    }
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

pub(super) fn submit_transaction(tx: L2Transaction) -> bool {
    let pool: &Mutex<TransactionPool> = match TX_POOL.get() {
        Some(p) => p,
        None => return false,
    };
    let hash = tx.hash;
    let success = pool.lock().insert(tx);
    if success {
        if let Some(status_map) = TX_STATUS.get() {
            status_map.lock().insert(hash, TransactionStatus::Pending);
        }
    }
    success
}

pub(super) fn get_tx_status(hash: &TxHash) -> Option<TransactionStatus> {
    TX_STATUS.get().and_then(|m| m.lock().get(hash).copied())
}

pub(super) fn set_tx_status(hash: TxHash, status: TransactionStatus) {
    if let Some(m) = TX_STATUS.get() {
        m.lock().insert(hash, status);
    }
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

pub(crate) fn get_config() -> Option<&'static ZkSyncConfig> {
    if !is_initialized() {
        return None;
    }
    unsafe { (*core::ptr::addr_of!(CONFIG)).as_ref() }
}

pub(crate) fn with_state<R, F: FnOnce(&StateManager) -> R>(f: F) -> Option<R> {
    STATE_MANAGER.get().map(|m| f(&m.lock()))
}

pub(crate) fn with_state_mut<R, F: FnOnce(&mut StateManager) -> R>(f: F) -> Option<R> {
    STATE_MANAGER.get().map(|m| f(&mut m.lock()))
}

pub(super) fn get_storage_value(address: &Address, slot: &U256) -> U256 {
    let storage: &Mutex<ContractStorage> = match CONTRACT_STORAGE.get() {
        Some(s) => s,
        None => return U256::ZERO,
    };
    storage.lock().get(address, slot)
}

pub(super) fn set_storage_value(address: Address, slot: U256, value: U256) {
    let storage: &Mutex<ContractStorage> = match CONTRACT_STORAGE.get() {
        Some(s) => s,
        None => return,
    };
    storage.lock().set(address, slot, value);
}

pub(super) fn queue_deposit(deposit: Deposit) {
    if let Some(h) = DEPOSIT_HANDLER.get() {
        h.lock().queue(deposit);
    }
}

pub(super) fn process_deposit() -> Option<Deposit> {
    if let Some(h) = DEPOSIT_HANDLER.get() {
        if let Some(state) = STATE_MANAGER.get() {
            return h.lock().process_next(&mut state.lock()).ok().flatten();
        }
    }
    None
}

pub(super) fn initiate_withdrawal(
    sender: Address,
    recipient: Address,
    amount: U256,
) -> Option<[u8; 32]> {
    let handler: &Mutex<WithdrawHandler> = WITHDRAW_HANDLER.get()?;
    let state: &Mutex<StateManager> = STATE_MANAGER.get()?;
    handler.lock().initiate(&mut state.lock(), sender, recipient, amount).ok()
}
