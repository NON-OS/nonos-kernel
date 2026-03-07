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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use spin::Mutex;

use super::types::{WalletAccount, Transaction};
use super::stealth::StealthKeyPair;

pub(crate) use super::state_ops::{init_wallet, lock_wallet, derive_account, clear_send_fields, refresh_balances};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum WalletView {
    Overview = 0,
    Send = 1,
    Receive = 2,
    Transactions = 3,
    Settings = 4,
    Stealth = 5,
}

impl From<u8> for WalletView {
    fn from(v: u8) -> Self {
        match v {
            0 => WalletView::Overview,
            1 => WalletView::Send,
            2 => WalletView::Receive,
            3 => WalletView::Transactions,
            4 => WalletView::Settings,
            5 => WalletView::Stealth,
            _ => WalletView::Overview,
        }
    }
}

pub(crate) struct WalletState {
    pub unlocked: bool,
    pub master_key: Option<[u8; 32]>,
    pub accounts: Vec<WalletAccount>,
    pub active_account: usize,
    pub stealth_keypair: Option<StealthKeyPair>,
    pub pending_transactions: Vec<Transaction>,
}

impl WalletState {
    pub(crate) const fn new() -> Self {
        Self {
            unlocked: false,
            master_key: None,
            accounts: Vec::new(),
            active_account: 0,
            stealth_keypair: None,
            pending_transactions: Vec::new(),
        }
    }

    pub(crate) fn lock(&mut self) {
        if let Some(ref mut key) = self.master_key {
            for byte in key.iter_mut() {
                *byte = 0;
            }
        }
        self.master_key = None;

        for account in self.accounts.iter_mut() {
            for byte in account.secret_key.iter_mut() {
                *byte = 0;
            }
        }

        self.accounts.clear();
        self.active_account = 0;
        self.stealth_keypair = None;
        self.pending_transactions.clear();
        self.unlocked = false;
    }

    pub(crate) fn get_active_account(&self) -> Option<&WalletAccount> {
        self.accounts.get(self.active_account)
    }

    pub(crate) fn set_active_account(&mut self, index: usize) {
        if index < self.accounts.len() {
            self.active_account = index;
        }
    }

    pub(crate) fn total_balance(&self) -> u128 {
        self.accounts.iter().map(|a| a.balance).sum()
    }
}

pub(crate) static WALLET_STATE: Mutex<WalletState> = Mutex::new(WalletState::new());
pub(crate) static CURRENT_VIEW: AtomicU8 = AtomicU8::new(0);
pub(crate) static INPUT_FOCUSED: AtomicBool = AtomicBool::new(false);
pub(crate) static INPUT_CURSOR: AtomicUsize = AtomicUsize::new(0);

pub(crate) static SEND_ADDRESS: Mutex<[u8; 64]> = Mutex::new([0u8; 64]);
pub(crate) static SEND_ADDRESS_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static SEND_AMOUNT: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
pub(crate) static SEND_AMOUNT_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static SEND_FIELD: AtomicU8 = AtomicU8::new(0);

pub(crate) static STATUS_MSG: Mutex<[u8; 64]> = Mutex::new([0u8; 64]);
pub(crate) static STATUS_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static STATUS_SUCCESS: AtomicBool = AtomicBool::new(true);

pub(crate) static PASSWORD_INPUT: Mutex<[u8; 64]> = Mutex::new([0u8; 64]);
pub(crate) static PASSWORD_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PASSWORD_FOCUSED: AtomicBool = AtomicBool::new(false);

pub(crate) static SHOW_PRIVATE_KEY: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_view(view: WalletView) {
    CURRENT_VIEW.store(view as u8, Ordering::SeqCst);
}

pub(crate) fn get_view() -> WalletView {
    WalletView::from(CURRENT_VIEW.load(Ordering::SeqCst))
}

pub(crate) fn set_status(msg: &[u8], success: bool) {
    let mut status = STATUS_MSG.lock();
    let len = msg.len().min(63);
    status[..len].copy_from_slice(&msg[..len]);
    STATUS_LEN.store(len, Ordering::SeqCst);
    STATUS_SUCCESS.store(success, Ordering::SeqCst);
}
