// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::state::{complete_login, get_selected_wallet, set_screen_state, ScreenState};
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

static CURRENT_WALLET: AtomicU8 = AtomicU8::new(0);
static WALLET_COUNT: AtomicUsize = AtomicUsize::new(0);
const MAX_WALLETS: usize = 8;

static mut WALLETS: [[u8; 20]; MAX_WALLETS] = [[0u8; 20]; MAX_WALLETS];

pub(super) fn get_wallet_count() -> u8 {
    WALLET_COUNT.load(Ordering::Relaxed) as u8
}

pub(super) fn get_wallet_address(idx: u8) -> Option<[u8; 20]> {
    let count = WALLET_COUNT.load(Ordering::Relaxed);
    if (idx as usize) >= count {
        return None;
    }
    unsafe { Some(WALLETS[idx as usize]) }
}

pub(super) fn login_with_wallet(idx: u8) -> bool {
    let count = WALLET_COUNT.load(Ordering::Relaxed);
    if (idx as usize) >= count {
        return false;
    }
    CURRENT_WALLET.store(idx, Ordering::Relaxed);
    complete_login();
    true
}

pub fn create_new_wallet() -> bool {
    let count = WALLET_COUNT.load(Ordering::Relaxed);
    if count >= MAX_WALLETS {
        return false;
    }
    let seed = crate::time::timestamp_millis() as u64;
    let hash = crate::crypto::sha256(&seed.to_le_bytes());
    unsafe {
        for i in 0..20 {
            WALLETS[count][i] = hash[i];
        }
    }
    WALLET_COUNT.store(count + 1, Ordering::Relaxed);
    CURRENT_WALLET.store(count as u8, Ordering::Relaxed);
    complete_login();
    true
}

pub fn import_wallet(_mnemonic: &[u8]) -> bool {
    let count = WALLET_COUNT.load(Ordering::Relaxed);
    if count >= MAX_WALLETS {
        return false;
    }
    let hash = crate::crypto::sha256(_mnemonic);
    unsafe {
        for i in 0..20 {
            WALLETS[count][i] = hash[i];
        }
    }
    WALLET_COUNT.store(count + 1, Ordering::Relaxed);
    CURRENT_WALLET.store(count as u8, Ordering::Relaxed);
    complete_login();
    true
}

pub fn get_current_user() -> u8 {
    CURRENT_WALLET.load(Ordering::Relaxed)
}

pub fn get_current_wallet_address() -> Option<[u8; 20]> {
    get_wallet_address(CURRENT_WALLET.load(Ordering::Relaxed))
}

pub fn logout() {
    CURRENT_WALLET.store(0, Ordering::Relaxed);
    set_screen_state(ScreenState::Welcome);
}

pub fn attempt_login() -> bool {
    let selected = get_selected_wallet();
    login_with_wallet(selected)
}
