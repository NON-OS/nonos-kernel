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

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

pub static WALLET_CONNECTED: AtomicBool = AtomicBool::new(false);
pub static WALLET_ADDRESS: Mutex<[u8; 42]> = Mutex::new([0u8; 42]);
pub static WALLET_BALANCE: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
pub static WALLET_BALANCE_LEN: AtomicUsize = AtomicUsize::new(0);
pub static STAKING_AMOUNT: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
pub static STAKING_AMOUNT_LEN: AtomicUsize = AtomicUsize::new(0);
pub static STAKING_REWARDS: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
pub static STAKING_REWARDS_LEN: AtomicUsize = AtomicUsize::new(0);

pub fn set_wallet_address(addr: &str) {
    let mut buf = WALLET_ADDRESS.lock();
    let len = addr.len().min(42);
    buf[..len].copy_from_slice(&addr.as_bytes()[..len]);
    WALLET_CONNECTED.store(true, Ordering::Relaxed);
}

pub fn get_wallet_address() -> Option<String> {
    if !WALLET_CONNECTED.load(Ordering::Relaxed) { return None; }
    let buf = WALLET_ADDRESS.lock();
    core::str::from_utf8(&buf[..42]).ok().map(String::from)
}

pub fn set_wallet_balance(balance: &str) {
    let mut buf = WALLET_BALANCE.lock();
    let len = balance.len().min(31);
    buf[..len].copy_from_slice(&balance.as_bytes()[..len]);
    WALLET_BALANCE_LEN.store(len, Ordering::Relaxed);
}

pub fn get_wallet_balance() -> Option<String> {
    let len = WALLET_BALANCE_LEN.load(Ordering::Relaxed);
    if len > 0 {
        let buf = WALLET_BALANCE.lock();
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else { None }
}

pub fn set_staking_amount(amount: &str) {
    let mut buf = STAKING_AMOUNT.lock();
    let len = amount.len().min(31);
    buf[..len].copy_from_slice(&amount.as_bytes()[..len]);
    STAKING_AMOUNT_LEN.store(len, Ordering::Relaxed);
}

pub fn get_staking_amount() -> Option<String> {
    let len = STAKING_AMOUNT_LEN.load(Ordering::Relaxed);
    if len > 0 {
        let buf = STAKING_AMOUNT.lock();
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else { None }
}

pub fn set_staking_rewards(rewards: &str) {
    let mut buf = STAKING_REWARDS.lock();
    let len = rewards.len().min(31);
    buf[..len].copy_from_slice(&rewards.as_bytes()[..len]);
    STAKING_REWARDS_LEN.store(len, Ordering::Relaxed);
}

pub fn get_staking_rewards() -> Option<String> {
    let len = STAKING_REWARDS_LEN.load(Ordering::Relaxed);
    if len > 0 {
        let buf = STAKING_REWARDS.lock();
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else { None }
}
