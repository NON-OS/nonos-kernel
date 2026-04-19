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

pub static IMPORT_SEED_PHRASE: Mutex<String> = Mutex::new(String::new());
pub static SEND_RECIPIENT: Mutex<Option<String>> = Mutex::new(None);
pub static SEND_AMOUNT: Mutex<Option<u64>> = Mutex::new(None);
pub static STAKE_INPUT: Mutex<Option<u64>> = Mutex::new(None);
pub static UNSTAKE_INPUT: Mutex<Option<u64>> = Mutex::new(None);
pub static LP_AMOUNT_A: Mutex<Option<u64>> = Mutex::new(None);
pub static LP_AMOUNT_B: Mutex<Option<u64>> = Mutex::new(None);
pub static REMOVE_LP_AMOUNT: Mutex<Option<u64>> = Mutex::new(None);

pub fn get_import_seed_phrase() -> String { IMPORT_SEED_PHRASE.lock().clone() }
pub fn clear_import_seed_phrase() { IMPORT_SEED_PHRASE.lock().clear(); }
pub fn get_send_recipient() -> Option<String> { SEND_RECIPIENT.lock().clone() }
pub fn get_send_amount() -> Option<u64> { *SEND_AMOUNT.lock() }
pub fn clear_send_fields() { *SEND_RECIPIENT.lock() = None; *SEND_AMOUNT.lock() = None; }
pub fn get_stake_amount() -> Option<u64> { *STAKE_INPUT.lock() }
pub fn clear_stake_amount() { *STAKE_INPUT.lock() = None; }
pub fn get_unstake_amount() -> Option<u64> { *UNSTAKE_INPUT.lock() }
pub fn clear_unstake_amount() { *UNSTAKE_INPUT.lock() = None; }
pub fn get_lp_amounts() -> Option<(u64, u64)> {
    let a = LP_AMOUNT_A.lock().clone()?;
    let b = LP_AMOUNT_B.lock().clone()?;
    Some((a, b))
}
pub fn clear_lp_amounts() { *LP_AMOUNT_A.lock() = None; *LP_AMOUNT_B.lock() = None; }
pub fn get_remove_lp_amount() -> Option<u64> { *REMOVE_LP_AMOUNT.lock() }
pub fn clear_remove_lp_amount() { *REMOVE_LP_AMOUNT.lock() = None; }
pub fn refresh_staking_info() {
    if let Ok(info) = crate::apps::ecosystem::staking::get_staking_info() {
        set_staking_amount(&alloc::format!("{}", info.staked_amount));
        set_staking_rewards(&alloc::format!("{}", info.pending_rewards));
    }
}
pub fn refresh_lp_info() {
    if let Ok(info) = crate::apps::ecosystem::lp::get_position_info() {
        set_wallet_balance(&alloc::format!("{}", info.lp_tokens));
    }
}
