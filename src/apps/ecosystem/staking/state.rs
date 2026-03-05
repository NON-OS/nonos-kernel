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

use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::RwLock;

use super::contract::StakingContract;

static STAKING_INITIALIZED: AtomicBool = AtomicBool::new(false);
static STAKING_STATE: RwLock<Option<StakingStateInner>> = RwLock::new(None);
static LAST_UPDATE: AtomicU64 = AtomicU64::new(0);

pub const STAKING_CONTRACT_MAINNET: &str = "0x0000000000000000000000000000000000000000";
pub const STAKING_CONTRACT_SEPOLIA: &str = "0x7c34956eb5e92460307846D754dD4d1a2400B652";
pub const NOX_TOKEN_MAINNET: &str = "0x0000000000000000000000000000000000000000";
pub const NOX_TOKEN_SEPOLIA: &str = "0xC87799c4517Dcdfc65bfefa3Be64Beb89668c66c";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Sepolia,
}

impl Network {
    pub fn staking_contract(&self) -> &'static str {
        match self {
            Network::Mainnet => STAKING_CONTRACT_MAINNET,
            Network::Sepolia => STAKING_CONTRACT_SEPOLIA,
        }
    }

    pub fn nox_token(&self) -> &'static str {
        match self {
            Network::Mainnet => NOX_TOKEN_MAINNET,
            Network::Sepolia => NOX_TOKEN_SEPOLIA,
        }
    }

    pub fn chain_id(&self) -> u64 {
        match self {
            Network::Mainnet => 1,
            Network::Sepolia => 11155111,
        }
    }
}

struct StakingStateInner {
    network: Network,
    contract: StakingContract,
    staked_amount: u128,
    pending_rewards: u128,
    total_staked: u128,
    current_apy: u64,
    min_stake: u128,
    lock_period: u64,
    user_stake_time: u64,
}

#[derive(Debug, Clone)]
pub struct StakingState {
    pub network: Network,
    pub staked_amount: u128,
    pub pending_rewards: u128,
    pub total_staked: u128,
    pub current_apy: u64,
    pub min_stake: u128,
    pub lock_period: u64,
    pub user_stake_time: u64,
    pub can_unstake: bool,
    pub last_update: u64,
}

impl StakingState {
    pub fn staked_amount_formatted(&self) -> String {
        format_token_amount(self.staked_amount, 18)
    }

    pub fn pending_rewards_formatted(&self) -> String {
        format_token_amount(self.pending_rewards, 18)
    }

    pub fn total_staked_formatted(&self) -> String {
        format_token_amount(self.total_staked, 18)
    }

    pub fn apy_percentage(&self) -> f64 {
        self.current_apy as f64 / 100.0
    }

    pub fn time_until_unlock(&self) -> u64 {
        let now = crate::time::timestamp_secs();
        let unlock_time = self.user_stake_time.saturating_add(self.lock_period);
        if now >= unlock_time {
            0
        } else {
            unlock_time - now
        }
    }
}

pub fn init(network: Network) {
    if STAKING_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    let contract = StakingContract::new(network.staking_contract(), network.nox_token());

    let inner = StakingStateInner {
        network,
        contract,
        staked_amount: 0,
        pending_rewards: 0,
        total_staked: 0,
        current_apy: 1200,
        min_stake: 100_000_000_000_000_000_000,
        lock_period: 7 * 24 * 60 * 60,
        user_stake_time: 0,
    };

    {
        let mut guard = STAKING_STATE.write();
        *guard = Some(inner);
    }

    STAKING_INITIALIZED.store(true, Ordering::SeqCst);
}

pub fn is_initialized() -> bool {
    STAKING_INITIALIZED.load(Ordering::SeqCst)
}

pub fn get_staking_state() -> Option<StakingState> {
    if !STAKING_INITIALIZED.load(Ordering::SeqCst) {
        return None;
    }

    let guard = STAKING_STATE.read();
    let inner = guard.as_ref()?;

    let now = crate::time::timestamp_secs();
    let unlock_time = inner.user_stake_time.saturating_add(inner.lock_period);
    let can_unstake = inner.staked_amount > 0 && now >= unlock_time;

    Some(StakingState {
        network: inner.network,
        staked_amount: inner.staked_amount,
        pending_rewards: inner.pending_rewards,
        total_staked: inner.total_staked,
        current_apy: inner.current_apy,
        min_stake: inner.min_stake,
        lock_period: inner.lock_period,
        user_stake_time: inner.user_stake_time,
        can_unstake,
        last_update: LAST_UPDATE.load(Ordering::Relaxed),
    })
}

pub fn update_staked_amount(amount: u128) {
    let mut guard = STAKING_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.staked_amount = amount;
        if amount > 0 && inner.user_stake_time == 0 {
            inner.user_stake_time = crate::time::timestamp_secs();
        }
    }
    LAST_UPDATE.store(crate::time::timestamp_secs(), Ordering::Relaxed);
}

pub fn update_pending_rewards(amount: u128) {
    let mut guard = STAKING_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.pending_rewards = amount;
    }
    LAST_UPDATE.store(crate::time::timestamp_secs(), Ordering::Relaxed);
}

pub fn update_total_staked(amount: u128) {
    let mut guard = STAKING_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.total_staked = amount;
    }
}

pub fn update_apy(apy: u64) {
    let mut guard = STAKING_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.current_apy = apy;
    }
}

pub fn get_contract() -> Option<StakingContract> {
    let guard = STAKING_STATE.read();
    guard.as_ref().map(|inner| inner.contract.clone())
}

pub fn get_network() -> Option<Network> {
    let guard = STAKING_STATE.read();
    guard.as_ref().map(|inner| inner.network)
}

pub fn set_network(network: Network) {
    let mut guard = STAKING_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.network = network;
        inner.contract = StakingContract::new(network.staking_contract(), network.nox_token());
    }
}

pub fn reset_user_state() {
    let mut guard = STAKING_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.staked_amount = 0;
        inner.pending_rewards = 0;
        inner.user_stake_time = 0;
    }
}

fn format_token_amount(amount: u128, decimals: u8) -> String {
    let divisor = 10u128.pow(decimals as u32);
    let whole = amount / divisor;
    let fraction = amount % divisor;

    let fraction_str = alloc::format!("{:0>width$}", fraction, width = decimals as usize);
    let trimmed = fraction_str.trim_end_matches('0');

    if trimmed.is_empty() {
        alloc::format!("{}", whole)
    } else {
        alloc::format!("{}.{}", whole, trimmed)
    }
}
