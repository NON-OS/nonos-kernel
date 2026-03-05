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

//! LP state management.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::RwLock;

use super::contract::LpContract;
use super::pool::PoolInfo;

static LP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static LP_STATE: RwLock<Option<LpStateInner>> = RwLock::new(None);
static LAST_UPDATE: AtomicU64 = AtomicU64::new(0);

pub const LP_CONTRACT_MAINNET: &str = "0x0000000000000000000000000000000000000000";
pub const LP_CONTRACT_SEPOLIA: &str = "0x33221345a0dF2638852dc05D0E51d66cE63C874E";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Sepolia,
}

impl Network {
    pub fn lp_contract(&self) -> &'static str {
        match self {
            Network::Mainnet => LP_CONTRACT_MAINNET,
            Network::Sepolia => LP_CONTRACT_SEPOLIA,
        }
    }

    pub fn chain_id(&self) -> u64 {
        match self {
            Network::Mainnet => 1,
            Network::Sepolia => 11155111,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserPosition {
    pub lp_tokens: u128,
    pub token0_amount: u128,
    pub token1_amount: u128,
    pub share_percentage: f64,
    pub pending_rewards: u128,
    pub lock_end_time: u64,
    pub boosted: bool,
}

impl UserPosition {
    pub fn is_locked(&self) -> bool {
        let now = crate::time::timestamp_secs();
        now < self.lock_end_time
    }

    pub fn time_until_unlock(&self) -> u64 {
        let now = crate::time::timestamp_secs();
        if now >= self.lock_end_time {
            0
        } else {
            self.lock_end_time - now
        }
    }

    pub fn lp_tokens_formatted(&self) -> String {
        format_amount(self.lp_tokens, 18)
    }

    pub fn pending_rewards_formatted(&self) -> String {
        format_amount(self.pending_rewards, 18)
    }
}

struct LpStateInner {
    network: Network,
    contract: LpContract,
    pools: Vec<PoolInfo>,
    user_positions: Vec<UserPosition>,
    selected_pool: usize,
}

#[derive(Debug, Clone)]
pub struct LpState {
    pub network: Network,
    pub pools: Vec<PoolInfo>,
    pub selected_pool: Option<PoolInfo>,
    pub user_position: Option<UserPosition>,
    pub total_value_locked: u128,
    pub last_update: u64,
}

impl LpState {
    pub fn tvl_formatted(&self) -> String {
        format_amount(self.total_value_locked, 18)
    }
}

pub fn init(network: Network) {
    if LP_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    let contract = LpContract::new(network.lp_contract());

    let default_pool = PoolInfo {
        address: String::from(network.lp_contract()),
        token0_symbol: String::from("NOX"),
        token1_symbol: String::from("ETH"),
        token0_address: String::from("0xC87799c4517Dcdfc65bfefa3Be64Beb89668c66c"),
        token1_address: String::from("0x0000000000000000000000000000000000000000"),
        token0_reserve: 0,
        token1_reserve: 0,
        total_supply: 0,
        fee_basis_points: 30,
        apy_basis_points: 2500,
    };

    let inner = LpStateInner {
        network,
        contract,
        pools: alloc::vec![default_pool],
        user_positions: Vec::new(),
        selected_pool: 0,
    };

    {
        let mut guard = LP_STATE.write();
        *guard = Some(inner);
    }

    LP_INITIALIZED.store(true, Ordering::SeqCst);
}

pub fn is_initialized() -> bool {
    LP_INITIALIZED.load(Ordering::SeqCst)
}

pub fn get_lp_state() -> Option<LpState> {
    if !LP_INITIALIZED.load(Ordering::SeqCst) {
        return None;
    }

    let guard = LP_STATE.read();
    let inner = guard.as_ref()?;

    let selected_pool = inner.pools.get(inner.selected_pool).cloned();
    let user_position = inner.user_positions.first().cloned();

    let tvl: u128 = inner.pools.iter().map(|p| p.total_value_locked()).sum();

    Some(LpState {
        network: inner.network,
        pools: inner.pools.clone(),
        selected_pool,
        user_position,
        total_value_locked: tvl,
        last_update: LAST_UPDATE.load(Ordering::Relaxed),
    })
}

pub fn update_pool(index: usize, pool: PoolInfo) {
    let mut guard = LP_STATE.write();
    if let Some(inner) = guard.as_mut() {
        if index < inner.pools.len() {
            inner.pools[index] = pool;
        } else {
            inner.pools.push(pool);
        }
    }
    LAST_UPDATE.store(crate::time::timestamp_secs(), Ordering::Relaxed);
}

pub fn update_user_position(position: UserPosition) {
    let mut guard = LP_STATE.write();
    if let Some(inner) = guard.as_mut() {
        if inner.user_positions.is_empty() {
            inner.user_positions.push(position);
        } else {
            inner.user_positions[0] = position;
        }
    }
    LAST_UPDATE.store(crate::time::timestamp_secs(), Ordering::Relaxed);
}

pub fn select_pool(index: usize) {
    let mut guard = LP_STATE.write();
    if let Some(inner) = guard.as_mut() {
        if index < inner.pools.len() {
            inner.selected_pool = index;
        }
    }
}

pub fn get_selected_pool() -> Option<PoolInfo> {
    let guard = LP_STATE.read();
    let inner = guard.as_ref()?;
    inner.pools.get(inner.selected_pool).cloned()
}

pub fn get_contract() -> Option<LpContract> {
    let guard = LP_STATE.read();
    guard.as_ref().map(|inner| inner.contract.clone())
}

pub fn get_network() -> Option<Network> {
    let guard = LP_STATE.read();
    guard.as_ref().map(|inner| inner.network)
}

pub fn set_network(network: Network) {
    let mut guard = LP_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.network = network;
        inner.contract = LpContract::new(network.lp_contract());
    }
}

pub fn clear_user_positions() {
    let mut guard = LP_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.user_positions.clear();
    }
}

pub fn get_all_pools() -> Vec<PoolInfo> {
    let guard = LP_STATE.read();
    match guard.as_ref() {
        Some(inner) => inner.pools.clone(),
        None => Vec::new(),
    }
}

fn format_amount(amount: u128, decimals: u8) -> String {
    let divisor = 10u128.pow(decimals as u32);
    let whole = amount / divisor;
    let fraction = amount % divisor;

    let fraction_str = alloc::format!("{:0>width$}", fraction, width = decimals as usize);
    let trimmed = fraction_str.trim_end_matches('0');

    if trimmed.is_empty() {
        alloc::format!("{}", whole)
    } else if trimmed.len() > 4 {
        alloc::format!("{}.{}", whole, &trimmed[..4])
    } else {
        alloc::format!("{}.{}", whole, trimmed)
    }
}
