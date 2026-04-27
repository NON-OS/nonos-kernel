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

use super::api::{ACTIVE_ACCOUNT, WALLET_INITIALIZED, WALLET_LOCKED, WALLET_STATE};
use core::sync::atomic::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletStatus {
    Uninitialized,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Sepolia,
    Localhost,
    Custom(u64),
}

impl Network {
    pub fn chain_id(&self) -> u64 {
        match self {
            Network::Mainnet => 1,
            Network::Sepolia => 11155111,
            Network::Localhost => 31337,
            Network::Custom(id) => *id,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Network::Mainnet => "Ethereum Mainnet",
            Network::Sepolia => "Sepolia Testnet",
            Network::Localhost => "Localhost",
            Network::Custom(_) => "Custom Network",
        }
    }
}

pub struct WalletState {
    pub status: WalletStatus,
    pub network: Network,
    pub account_count: usize,
    pub active_account: u8,
}

impl WalletState {
    pub fn current() -> Self {
        if !WALLET_INITIALIZED.load(Ordering::SeqCst) {
            return Self {
                status: WalletStatus::Uninitialized,
                network: Network::Mainnet,
                account_count: 0,
                active_account: 0,
            };
        }
        let locked = WALLET_LOCKED.load(Ordering::SeqCst);
        let guard = WALLET_STATE.read();
        let (network, account_count) = match guard.as_ref() {
            Some(inner) => (inner.network, inner.accounts.len()),
            None => (Network::Mainnet, 0),
        };
        Self {
            status: if locked { WalletStatus::Locked } else { WalletStatus::Unlocked },
            network,
            account_count,
            active_account: ACTIVE_ACCOUNT.load(Ordering::Relaxed),
        }
    }
}
