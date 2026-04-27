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

use super::api::{SdkApi, WalletAccess};
use super::app::{AppError, AppResult};
use super::manifest::AppPermission;
use crate::graphics::window::apps::wallet::{send_nox_to, WALLET_STATE};

impl WalletAccess for SdkApi {
    fn get_address(&self) -> Option<[u8; 20]> {
        if !self.has_permission(AppPermission::Wallet) {
            return None;
        }
        let state = WALLET_STATE.lock();
        let idx = state.active_account;
        if idx >= state.accounts.len() {
            return None;
        }
        Some(state.accounts[idx].address)
    }

    fn get_nox_balance(&self) -> u128 {
        if !self.has_permission(AppPermission::Wallet) {
            return 0;
        }
        let state = WALLET_STATE.lock();
        let idx = state.active_account;
        if idx >= state.accounts.len() {
            return 0;
        }
        state.accounts[idx].nox_balance
    }

    fn request_payment(&self, to: &[u8; 20], amount_nox: u64) -> AppResult<[u8; 32]> {
        if !self.has_permission(AppPermission::Wallet) {
            return Err(AppError::PermissionDenied);
        }
        let state = WALLET_STATE.lock();
        if !state.unlocked {
            return Err(AppError::WalletLocked);
        }
        let idx = state.active_account;
        if idx >= state.accounts.len() {
            return Err(AppError::InvalidState);
        }
        let balance = state.accounts[idx].nox_balance;
        if balance < amount_nox as u128 {
            return Err(AppError::InsufficientFunds);
        }
        drop(state);
        match send_nox_to(to, amount_nox as u128) {
            Ok(tx_hash) => Ok(tx_hash),
            Err(_) => Err(AppError::NetworkError),
        }
    }
}
