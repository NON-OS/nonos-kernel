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

mod account;
mod api;
mod types;

pub use account::AccountInfo;
pub use api::{
    add_account, destroy_wallet, get_account, get_active_account, get_all_accounts, get_network,
    get_secret_key, get_stealth_keys, get_wallet, init_wallet, is_initialized, is_locked,
    lock_wallet, set_active_account, set_network, set_stealth_keys, unlock_wallet,
    update_account_balance, update_account_nonce,
};
pub use types::{Network, WalletState, WalletStatus};
