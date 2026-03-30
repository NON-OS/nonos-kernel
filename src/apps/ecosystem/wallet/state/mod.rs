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

mod types;
mod account;
mod api;

pub use types::{WalletStatus, Network, WalletState};
pub use account::AccountInfo;
pub use api::{init_wallet, get_wallet, lock_wallet, unlock_wallet, is_locked, is_initialized,
    set_network, get_network, set_active_account, get_active_account, add_account, get_account,
    get_all_accounts, update_account_balance, update_account_nonce, get_secret_key,
    set_stealth_keys, get_stealth_keys, destroy_wallet};
