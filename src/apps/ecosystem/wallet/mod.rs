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

mod api;
pub mod keys;
pub mod rpc;
pub mod state;
pub mod stealth;
pub mod transaction;

pub use api::{init, start, stop, is_running, create_wallet};
pub use keys::{derive_account, generate_wallet, import_wallet, WalletKeys};
pub use rpc::{EthRpcClient, RpcEndpoint, RpcNetwork};
pub use state::{get_wallet, init_wallet, lock_wallet, unlock_wallet, WalletState};
pub use stealth::{generate_stealth_address, scan_announcements, StealthKeyPair, StealthMetaAddress};
pub use transaction::{build_transaction, sign_transaction, SignedTransaction, TransactionRequest};
