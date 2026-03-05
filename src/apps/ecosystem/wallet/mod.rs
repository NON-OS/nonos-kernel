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

//! NONOS Ecosystem Wallet Module.

extern crate alloc;

pub mod keys;
pub mod rpc;
pub mod state;
pub mod stealth;
pub mod transaction;

pub use keys::{derive_account, generate_wallet, import_wallet, WalletKeys};
pub use rpc::{EthRpcClient, RpcEndpoint, RpcNetwork};
pub use state::{get_wallet, init_wallet, lock_wallet, unlock_wallet, WalletState};
pub use stealth::{generate_stealth_address, scan_announcements, StealthKeyPair, StealthMetaAddress};
pub use transaction::{build_transaction, sign_transaction, SignedTransaction, TransactionRequest};

use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn init() {
    // Initialize wallet subsystem
}

pub fn start() {
    RUNNING.store(true, Ordering::SeqCst);
}

pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

pub fn create_wallet() -> Result<String, &'static str> {
    let mnemonic = crate::crypto::application::bip39::generate_mnemonic(12)
        .map_err(|_| "Failed to generate mnemonic")?;

    let seed = crate::crypto::application::bip39::mnemonic_to_seed(&mnemonic, "")
        .map_err(|_| "Failed to derive seed")?;

    let wallet_keys = WalletKeys::from_seed(&seed)
        .map_err(|_| "Failed to create wallet keys")?;

    let address = wallet_keys.derive_address_hex(0)
        .map_err(|_| "Failed to derive address")?;

    Ok(address)
}
