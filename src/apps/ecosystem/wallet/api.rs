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
use core::sync::atomic::{AtomicBool, Ordering};
use super::WalletKeys;

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn init() {
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
