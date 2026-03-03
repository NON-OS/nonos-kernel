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

use crate::crypto::ethereum::{EthAddress, Wallet};
use super::state::CAPSULE_STORE;

pub fn set_wallet(sk: [u8; 32]) -> Result<EthAddress, &'static str> {
    let wallet = Wallet::from_secret_key(sk).ok_or("Invalid secret key")?;
    let addr = wallet.address().clone();

    let lock = CAPSULE_STORE.lock();
    if let Some(store) = lock.as_ref() {
        let mut w = store.wallet.write();
        *w = Some(wallet);
        Ok(addr)
    } else {
        Err("Store not initialized")
    }
}

pub fn get_wallet_address() -> Option<EthAddress> {
    let lock = CAPSULE_STORE.lock();
    let store = lock.as_ref()?;
    let wallet = store.wallet.read();
    wallet.as_ref().map(|w| w.address().clone())
}
