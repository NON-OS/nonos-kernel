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

use super::{context::CryptoContext, EncryptionError};
use crate::crypto::random_api::get_bytes_secure;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};

pub static CRYPTO_CONTEXT: Once<Mutex<CryptoContext>> = Once::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_global_key() -> Result<(), EncryptionError> {
    if INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }

    let mut master_key = [0u8; 32];
    get_bytes_secure(&mut master_key).map_err(|_| EncryptionError::InsufficientEntropy)?;

    CRYPTO_CONTEXT.call_once(|| Mutex::new(CryptoContext::new(master_key)));
    INITIALIZED.store(true, Ordering::Release);

    Ok(())
}
