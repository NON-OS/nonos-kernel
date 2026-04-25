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

use crate::crypto::application::bip32::ExtendedPrivateKey;
use core::ops::Deref;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

pub(super) const BIP44_PURPOSE: u32 = 44;
pub(super) const BIP44_ETH_COIN: u32 = 60;

pub struct SecureSecretKey([u8; 32]);

impl SecureSecretKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Deref for SecureSecretKey {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SecureSecretKey {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct WalletKeys {
    pub(super) master: ExtendedPrivateKey,
    pub(super) account_key: ExtendedPrivateKey,
}

impl Drop for WalletKeys {
    fn drop(&mut self) {
        unsafe {
            ptr::write_volatile(&mut self.master as *mut ExtendedPrivateKey, core::mem::zeroed());
            ptr::write_volatile(
                &mut self.account_key as *mut ExtendedPrivateKey,
                core::mem::zeroed(),
            );
        }
        compiler_fence(Ordering::SeqCst);
    }
}

pub(super) fn hex_char(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }
}
