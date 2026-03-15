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

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;
use crate::crypto::asymmetric::ed25519::{KeyPair, sign, Signature};

static KERNEL_KEYPAIR: Once<KeyPair> = Once::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    KERNEL_KEYPAIR.call_once(|| {
        let kp = KeyPair::generate();
        INITIALIZED.store(true, Ordering::Release);
        kp
    });
}

pub fn is_initialized() -> bool { INITIALIZED.load(Ordering::Acquire) }

pub fn sign_with_kernel_key(data: &[u8]) -> Option<Signature> {
    KERNEL_KEYPAIR.get().map(|kp| sign(kp, data))
}

pub fn kernel_public_key() -> Option<[u8; 32]> {
    KERNEL_KEYPAIR.get().map(|kp| kp.public)
}

pub fn sign_capability_token(token_data: &[u8]) -> [u8; 64] {
    match sign_with_kernel_key(token_data) {
        Some(sig) => sig.to_bytes(),
        None => [0u8; 64],
    }
}
