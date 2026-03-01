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

use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use crate::syscall::dispatch::{errno, require_capability};

pub fn handle_crypto_keygen(algo: u64, public_key_ptr: u64, private_key_ptr: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }

    if public_key_ptr == 0 || private_key_ptr == 0 {
        return errno(22);
    }

    match algo {
        0 => {
            let keypair = crate::crypto::ed25519::KeyPair::generate();

            let public_key = unsafe { core::slice::from_raw_parts_mut(public_key_ptr as *mut u8, 32) };
            let private_key = unsafe { core::slice::from_raw_parts_mut(private_key_ptr as *mut u8, 32) };

            public_key.copy_from_slice(&keypair.public);
            private_key.copy_from_slice(&keypair.private);

            SyscallResult { value: 0, capability_consumed: false, audit_required: true }
        }
        _ => errno(22),
    }
}
