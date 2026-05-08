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

//! Userland wrapper for `CryptoEd25519Verify`. The kernel cap-gates
//! by `Capability::Crypto` and routes the request through the
//! crypto capsule's existing client transport; nothing here pulls
//! in a crypto crate. Status `0` means the signature checked;
//! `-74` (`EBADMSG`) means it did not.

use crate::syscall::{call_raw, N_CRYPTO_ED25519_VERIFY};

#[no_mangle]
pub extern "C" fn crypto_ed25519_verify(
    pubkey: *const u8,
    signature: *const u8,
    message: *const u8,
    message_len: usize,
) -> i64 {
    call_raw(
        N_CRYPTO_ED25519_VERIFY,
        [pubkey as u64, signature as u64, message as u64, message_len as u64, 0, 0],
    )
}
