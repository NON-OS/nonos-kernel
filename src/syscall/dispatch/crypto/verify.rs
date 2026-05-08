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

//! `CryptoEd25519Verify` syscall handler. Caller supplies a 32-byte
//! pubkey, a 64-byte signature, and a message; the kernel cap-gates
//! the call and routes it through the crypto capsule's existing
//! kernel-side client. No crypto runs in the kernel from this path
//! — the userland capsule does the math.

extern crate alloc;

use crate::capabilities::Capability;
use crate::security::crypto_capsule::client as crypto_client;
use crate::security::crypto_capsule::CryptoCapsuleError;
use crate::syscall::dispatch::{errno, require_capability};
use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;

const PUBKEY_LEN: usize = 32;
const SIG_LEN: usize = 64;
const MAX_MESSAGE_LEN: u64 = 1024 * 1024;

pub fn handle_crypto_ed25519_verify(
    pubkey_ptr: u64,
    sig_ptr: u64,
    msg_ptr: u64,
    msg_len: u64,
) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }
    if pubkey_ptr == 0 || sig_ptr == 0 {
        return errno(22);
    }
    if msg_len > MAX_MESSAGE_LEN {
        return errno(90);
    }
    // A zero-length message is valid for Ed25519 in principle, but
    // a null pointer with a zero length is still treated as an
    // argument error so the contract stays uniform with the other
    // crypto syscalls.
    if msg_ptr == 0 && msg_len != 0 {
        return errno(22);
    }

    let mut pubkey = [0u8; PUBKEY_LEN];
    if copy_from_user(pubkey_ptr, &mut pubkey).is_err() {
        return errno(14);
    }
    let mut signature = [0u8; SIG_LEN];
    if copy_from_user(sig_ptr, &mut signature).is_err() {
        return errno(14);
    }

    let mut message = alloc::vec![0u8; msg_len as usize];
    if msg_len > 0 {
        if copy_from_user(msg_ptr, &mut message).is_err() {
            return errno(14);
        }
    }

    match crypto_client::verify_ed25519(&pubkey, &signature, &message) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(e) => map_capsule_error(e),
    }
}

fn map_capsule_error(err: CryptoCapsuleError) -> SyscallResult {
    match err {
        CryptoCapsuleError::AccessDenied => errno(13),
        CryptoCapsuleError::InvalidArgument => errno(22),
        CryptoCapsuleError::OversizedRequest => errno(90),
        CryptoCapsuleError::AuthFailure => errno(74),
        CryptoCapsuleError::ProtocolMismatch => errno(71),
        CryptoCapsuleError::Dead => errno(19),
        CryptoCapsuleError::Stale => errno(116),
        CryptoCapsuleError::NoCallerPid | CryptoCapsuleError::TransportFailure => errno(5),
    }
}
