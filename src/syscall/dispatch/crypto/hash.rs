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

use crate::capabilities::Capability;
use crate::security::crypto_capsule::client as crypto_client;
use crate::security::crypto_capsule::CryptoCapsuleError;
use crate::syscall::dispatch::{errno, require_capability};
use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;

// User-facing CryptoHash. CAP_CRYPTO at the syscall gate, then routed
// to the crypto capsule which owns the primitives. The capsule
// returns the full digest; we keep the legacy 8-byte truncated u64
// ABI for now (digest-out buffer ABI is a separate slice).
pub fn handle_crypto_hash(algo: u64, data: u64, len: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }
    if data == 0 || len == 0 || len > 1024 * 1024 {
        return errno(22);
    }
    let mut input = alloc::vec![0u8; len as usize];
    if copy_from_user(data, &mut input).is_err() {
        return errno(14);
    }
    match algo {
        0 => match crypto_client::hash_blake3(&input) {
            Ok(digest) => ok_truncated(&digest),
            Err(e) => map_capsule_error(e),
        },
        1 => match crypto_client::hash_sha256(&input) {
            Ok(digest) => ok_truncated(&digest),
            Err(e) => map_capsule_error(e),
        },
        2 => match crypto_client::hash_sha512(&input) {
            Ok(digest) => ok_truncated(&digest),
            Err(e) => map_capsule_error(e),
        },
        _ => errno(22),
    }
}

fn ok_truncated(digest: &[u8]) -> SyscallResult {
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&digest[..8]);
    SyscallResult {
        value: u64::from_le_bytes(id_bytes) as i64,
        capability_consumed: false,
        audit_required: false,
    }
}

fn map_capsule_error(err: CryptoCapsuleError) -> SyscallResult {
    match err {
        CryptoCapsuleError::AccessDenied => errno(13),
        CryptoCapsuleError::InvalidArgument => errno(22),
        CryptoCapsuleError::OversizedRequest => errno(90),
        CryptoCapsuleError::ProtocolMismatch => errno(71),
        CryptoCapsuleError::Dead => errno(19),
        CryptoCapsuleError::Stale => errno(116),
        // Hash ops never authenticate; the cipher primitive doesn't
        // run from this dispatch family. Treat the same as a
        // primitive-side internal error.
        CryptoCapsuleError::AuthFailure => errno(5),
        CryptoCapsuleError::NoCallerPid | CryptoCapsuleError::TransportFailure => errno(5),
    }
}
