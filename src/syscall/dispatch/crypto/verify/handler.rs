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

use super::inputs;
use crate::capabilities::Capability;
use crate::security::crypto_capsule::client as crypto_client;
use crate::syscall::dispatch::crypto::error::{map_capsule_error, CryptoErrorContext};
use crate::syscall::dispatch::require_capability;
use crate::syscall::SyscallResult;

pub fn handle_crypto_ed25519_verify(
    pubkey_ptr: u64,
    sig_ptr: u64,
    msg_ptr: u64,
    msg_len: u64,
) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }
    let input = match inputs::read(pubkey_ptr, sig_ptr, msg_ptr, msg_len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match crypto_client::verify_ed25519(&input.public_key, &input.signature, &input.message) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(e) => map_capsule_error(e, CryptoErrorContext::Authenticated),
    }
}
