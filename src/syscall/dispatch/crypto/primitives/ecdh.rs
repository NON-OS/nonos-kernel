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

use super::copy;
use crate::capabilities::Capability;
use crate::security::crypto_capsule::client;
use crate::syscall::dispatch::crypto::error::{map_capsule_error, CryptoErrorContext};
use crate::syscall::dispatch::require_capability;
use crate::syscall::SyscallResult;

pub fn handle_x25519_public(private_ptr: u64, out_ptr: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }
    let private = match copy::read_array::<32>(private_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match client::x25519_public(&private) {
        Ok(out) => copy::write(out_ptr, &out),
        Err(e) => map_capsule_error(e, CryptoErrorContext::Digest),
    }
}

pub fn handle_x25519_shared(private_ptr: u64, public_ptr: u64, out_ptr: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }
    let private = match copy::read_array::<32>(private_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let public = match copy::read_array::<32>(public_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match client::x25519_shared(&private, &public) {
        Ok(out) => copy::write(out_ptr, &out),
        Err(e) => map_capsule_error(e, CryptoErrorContext::Digest),
    }
}
