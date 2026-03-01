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

pub fn handle_crypto_sign(key_id: u64, data: u64, len: u64, sig_out: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }

    if data == 0 || len == 0 || sig_out == 0 {
        return errno(22);
    }

    let message = unsafe {
        core::slice::from_raw_parts(data as *const u8, len as usize)
    };

    let sig_buffer = unsafe {
        core::slice::from_raw_parts_mut(sig_out as *mut u8, 64)
    };

    match crate::crypto::sign_message(key_id as u32, message, sig_buffer) {
        Ok(sig_len) => SyscallResult { value: sig_len as i64, capability_consumed: false, audit_required: true },
        Err(crate::crypto::SyscallCryptoError::InvalidArgument) => errno(22),
        Err(crate::crypto::SyscallCryptoError::BufferTooSmall) => errno(34),
        Err(_) => errno(5),
    }
}

pub fn handle_crypto_verify(key_id: u64, data: u64, len: u64, sig: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }

    if data == 0 || len == 0 || sig == 0 {
        return errno(22);
    }

    let message = unsafe {
        core::slice::from_raw_parts(data as *const u8, len as usize)
    };

    let signature = unsafe {
        core::slice::from_raw_parts(sig as *const u8, 64)
    };

    let public_key = match crate::crypto::vault::get_public_key(key_id as u32) {
        Some(pk) => pk,
        None => return errno(2),
    };

    let valid = crate::crypto::verify_signature(message, signature, &public_key);
    SyscallResult {
        value: if valid { 1 } else { 0 },
        capability_consumed: false,
        audit_required: true
    }
}
