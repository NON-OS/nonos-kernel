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

use crate::syscall::dispatch::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;
use alloc::vec::Vec;

pub(super) struct Ed25519Inputs {
    pub(super) public_key: [u8; 32],
    pub(super) signature: [u8; 64],
    pub(super) message: Vec<u8>,
}

pub(super) fn read(
    pubkey_ptr: u64,
    sig_ptr: u64,
    msg_ptr: u64,
    msg_len: u64,
) -> Result<Ed25519Inputs, SyscallResult> {
    if pubkey_ptr == 0 || sig_ptr == 0 {
        return Err(errno(22));
    }
    if msg_len > 1024 * 1024 {
        return Err(errno(90));
    }
    if msg_ptr == 0 && msg_len != 0 {
        return Err(errno(22));
    }
    let mut public_key = [0u8; 32];
    let mut signature = [0u8; 64];
    copy_from_user(pubkey_ptr, &mut public_key).map_err(|_| errno(14))?;
    copy_from_user(sig_ptr, &mut signature).map_err(|_| errno(14))?;
    let mut message = alloc::vec![0u8; msg_len as usize];
    if msg_len != 0 {
        copy_from_user(msg_ptr, &mut message).map_err(|_| errno(14))?;
    }
    Ok(Ed25519Inputs { public_key, signature, message })
}
