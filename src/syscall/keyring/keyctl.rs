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

use super::keyctl_ops::*;
use super::keyctl_ops2::{
    keyctl_clear, keyctl_describe, keyctl_invalidate, keyctl_link, keyctl_read, keyctl_search,
    keyctl_set_timeout, keyctl_unlink,
};
use super::types::*;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;

pub fn handle_keyctl(operation: u32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> SyscallResult {
    match operation {
        KEYCTL_GET_KEYRING_ID => keyctl_get_keyring_id(arg2 as KeySerial, arg3 != 0),
        KEYCTL_JOIN_SESSION_KEYRING => keyctl_join_session_keyring(arg2),
        KEYCTL_UPDATE => keyctl_update(arg2 as KeySerial, arg3, arg4 as usize),
        KEYCTL_REVOKE => keyctl_revoke(arg2 as KeySerial),
        KEYCTL_CHOWN => keyctl_chown(arg2 as KeySerial, arg3 as u32, arg4 as u32),
        KEYCTL_SETPERM => keyctl_setperm(arg2 as KeySerial, arg3 as u32),
        KEYCTL_DESCRIBE => keyctl_describe(arg2 as KeySerial, arg3, arg4 as usize),
        KEYCTL_CLEAR => keyctl_clear(arg2 as KeySerial),
        KEYCTL_LINK => keyctl_link(arg2 as KeySerial, arg3 as KeySerial),
        KEYCTL_UNLINK => keyctl_unlink(arg2 as KeySerial, arg3 as KeySerial),
        KEYCTL_SEARCH => keyctl_search(arg2 as KeySerial, arg3, arg4, arg5 as KeySerial),
        KEYCTL_READ => keyctl_read(arg2 as KeySerial, arg3, arg4 as usize),
        KEYCTL_SET_TIMEOUT => keyctl_set_timeout(arg2 as KeySerial, arg3 as u32),
        KEYCTL_INVALIDATE => keyctl_invalidate(arg2 as KeySerial),
        _ => errno(22),
    }
}
