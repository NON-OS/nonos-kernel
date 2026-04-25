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

use super::special::resolve_special_keyring;
use super::types::KeySerial;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::read_user_string;

pub fn handle_request_key(
    type_ptr: u64,
    desc_ptr: u64,
    _callout_info: u64,
    dest_keyring: KeySerial,
) -> SyscallResult {
    let type_str = match read_user_string(type_ptr, 32) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };
    let description = match read_user_string(desc_ptr, 256) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };
    let tid = crate::process::current_tid() as u64;
    let pid = crate::process::current_pid().unwrap_or(1);
    let uid = crate::process::current_uid();
    let resolved_keyring = if dest_keyring == 0 {
        resolve_special_keyring(-3, tid, pid, uid)
    } else {
        resolve_special_keyring(dest_keyring, tid, pid, uid)
    };
    let keyring_serial = match resolved_keyring {
        Some(s) => s,
        None => return errno(22),
    };
    match super::search::search_keyring(keyring_serial, &type_str, &description) {
        Some(serial) => SyscallResult {
            value: serial as i64,
            capability_consumed: false,
            audit_required: false,
        },
        None => errno(126),
    }
}
