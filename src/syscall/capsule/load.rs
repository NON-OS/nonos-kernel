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

use crate::capsule::{self, UnlockToken, CapsuleId};

pub const SYS_CAPSULE_LOAD: usize = 500;
pub const SYS_CAPSULE_EXEC: usize = 501;
pub const SYS_CAPSULE_KILL: usize = 502;

pub fn sys_capsule_load(data_ptr: usize, data_len: usize, token_ptr: usize) -> i64 {
    let data = match crate::usercopy::copy_from_user(data_ptr, data_len) {
        Ok(d) => d,
        Err(_) => return -1,
    };
    let token_bytes = match crate::usercopy::copy_from_user_fixed::<113>(token_ptr) {
        Ok(t) => t,
        Err(_) => return -1,
    };
    let token = parse_token(&token_bytes);
    match capsule::load(&data, token) {
        Ok(id) => id as i64,
        Err(_) => -1,
    }
}

pub fn sys_capsule_exec(id: CapsuleId, data_ptr: usize, data_len: usize) -> i64 {
    let data = match crate::usercopy::copy_from_user(data_ptr, data_len) {
        Ok(d) => d,
        Err(_) => return -1,
    };
    match capsule::execute(id, &data) {
        Ok(pid) => pid as i64,
        Err(_) => -1,
    }
}

pub fn sys_capsule_kill(id: CapsuleId) -> i64 {
    capsule::registry::remove(id);
    0
}

fn parse_token(data: &[u8; 113]) -> UnlockToken {
    let mut token = [0u8; 32];
    let mut capsule_id = [0u8; 32];
    let mut manifest_hash = [0u8; 32];
    token.copy_from_slice(&data[0..32]);
    capsule_id.copy_from_slice(&data[32..64]);
    manifest_hash.copy_from_slice(&data[64..96]);
    let mut approved_bytes = [0u8; 8];
    let mut expires_bytes = [0u8; 8];
    approved_bytes.copy_from_slice(&data[96..104]);
    expires_bytes.copy_from_slice(&data[104..112]);
    let approved_caps = u64::from_le_bytes(approved_bytes);
    let expires_at = u64::from_le_bytes(expires_bytes);
    UnlockToken { token, capsule_id, manifest_hash, approved_caps, expires_at }
}
