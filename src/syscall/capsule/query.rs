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

use crate::capsule::{self, CapsuleId, CapsuleState};

pub const SYS_CAPSULE_STATE: usize = 510;
pub const SYS_CAPSULE_INFO: usize = 511;
pub const SYS_CAPSULE_LIST: usize = 512;

pub fn sys_capsule_state(id: CapsuleId) -> i64 {
    match capsule::registry::get(id) {
        Some(c) => match c.state {
            CapsuleState::Loaded => 0,
            CapsuleState::Running => 1,
            CapsuleState::Suspended => 2,
            CapsuleState::Exited(code) => 3 | ((code as i64) << 8),
            CapsuleState::Faulted => 4,
        },
        None => -1,
    }
}

pub fn sys_capsule_info(id: CapsuleId, buf_ptr: usize, buf_len: usize) -> i64 {
    if buf_len < 80 {
        return -1;
    }
    let c = match capsule::registry::get(id) {
        Some(c) => c,
        None => return -1,
    };
    let mut buf = [0u8; 80];
    buf[0..32].copy_from_slice(&c.manifest_id);
    buf[32..40].copy_from_slice(&c.id.to_le_bytes());
    buf[40..48].copy_from_slice(&c.caps.to_le_bytes());
    buf[48..56].copy_from_slice(&c.pid.unwrap_or(0).to_le_bytes());
    buf[56] = match c.state {
        CapsuleState::Loaded => 0,
        CapsuleState::Running => 1,
        CapsuleState::Suspended => 2,
        CapsuleState::Exited(_) => 3,
        CapsuleState::Faulted => 4,
    };
    if crate::usercopy::copy_to_user(buf_ptr, &buf).is_err() {
        return -1;
    }
    80
}

pub fn sys_capsule_list(buf_ptr: usize, max_count: usize) -> i64 {
    let ids: alloc::vec::Vec<u64> = capsule::registry::get_all_ids();
    let count = ids.len().min(max_count);
    let mut buf = alloc::vec![0u8; count * 8];
    for (i, &id) in ids.iter().take(count).enumerate() {
        buf[i * 8..(i + 1) * 8].copy_from_slice(&id.to_le_bytes());
    }
    if crate::usercopy::copy_to_user(buf_ptr, &buf).is_err() {
        return -1;
    }
    count as i64
}
