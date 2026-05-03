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

use crate::capsule::{self, metrics, CapsuleId};
use crate::process::current_pid;

pub const SYS_CAPSULE_METRICS_GET: usize = 540;
pub const SYS_CAPSULE_METRICS_GLOBAL: usize = 541;

pub fn sys_capsule_metrics_get(buf_ptr: usize, buf_len: usize) -> i64 {
    let pid = current_pid();
    let id = match capsule::registry::id_by_pid(pid) {
        Some(id) => id,
        None => return -1,
    };
    let data = match metrics::export::export_capsule(id) {
        Some(d) => d,
        None => return -1,
    };
    let len = data.len().min(buf_len);
    if crate::usercopy::copy_to_user(buf_ptr, &data[..len]).is_err() {
        return -1;
    }
    len as i64
}

pub fn sys_capsule_metrics_get_by_id(id: CapsuleId, buf_ptr: usize, buf_len: usize) -> i64 {
    let data = match metrics::export::export_capsule(id) {
        Some(d) => d,
        None => return -1,
    };
    let len = data.len().min(buf_len);
    if crate::usercopy::copy_to_user(buf_ptr, &data[..len]).is_err() {
        return -1;
    }
    len as i64
}

pub fn sys_capsule_metrics_global(buf_ptr: usize, buf_len: usize) -> i64 {
    let data = metrics::export::export_global();
    let len = data.len().min(buf_len);
    if crate::usercopy::copy_to_user(buf_ptr, &data[..len]).is_err() {
        return -1;
    }
    len as i64
}
