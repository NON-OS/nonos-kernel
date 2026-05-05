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

use core::mem::size_of;

use crate::hardware::broker::{self, DeviceRecord};
use crate::usercopy::{validate_user_write, write_user_value};

const ERRNO_INVAL: i64 = -22;
const ERRNO_FAULT: i64 = -14;

// `MkDeviceList(class, buf, count) -> i64`
//
// Returns the number of records written. With `count == 0` the call is
// a probe: returns the table size for the requested class without
// touching memory. Otherwise writes up to `count` records to `buf` and
// returns the number written.
//
// Cap-gated by `Capability::DeviceEnum` at the contract layer.
pub fn sys_device_list(class: u32, buf_ptr: u64, count: u64) -> i64 {
    let snapshot = broker::list_by_class(class);
    let total = snapshot.len();
    if count == 0 {
        return total as i64;
    }
    if buf_ptr == 0 {
        return ERRNO_FAULT;
    }
    let to_write = core::cmp::min(count as usize, total);
    let bytes = match (to_write as u64).checked_mul(size_of::<DeviceRecord>() as u64) {
        Some(v) => v,
        None => return ERRNO_INVAL,
    };
    if validate_user_write(buf_ptr, bytes as usize).is_err() {
        return ERRNO_FAULT;
    }
    let stride = size_of::<DeviceRecord>() as u64;
    for (i, rec) in snapshot.iter().take(to_write).enumerate() {
        let dst = buf_ptr + (i as u64) * stride;
        if write_user_value(dst, rec).is_err() {
            return ERRNO_FAULT;
        }
    }
    to_write as i64
}
