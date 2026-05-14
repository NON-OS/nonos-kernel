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

//! Device enumerate / claim / release. Cap requirement: `DeviceEnum`
//! for list, `Driver` for claim and release.

use super::types::DeviceRecord;
use crate::syscall::{call_raw, N_MK_DEVICE_CLAIM, N_MK_DEVICE_LIST, N_MK_DEVICE_RELEASE};

#[no_mangle]
pub extern "C" fn mk_device_list(class: u32, buf: *mut DeviceRecord, count: u64) -> i64 {
    call_raw(N_MK_DEVICE_LIST, [class as u64, buf as u64, count, 0, 0, 0])
}

#[no_mangle]
pub extern "C" fn mk_device_claim(device_id: u64) -> i64 {
    call_raw(N_MK_DEVICE_CLAIM, [device_id, 0, 0, 0, 0, 0])
}

#[no_mangle]
pub extern "C" fn mk_device_release(device_id: u64) -> i64 {
    call_raw(N_MK_DEVICE_RELEASE, [device_id, 0, 0, 0, 0, 0])
}
