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

use super::common_cfg::VirtioPciCommonCfg;
use core::ptr;

impl VirtioPciCommonCfg {
    pub unsafe fn select_queue(ptr: *mut Self, queue: u16) {
        unsafe {
            ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_select), queue);
        }
    }

    pub unsafe fn read_queue_size(ptr: *mut Self) -> u16 {
        unsafe { ptr::read_unaligned(ptr::addr_of!((*ptr).queue_size)) }
    }

    pub unsafe fn write_queue_size(ptr: *mut Self, size: u16) {
        unsafe {
            ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_size), size);
        }
    }

    pub unsafe fn enable_queue(ptr: *mut Self) {
        unsafe {
            ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_enable), 1);
        }
    }

    pub unsafe fn read_queue_notify_off(ptr: *mut Self) -> u16 {
        unsafe { ptr::read_unaligned(ptr::addr_of!((*ptr).queue_notify_off)) }
    }

    pub unsafe fn write_queue_addresses(ptr: *mut Self, desc: u64, avail: u64, used: u64) {
        unsafe {
            ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_desc), desc);
            ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_avail), avail);
            ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_used), used);
        }
    }
}
