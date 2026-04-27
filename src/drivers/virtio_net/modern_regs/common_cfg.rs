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

use core::ptr;

#[repr(C, packed)]
pub struct VirtioPciCommonCfg {
    pub device_feature_select: u32,
    pub device_feature: u32,
    pub driver_feature_select: u32,
    pub driver_feature: u32,
    pub msix_config: u16,
    pub num_queues: u16,
    pub device_status: u8,
    pub config_generation: u8,
    pub queue_select: u16,
    pub queue_size: u16,
    pub queue_msix_vector: u16,
    pub queue_enable: u16,
    pub queue_notify_off: u16,
    pub queue_desc: u64,
    pub queue_avail: u64,
    pub queue_used: u64,
}

impl VirtioPciCommonCfg {
    pub const SIZE: usize = 64;

    pub unsafe fn read_device_features(p: *mut Self) -> u64 {
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!((*p).device_feature_select), 0);
            let low = ptr::read_volatile(ptr::addr_of!((*p).device_feature)) as u64;
            ptr::write_volatile(ptr::addr_of_mut!((*p).device_feature_select), 1);
            let high = ptr::read_volatile(ptr::addr_of!((*p).device_feature)) as u64;
            low | (high << 32)
        }
    }

    pub unsafe fn write_driver_features(p: *mut Self, features: u64) {
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!((*p).driver_feature_select), 0);
            ptr::write_volatile(ptr::addr_of_mut!((*p).driver_feature), features as u32);
            ptr::write_volatile(ptr::addr_of_mut!((*p).driver_feature_select), 1);
            ptr::write_volatile(ptr::addr_of_mut!((*p).driver_feature), (features >> 32) as u32);
        }
    }

    pub unsafe fn read_status(p: *mut Self) -> u8 {
        unsafe { ptr::read_volatile(ptr::addr_of!((*p).device_status)) }
    }

    pub unsafe fn write_status(p: *mut Self, status: u8) {
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!((*p).device_status), status);
        }
    }

    pub unsafe fn read_num_queues(p: *mut Self) -> u16 {
        unsafe { ptr::read_volatile(ptr::addr_of!((*p).num_queues)) }
    }

    pub unsafe fn select_queue(p: *mut Self, queue: u16) {
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!((*p).queue_select), queue);
        }
    }
}
