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
use super::common_cfg::VirtioPciCommonCfg;
use super::structure::VirtioModernRegs;

impl VirtioPciCommonCfg {
    pub unsafe fn read_queue_size(p: *mut Self) -> u16 {
        unsafe { ptr::read_unaligned(ptr::addr_of!((*p).queue_size)) }
    }

    pub unsafe fn write_queue_size(p: *mut Self, size: u16) {
        unsafe { ptr::write_unaligned(ptr::addr_of_mut!((*p).queue_size), size); }
    }

    pub unsafe fn enable_queue(p: *mut Self) {
        unsafe { ptr::write_unaligned(ptr::addr_of_mut!((*p).queue_enable), 1); }
    }

    pub unsafe fn read_queue_notify_off(p: *mut Self) -> u16 {
        unsafe { ptr::read_unaligned(ptr::addr_of!((*p).queue_notify_off)) }
    }

    pub unsafe fn write_queue_addresses(p: *mut Self, desc: u64, avail: u64, used: u64) { unsafe {
        ptr::write_unaligned(ptr::addr_of_mut!((*p).queue_desc), desc);
        ptr::write_unaligned(ptr::addr_of_mut!((*p).queue_avail), avail);
        ptr::write_unaligned(ptr::addr_of_mut!((*p).queue_used), used);
    }}
}

impl VirtioModernRegs {
    pub fn setup_queue(&self, idx: u16, desc: u64, avail: u64, used: u64, size: u16) -> Result<u16, &'static str> {
        unsafe {
            let p = self.common.as_ptr();
            VirtioPciCommonCfg::select_queue(p, idx);
            let max = VirtioPciCommonCfg::read_queue_size(p);
            if max == 0 { return Err("virtio: queue not available"); }
            let actual = core::cmp::min(size, max);
            VirtioPciCommonCfg::write_queue_size(p, actual);
            VirtioPciCommonCfg::write_queue_addresses(p, desc, avail, used);
            VirtioPciCommonCfg::enable_queue(p);
            Ok(VirtioPciCommonCfg::read_queue_notify_off(p))
        }
    }
}
