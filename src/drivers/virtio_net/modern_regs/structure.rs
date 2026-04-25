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
use core::ptr::NonNull;

pub struct VirtioModernRegs {
    pub common: NonNull<VirtioPciCommonCfg>,
    pub isr_ptr: NonNull<u8>,
    pub notify_base: usize,
    pub notify_off_multiplier: u32,
    pub device_cfg: usize,
    pub(super) bar_bases: [Option<usize>; 6],
}

unsafe impl Send for VirtioModernRegs {}
unsafe impl Sync for VirtioModernRegs {}

impl VirtioModernRegs {
    pub fn common_ptr(&self) -> *mut VirtioPciCommonCfg {
        self.common.as_ptr()
    }

    pub fn bar_base(&self, bar: usize) -> Option<usize> {
        self.bar_bases.get(bar).copied().flatten()
    }
}
