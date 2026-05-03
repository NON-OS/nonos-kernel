// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::super::types::{PageTableEntry, ProtectionFlags};
use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::layout;
use alloc::collections::BTreeMap;
use spin::Mutex;

pub struct MMU {
    pub(super) current_cr3: Mutex<u64>,
    pub(super) page_tables: Mutex<BTreeMap<u64, PageTableEntry>>,
    pub(super) protection_flags: Mutex<ProtectionFlags>,
    pub(super) initialized: Mutex<bool>,
}

impl MMU {
    pub const fn new() -> Self {
        Self {
            current_cr3: Mutex::new(0),
            page_tables: Mutex::new(BTreeMap::new()),
            protection_flags: Mutex::new(ProtectionFlags::new()),
            initialized: Mutex::new(false),
        }
    }

    pub fn is_initialized(&self) -> bool {
        *self.initialized.lock()
    }
    pub fn get_current_cr3(&self) -> u64 {
        *self.current_cr3.lock()
    }
    pub fn get_protection_flags(&self) -> ProtectionFlags {
        *self.protection_flags.lock()
    }

    #[inline]
    pub(super) fn frame_to_virt(&self, frame: PhysAddr) -> VirtAddr {
        VirtAddr::new(layout::DIRECTMAP_BASE + frame.as_u64())
    }
}

impl Default for MMU {
    fn default() -> Self {
        Self::new()
    }
}
