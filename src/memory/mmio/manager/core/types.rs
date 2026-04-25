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

extern crate alloc;

use super::super::super::types::MmioRegion;
use crate::memory::layout;
use alloc::collections::BTreeMap;
use x86_64::VirtAddr;

pub struct MmioManager {
    pub(super) regions: BTreeMap<VirtAddr, MmioRegion>,
    pub(super) next_vaddr: u64,
    pub(super) initialized: bool,
}

impl MmioManager {
    pub const fn new() -> Self {
        Self { regions: BTreeMap::new(), next_vaddr: layout::MMIO_BASE, initialized: false }
    }
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for MmioManager {
    fn default() -> Self {
        Self::new()
    }
}
