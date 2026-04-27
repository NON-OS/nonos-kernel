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

use alloc::collections::BTreeMap;
use spin::Mutex;
use x86_64::VirtAddr;

use super::super::constants::INITIAL_REGION_ID;
use super::super::error::SecureMemoryResult;
use super::super::types::MemoryRegion;

pub(super) struct MemoryManager {
    pub regions: BTreeMap<u64, MemoryRegion>,
    pub va_to_region: BTreeMap<u64, u64>,
    pub next_region_id: u64,
    pub initialized: bool,
}

impl MemoryManager {
    pub(super) const fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            va_to_region: BTreeMap::new(),
            next_region_id: INITIAL_REGION_ID,
            initialized: false,
        }
    }

    pub(super) fn init(&mut self) -> SecureMemoryResult<()> {
        if self.initialized {
            return Ok(());
        }
        self.regions.clear();
        self.va_to_region.clear();
        self.next_region_id = INITIAL_REGION_ID;
        self.initialized = true;
        Ok(())
    }

    pub(super) fn get_region_info(&self, va: VirtAddr) -> Option<&MemoryRegion> {
        self.va_to_region.get(&va.as_u64()).and_then(|id| self.regions.get(id))
    }
}

pub(super) static MEMORY_MANAGER: Mutex<MemoryManager> = Mutex::new(MemoryManager::new());
