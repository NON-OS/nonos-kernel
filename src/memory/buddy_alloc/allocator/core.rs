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
use super::super::constants::{size_to_order, FREE_LIST_COUNT, MAX_ORDER, MIN_ORDER};
use super::super::error::BuddyAllocResult;
use super::super::types::{AllocatedBlock, BuddyBlock};
use crate::memory::layout;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub struct VmapAllocator {
    pub(super) free_lists: [Vec<BuddyBlock>; FREE_LIST_COUNT],
    pub(super) allocated_blocks: BTreeMap<u64, AllocatedBlock>,
    pub(super) base_addr: u64,
    pub(super) total_size: u64,
    pub(super) initialized: bool,
}

impl VmapAllocator {
    pub const fn new() -> Self {
        const INIT: Vec<BuddyBlock> = Vec::new();
        Self {
            free_lists: [INIT; FREE_LIST_COUNT],
            allocated_blocks: BTreeMap::new(),
            base_addr: layout::VMAP_BASE,
            total_size: layout::VMAP_SIZE,
            initialized: false,
        }
    }

    pub fn init(&mut self) -> BuddyAllocResult<()> {
        if self.initialized {
            return Ok(());
        }
        for list in &mut self.free_lists {
            list.clear();
        }
        self.allocated_blocks.clear();
        let initial_order = size_to_order(self.total_size as usize);
        if initial_order <= MAX_ORDER {
            let list_idx = initial_order.saturating_sub(MIN_ORDER);
            if list_idx < self.free_lists.len() {
                self.free_lists[list_idx]
                    .push(BuddyBlock { addr: self.base_addr, order: initial_order });
            }
        }
        self.initialized = true;
        Ok(())
    }
}
