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

use super::super::constants::{buddy_address, MAX_ORDER, MIN_ORDER};
use super::super::types::BuddyBlock;
use super::core::VmapAllocator;

impl VmapAllocator {
    pub fn find_block(&mut self, order: usize) -> Option<BuddyBlock> {
        for current_order in order..=MAX_ORDER {
            let list_idx = current_order.saturating_sub(MIN_ORDER);
            if list_idx >= self.free_lists.len() || self.free_lists[list_idx].is_empty() {
                continue;
            }
            let mut block = self.free_lists[list_idx].remove(0);
            while block.order > order {
                let split_order = block.order - 1;
                let split_size = match (1u64).checked_shl(split_order as u32) {
                    Some(s) => s,
                    None => break,
                };
                let buddy_addr = match block.addr.checked_add(split_size) {
                    Some(a) => a,
                    None => break,
                };
                let buddy_idx = split_order.saturating_sub(MIN_ORDER);
                if buddy_idx < self.free_lists.len() {
                    self.free_lists[buddy_idx]
                        .push(BuddyBlock { addr: buddy_addr, order: split_order });
                }
                block.order = split_order;
                if block.order == order {
                    break;
                }
            }
            return Some(block);
        }
        None
    }

    pub fn merge_buddies(&mut self, mut block: BuddyBlock) {
        while block.order < MAX_ORDER {
            let buddy_addr = buddy_address(block.addr, block.order);
            let list_idx = block.order.saturating_sub(MIN_ORDER);
            if list_idx >= self.free_lists.len() {
                break;
            }
            let buddy_pos = self.free_lists[list_idx].iter().position(|b| b.addr == buddy_addr);
            if let Some(pos) = buddy_pos {
                self.free_lists[list_idx].remove(pos);
                let new_order = match block.order.checked_add(1) {
                    Some(o) if o <= MAX_ORDER => o,
                    _ => break,
                };
                block = BuddyBlock { addr: block.addr.min(buddy_addr), order: new_order };
            } else {
                break;
            }
        }
        let list_idx = block.order.saturating_sub(MIN_ORDER);
        if list_idx < self.free_lists.len() {
            self.free_lists[list_idx].push(block);
        }
    }
}
