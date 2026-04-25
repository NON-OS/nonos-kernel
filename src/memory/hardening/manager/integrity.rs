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

use super::super::constants::CORRUPTION_PATTERN;
use super::core::{MemoryHardening, HARDENING_STATS};
use x86_64::VirtAddr;

impl MemoryHardening {
    pub(super) fn check_stack_integrity(&self, stack_base: VirtAddr) -> Result<(), &'static str> {
        let canaries = self.stack_canaries.read();
        if let Some(canary) = canaries.get(&stack_base.as_u64()) {
            unsafe {
                let canary_location =
                    (stack_base.as_u64() + canary.stack_size as u64 - 8) as *const u64;
                let current_canary = canary_location.read_volatile();
                if current_canary != canary.value {
                    HARDENING_STATS.increment_stack_overflows();
                    return Err("Stack overflow detected: canary corrupted");
                }
            }
        }
        Ok(())
    }

    pub(super) fn detect_heap_corruption(
        &self,
        addr: u64,
        size: usize,
    ) -> Result<(), &'static str> {
        unsafe {
            let ptr = addr as *const u64;
            for i in 0..(size / 8) {
                let value = ptr.add(i).read_volatile();
                if value == CORRUPTION_PATTERN || value == !CORRUPTION_PATTERN {
                    HARDENING_STATS.increment_heap_corruptions();
                    return Err("Heap corruption detected");
                }
            }
        }
        Ok(())
    }
}
