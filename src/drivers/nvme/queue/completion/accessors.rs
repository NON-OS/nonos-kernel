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

use super::structure::CompletionQueue;
use crate::memory::addr::VirtAddr;
use crate::memory::mmio::mmio_w32;
use core::sync::atomic::Ordering;

impl CompletionQueue {
    #[inline]
    pub const fn qid(&self) -> u16 {
        self.qid
    }
    #[inline]
    pub const fn depth(&self) -> u16 {
        self.depth
    }
    #[inline]
    pub fn phys_addr(&self) -> u64 {
        self.region.phys_u64()
    }
    #[inline]
    pub fn head(&self) -> u16 {
        self.head.load(Ordering::Acquire)
    }
    #[inline]
    pub fn current_phase(&self) -> bool {
        self.phase.load(Ordering::Acquire) == 1
    }

    pub(super) fn advance_head(&self) {
        let head = self.head.load(Ordering::Acquire);
        let new_head = head.wrapping_add(1) % self.depth;
        if new_head == 0 {
            let current_phase = self.phase.load(Ordering::Acquire);
            self.phase.store(current_phase ^ 1, Ordering::Release);
        }
        self.head.store(new_head, Ordering::Release);
        self.ring_doorbell(new_head);
    }

    #[inline]
    pub(super) fn ring_doorbell(&self, head: u16) {
        mmio_w32(VirtAddr::new(self.doorbell_addr as u64), head as u32);
    }

    pub fn reset(&self) {
        self.head.store(0, Ordering::Release);
        self.phase.store(1, Ordering::Release);
    }
}
