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

#[derive(Clone, Copy)]
pub(crate) enum WorkItem {
    FlushPageCache { start_page: u64, count: u64 },
    ReclaimMemory { target_pages: u64 },
    CompactMemory,
    SyncFilesystem,
    ProcessDeferredFree,
    UpdateStats,
    ReapZombies,
    FlushBuffers,
    DelayedWork { id: u64, ticks_remaining: u64 },
    Noop,
}

pub(super) struct WorkQueue {
    pub(super) items: [Option<WorkItem>; 64],
    pub(super) head: usize,
    pub(super) tail: usize,
    pub(super) count: usize,
}

impl WorkQueue {
    pub(super) const fn new() -> Self {
        const NONE: Option<WorkItem> = None;
        Self { items: [NONE; 64], head: 0, tail: 0, count: 0 }
    }

    pub(super) fn enqueue(&mut self, item: WorkItem) -> Result<(), ()> {
        if self.count >= 64 {
            return Err(());
        }
        self.items[self.tail] = Some(item);
        self.tail = (self.tail + 1) % 64;
        self.count += 1;
        Ok(())
    }

    pub(super) fn dequeue(&mut self) -> Option<WorkItem> {
        if self.count == 0 {
            return None;
        }
        let item = self.items[self.head].take();
        self.head = (self.head + 1) % 64;
        self.count -= 1;
        item
    }

    pub(super) fn is_empty(&self) -> bool {
        self.count == 0
    }
}
