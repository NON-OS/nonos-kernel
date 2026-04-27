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

use super::queue::queue_work;
use super::types::WorkItem;
use spin::Mutex;

pub(crate) struct WorkerStats {
    pub items_processed: u64,
    pub pages_reclaimed: u64,
    pub buffers_flushed: u64,
    pub zombies_reaped: u64,
    pub compactions: u64,
}

pub(super) static WORKER_STATS: Mutex<WorkerStats> = Mutex::new(WorkerStats {
    items_processed: 0,
    pages_reclaimed: 0,
    buffers_flushed: 0,
    zombies_reaped: 0,
    compactions: 0,
});

pub(crate) fn get_stats() -> WorkerStats {
    let stats = WORKER_STATS.lock();
    WorkerStats {
        items_processed: stats.items_processed,
        pages_reclaimed: stats.pages_reclaimed,
        buffers_flushed: stats.buffers_flushed,
        zombies_reaped: stats.zombies_reaped,
        compactions: stats.compactions,
    }
}

pub(crate) fn queue_periodic_maintenance() {
    let _ = queue_work(WorkItem::UpdateStats);
    let _ = queue_work(WorkItem::ReapZombies);
    let _ = queue_work(WorkItem::ProcessDeferredFree);
    let _ = queue_work(WorkItem::FlushPageCache { start_page: 0, count: 16 });
    let _ = queue_work(WorkItem::FlushBuffers);
}
