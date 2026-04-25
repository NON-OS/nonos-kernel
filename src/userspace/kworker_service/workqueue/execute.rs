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

use super::handlers;
use super::queue::queue_work;
use super::types::WorkItem;

pub(super) fn execute_work_item(item: WorkItem) {
    match item {
        WorkItem::FlushPageCache { start_page, count } => {
            handlers::flush_page_cache(start_page, count)
        }
        WorkItem::ReclaimMemory { target_pages } => handlers::reclaim_memory(target_pages),
        WorkItem::CompactMemory => handlers::compact_memory(),
        WorkItem::SyncFilesystem => handlers::sync_filesystem(),
        WorkItem::ProcessDeferredFree => handlers::process_deferred_free(),
        WorkItem::UpdateStats => handlers::update_system_stats(),
        WorkItem::ReapZombies => handlers::reap_zombie_processes(),
        WorkItem::FlushBuffers => handlers::flush_dirty_buffers(),
        WorkItem::DelayedWork { id, ticks_remaining } => {
            if ticks_remaining > 0 {
                let _ =
                    queue_work(WorkItem::DelayedWork { id, ticks_remaining: ticks_remaining - 1 });
            } else {
                handlers::execute_delayed_work(id);
            }
        }
        WorkItem::Noop => {}
    }
}
