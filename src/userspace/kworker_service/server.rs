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

use super::workqueue::{self, WorkItem};
use core::sync::atomic::{AtomicU64, Ordering};

/// Tick counter for periodic tasks
static TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Run the kernel worker service
/// This is the main entry point for the kworker process
pub fn run_kworker_service() -> ! {
    init_kworker();
    crate::services::registry::register_endpoint_simple("kworker", 1020, 20);
    crate::sys::boot_log::ok("KWORKER", "Service ready");

    loop {
        // Process any pending work items
        let processed = workqueue::process_work();

        // Handle IPC requests
        handle_kworker_requests();

        // Periodic maintenance every 100 ticks
        let tick = TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
        if tick % 100 == 0 {
            workqueue::queue_periodic_maintenance();
        }

        // Periodic buffer flush every 500 ticks
        if tick % 500 == 0 {
            let _ = workqueue::queue_work(WorkItem::FlushBuffers);
        }

        // Periodic filesystem sync every 1000 ticks
        if tick % 1000 == 0 {
            let _ = workqueue::queue_work(WorkItem::SyncFilesystem);
        }

        crate::sched::yield_now();
    }
}

fn init_kworker() {
    // Queue initial maintenance work batch
    let init_batch = [
        WorkItem::UpdateStats,
        WorkItem::ReapZombies,
        WorkItem::Noop,
    ];
    workqueue::queue_work_batch(&init_batch);

    // Schedule delayed work for initial memory scan after 50 ticks
    let _ = workqueue::queue_work(WorkItem::DelayedWork { id: 1, ticks_remaining: 50 });
}

fn handle_kworker_requests() {
    if let Some(msg) = crate::ipc::nonos_inbox::try_dequeue("kworker") {
        let response = process_request(&msg.data);
        if let Ok(reply) = crate::ipc::nonos_channel::IpcMessage::new("kworker", &msg.from, &response) {
            let _ = crate::ipc::nonos_inbox::try_enqueue(&msg.from, reply);
        }
    }
}

fn process_request(data: &[u8]) -> [u8; 64] {
    let mut response = [0u8; 64];

    if data.is_empty() {
        return response;
    }

    match data[0] {
        // Queue flush buffers request
        0x01 => {
            if workqueue::queue_work(WorkItem::FlushBuffers).is_ok() {
                response[0] = 0x01; // Success
            }
        }
        // Queue memory reclaim
        0x02 => {
            let target = if data.len() >= 9 {
                u64::from_le_bytes([data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8]])
            } else {
                16 // Default to 16 pages
            };
            if workqueue::queue_work(WorkItem::ReclaimMemory { target_pages: target }).is_ok() {
                response[0] = 0x01;
            }
        }
        // Queue memory compact
        0x03 => {
            if workqueue::queue_work(WorkItem::CompactMemory).is_ok() {
                response[0] = 0x01;
            }
        }
        // Queue filesystem sync
        0x04 => {
            if workqueue::queue_work(WorkItem::SyncFilesystem).is_ok() {
                response[0] = 0x01;
            }
        }
        // Get statistics
        0x10 => {
            let stats = workqueue::get_stats();
            response[0] = 0x01;
            response[1..9].copy_from_slice(&stats.items_processed.to_le_bytes());
            response[9..17].copy_from_slice(&stats.pages_reclaimed.to_le_bytes());
            response[17..25].copy_from_slice(&stats.buffers_flushed.to_le_bytes());
            response[25..33].copy_from_slice(&stats.zombies_reaped.to_le_bytes());
            response[33..41].copy_from_slice(&stats.compactions.to_le_bytes());
        }
        _ => {
            response[0] = 0xFF; // Unknown command
        }
    }

    response
}
