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

use super::handlers::{self, call_rcu, schedule_tasklet, SoftIrqType};
use core::sync::atomic::{AtomicU64, Ordering};

/// Total softirqs processed
static TOTAL_PROCESSED: AtomicU64 = AtomicU64::new(0);

/// Run the software interrupt daemon service
pub fn run_softirq_service() -> ! {
    init_softirq();
    crate::services::registry::register_endpoint_simple("softirq", 1021, 21);
    crate::sys::boot_log::ok("SOFTIRQ", "Service ready");

    loop {
        // Check for pending softirqs
        if handlers::pending() {
            let processed = handlers::process_softirqs();
            TOTAL_PROCESSED.fetch_add(processed as u64, Ordering::Relaxed);
        }

        // Handle IPC requests
        handle_softirq_requests();

        // Yield to other processes
        crate::sched::yield_now();
    }
}

fn example_tasklet_callback(_data: u64) {}
fn example_rcu_callback() {}

fn init_softirq() {
    schedule_tasklet(example_tasklet_callback, 0);
    call_rcu(example_rcu_callback);
}

fn handle_softirq_requests() {
    if let Some(msg) = crate::ipc::nonos_inbox::try_dequeue("softirq") {
        let response = process_request(&msg.data);
        if let Ok(reply) =
            crate::ipc::nonos_channel::IpcMessage::new("softirq", &msg.from, &response)
        {
            let _ = crate::ipc::nonos_inbox::try_enqueue(&msg.from, reply);
        }
    }
}

fn process_request(data: &[u8]) -> [u8; 128] {
    let mut response = [0u8; 128];

    if data.is_empty() {
        return response;
    }

    match data[0] {
        // Raise softirq
        0x01 => {
            if data.len() >= 2 {
                let irq_type = match data[1] {
                    0 => Some(SoftIrqType::Timer),
                    1 => Some(SoftIrqType::NetTx),
                    2 => Some(SoftIrqType::NetRx),
                    3 => Some(SoftIrqType::Block),
                    4 => Some(SoftIrqType::IrqPoll),
                    5 => Some(SoftIrqType::Tasklet),
                    6 => Some(SoftIrqType::Sched),
                    7 => Some(SoftIrqType::HrTimer),
                    8 => Some(SoftIrqType::Rcu),
                    _ => None,
                };
                if let Some(irq) = irq_type {
                    handlers::raise_softirq(irq);
                    response[0] = 0x01; // Success
                } else {
                    response[0] = 0xFE; // Invalid IRQ type
                }
            }
        }
        // Get pending bitmap
        0x02 => {
            response[0] = 0x01;
            let pending = handlers::get_pending();
            response[1..5].copy_from_slice(&pending.to_le_bytes());
        }
        // Get statistics
        0x10 => {
            let stats = handlers::get_stats();
            response[0] = 0x01;
            // Pack count array (9 * 8 = 72 bytes)
            for (i, &count) in stats.count.iter().enumerate() {
                let offset = 1 + i * 8;
                response[offset..offset + 8].copy_from_slice(&count.to_le_bytes());
            }
            // Pack total processed
            response[73..81]
                .copy_from_slice(&TOTAL_PROCESSED.load(Ordering::Relaxed).to_le_bytes());
        }
        _ => {
            response[0] = 0xFF; // Unknown command
        }
    }

    response
}
